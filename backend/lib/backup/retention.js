// Retention selection: delete completed backups older than retentionDays,
// never touch active, safety (recent), in-use, or unverified archives, and never
// drop below minRetained valid recovery points regardless of age.

/**
 * A recovery point is a completed archive whose verification passed
 * (or a legacy row from before verification existed).
 */
export function isRecoveryPoint(row) {
  if (!row || row.status !== 'completed') return false;
  return row.verify_status === 'passed' || row.verify_status == null;
}

function createdMs(row) {
  const t = new Date(row?.created_at || row?.completed_at || 0).getTime();
  return Number.isFinite(t) ? t : 0;
}

/** Newest-first recovery points. */
export function listRecoveryPoints(rows) {
  return (rows || []).filter(isRecoveryPoint).sort((a, b) => createdMs(b) - createdMs(a));
}

/**
 * @param {Array<object>} backups - rows with status, trigger_type, created_at, verify_status, backup_id
 * @param {object} opts
 * @param {number} opts.retentionDays
 * @param {number} [opts.minRetained] newest recovery points that are always kept
 * @param {Date} [opts.now]
 * @param {Set<string>} [opts.protectedBackupIds] - backup_ids referenced by open restores
 * @returns {object[]} candidates eligible for deletion
 */
export function selectRetentionCandidates(backups, {
  retentionDays,
  minRetained = 1,
  now = new Date(),
  protectedBackupIds = new Set()
} = {}) {
  const cutoff = new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000);
  const keepNewest = new Set(
    listRecoveryPoints(backups)
      .slice(0, Math.max(1, Number(minRetained) || 1))
      .map((r) => r.backup_id)
  );
  const out = [];
  for (const row of backups || []) {
    if (row.status !== 'completed') continue;
    if (row.verify_status === 'failed') continue;
    // Prefer not to delete never-verified unless clearly aged; require passed or null-legacy
    if (row.verify_status === 'pending') continue;
    if (protectedBackupIds.has(row.backup_id)) continue;
    if (keepNewest.has(row.backup_id)) continue;
    // Keep safety backups for at least retention window (same rule); do not special-case forever
    const created = new Date(row.created_at || row.completed_at || 0);
    if (!(created < cutoff)) continue;
    out.push(row);
  }
  return out;
}

/**
 * Recovery points that would remain if `row` were deleted.
 * @returns {{ isRecoveryPoint: boolean, remaining: number }}
 */
export function recoveryPointsAfterDelete(rows, row) {
  const points = listRecoveryPoints(rows);
  const target = isRecoveryPoint(row);
  const remaining = points.filter((r) => r.backup_id !== row?.backup_id).length;
  return { isRecoveryPoint: target, remaining };
}
