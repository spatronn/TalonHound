// Retention selection: delete completed backups older than retentionDays,
// never touch active, safety (recent), in-use, or unverified archives.

/**
 * @param {Array<object>} backups - rows with status, trigger_type, created_at, verify_status, backup_id
 * @param {object} opts
 * @param {number} opts.retentionDays
 * @param {Date} [opts.now]
 * @param {Set<string>} [opts.protectedBackupIds] - backup_ids referenced by open restores
 * @returns {object[]} candidates eligible for deletion
 */
export function selectRetentionCandidates(backups, {
  retentionDays,
  now = new Date(),
  protectedBackupIds = new Set()
} = {}) {
  const cutoff = new Date(now.getTime() - retentionDays * 24 * 60 * 60 * 1000);
  const out = [];
  for (const row of backups || []) {
    if (row.status !== 'completed') continue;
    if (row.verify_status === 'failed') continue;
    // Prefer not to delete never-verified unless clearly aged; require passed or null-legacy
    if (row.verify_status === 'pending') continue;
    if (protectedBackupIds.has(row.backup_id)) continue;
    // Keep safety backups for at least retention window (same rule); do not special-case forever
    const created = new Date(row.created_at || row.completed_at || 0);
    if (!(created < cutoff)) continue;
    out.push(row);
  }
  return out;
}
