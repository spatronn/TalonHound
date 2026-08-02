/**
 * Merge conflict recording for contradictory exact-hash mappings.
 */

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {{
 *   conflicting_hash_type: string,
 *   conflicting_hash_value: string,
 *   candidate_artifact_ids?: string[],
 *   evidence?: object,
 *   reason: string
 * }} input
 */
export async function recordMergeConflict(db, input) {
  const type = String(input.conflicting_hash_type || '').toLowerCase();
  const value = String(input.conflicting_hash_value || '').toLowerCase();
  const reason = String(input.reason || 'conflicting_exact_hash_mapping');
  const candidates = Array.isArray(input.candidate_artifact_ids)
    ? input.candidate_artifact_ids.filter(Boolean)
    : [];
  const evidence = input.evidence && typeof input.evidence === 'object' ? input.evidence : {};

  const existing = await db.query(
    `SELECT id FROM file_artifact_merge_conflicts
     WHERE status = 'open'
       AND conflicting_hash_type = $1
       AND conflicting_hash_value = $2
       AND reason = $3
     ORDER BY id ASC
     LIMIT 1`,
    [type, value, reason]
  );
  if (existing.rowCount) {
    return { id: existing.rows[0].id, created: false };
  }

  const ins = await db.query(
    `INSERT INTO file_artifact_merge_conflicts (
       conflicting_hash_type, conflicting_hash_value,
       candidate_artifact_ids, evidence, reason, status
     ) VALUES ($1, $2, $3::uuid[], $4::jsonb, $5, 'open')
     RETURNING id`,
    [type, value, candidates, JSON.stringify(evidence), reason]
  );
  return { id: ins.rows[0].id, created: true };
}

/**
 * Detect conflict: same hash_type+value already bound to a different artifact
 * than the one we want to attach, OR provider set maps to multiple active artifacts
 * that cannot safely merge.
 *
 * @param {Array<{ artifact_id: string }>} artifactHits
 * @returns {{ conflict: boolean, artifact_ids: string[] }}
 */
export function detectMultiArtifactConflict(artifactHits) {
  const ids = [...new Set((artifactHits || []).map((h) => String(h.artifact_id)).filter(Boolean))];
  return { conflict: ids.length > 1, artifact_ids: ids };
}

/**
 * Collect duplicate artifact IDs to merge into the current artifact from a
 * provider exact-hash-set sibling result.
 * @param {{ artifact_id?: string|null, siblings?: { needs_merge_with?: string|null, needs_merge_with_ids?: string[]|null }|null }} result
 * @returns {string[]}
 */
export function collectProviderMergeTargetIds(result) {
  const selfId = result?.artifact_id || null;
  const fromIds = Array.isArray(result?.siblings?.needs_merge_with_ids)
    ? result.siblings.needs_merge_with_ids
    : [];
  const single = result?.siblings?.needs_merge_with || null;
  return [...new Set([...fromIds, single].filter(Boolean))]
    .filter((id) => id && id !== selfId);
}

/**
 * Mark open provider-set conflicts as resolved after a successful merge/attach.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {{
 *   hash_type?: string,
 *   hash_value?: string,
 *   reason?: string,
 *   resolution?: object
 * }} input
 */
export async function resolveOpenProviderHashSetConflicts(db, input = {}) {
  const type = String(input.hash_type || 'sha256').toLowerCase();
  const value = String(input.hash_value || '').toLowerCase();
  if (!value) return { resolved: 0 };
  const reason = String(input.reason || 'provider_hash_set_maps_to_multiple_artifacts');
  const resolution = input.resolution && typeof input.resolution === 'object'
    ? input.resolution
    : { resolved_by: 'provider_exact_hash_set_merge' };

  const res = await db.query(
    `UPDATE file_artifact_merge_conflicts
     SET status = 'resolved',
         resolved_at = NOW(),
         resolution_metadata = COALESCE(resolution_metadata, '{}'::jsonb) || $4::jsonb
     WHERE status = 'open'
       AND conflicting_hash_type = $1
       AND conflicting_hash_value = $2
       AND reason IN ($3, 'provider_hash_set_multiple_artifacts')
     RETURNING id`,
    [type, value, reason, JSON.stringify(resolution)]
  );
  return { resolved: res.rowCount, ids: res.rows.map((r) => r.id) };
}
