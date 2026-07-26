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
