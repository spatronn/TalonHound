/**
 * File Artifact validation helpers (read-only invariant checks).
 */

/** Empty orphan: active artifact with no hashes, no IOC links, no source observations. */
export const EMPTY_ORPHAN_ARTIFACTS_SQL = `
SELECT fa.id
FROM file_artifacts fa
LEFT JOIN file_artifact_hashes fah ON fah.artifact_id = fa.id
LEFT JOIN file_artifact_ioc_links fail ON fail.artifact_id = fa.id
LEFT JOIN file_artifact_source_observations faso ON faso.artifact_id = fa.id
WHERE fa.status = 'active'
  AND fah.id IS NULL
  AND fail.id IS NULL
  AND faso.id IS NULL
`;

export const DUPLICATE_EXACT_HASHES_SQL = `
SELECT hash_type, normalized_hash_value, COUNT(*)::int AS c
FROM file_artifact_hashes
GROUP BY hash_type, normalized_hash_value
HAVING COUNT(*) > 1
`;

export const MULTIPLE_PRIMARY_SQL = `
SELECT artifact_id, COUNT(*)::int AS c
FROM file_artifact_hashes
WHERE is_primary = TRUE
GROUP BY artifact_id
HAVING COUNT(*) > 1
`;

export const PRIMARY_NOT_IN_ARTIFACT_SQL = `
SELECT a.id
FROM file_artifacts a
JOIN file_artifact_hashes h ON h.id = a.primary_hash_id
WHERE a.status = 'active'
  AND h.artifact_id <> a.id
`;

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 */
export async function countEmptyOrphanArtifacts(db) {
  const { rows } = await db.query(`SELECT COUNT(*)::int AS c FROM (${EMPTY_ORPHAN_ARTIFACTS_SQL}) q`);
  return Number(rows[0]?.c || 0);
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} db
 */
export async function collectFileArtifactValidationMetrics(db) {
  const [orphans, dupHashes, multiPrimary, primaryBad] = await Promise.all([
    db.query(`SELECT COUNT(*)::int AS c FROM (${EMPTY_ORPHAN_ARTIFACTS_SQL}) q`),
    db.query(`SELECT COUNT(*)::int AS c FROM (${DUPLICATE_EXACT_HASHES_SQL}) q`),
    db.query(`SELECT COUNT(*)::int AS c FROM (${MULTIPLE_PRIMARY_SQL}) q`),
    db.query(`SELECT COUNT(*)::int AS c FROM (${PRIMARY_NOT_IN_ARTIFACT_SQL}) q`)
  ]);
  return {
    empty_orphan_artifacts: Number(orphans.rows[0]?.c || 0),
    duplicate_exact_hashes: Number(dupHashes.rows[0]?.c || 0),
    multiple_primary_hashes: Number(multiPrimary.rows[0]?.c || 0),
    primary_not_in_artifact: Number(primaryBad.rows[0]?.c || 0)
  };
}
