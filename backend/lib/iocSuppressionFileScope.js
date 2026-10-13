/**
 * Canonical file-scoped IOC suppression helpers.
 *
 * Source of truth for SAME-FILE identity is file_artifacts + file_artifact_hashes
 * (proven exact md5/sha1/sha256 only). Suppressions with file_artifact_id set
 * apply to every proven hash of that survivor artifact. NULL file_artifact_id
 * keeps exact (type, value) semantics (manual Suppressions screen).
 *
 * Matching does NOT depend on FILE_ARTIFACTS_READ_ENABLED — enforcement must
 * work whenever the artifact schema is present. Fail soft when tables are
 * missing (pre-migration) so ingestion is never blocked.
 */

import { isExactFileHashIocType, normalizeExactHash } from './fileArtifacts/hashNormalize.js';

/** SQL: survivor artifact id for a file_artifacts row alias `fa`. */
export const SURVIVOR_ARTIFACT_ID_SQL_FA = `COALESCE(
  CASE
    WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
      THEN fa.merged_into_artifact_id
    ELSE fa.id
  END,
  fa.id
)`;

/**
 * EXISTS predicate: observable ($1 value, $2 type) is covered by an active
 * file-scoped suppression. Caller supplies table alias `s` for ioc_suppressions
 * and bind positions for value/type.
 *
 * @param {number} valueParam
 * @param {number} typeParam
 */
export function fileScopedSuppressionExistsSql(valueParam = 1, typeParam = 2) {
  return `(
    s.file_artifact_id IS NOT NULL
    AND lower($${typeParam}) IN ('md5', 'sha1', 'sha256')
    AND EXISTS (
      SELECT 1
      FROM file_artifact_hashes h
      JOIN file_artifacts fa ON fa.id = h.artifact_id
      JOIN file_artifacts sfa ON sfa.id = s.file_artifact_id
      WHERE h.hash_type = lower($${typeParam})
        AND h.normalized_hash_value = lower($${valueParam})
        AND ${SURVIVOR_ARTIFACT_ID_SQL_FA} = COALESCE(
          CASE
            WHEN sfa.status = 'merged' AND sfa.merged_into_artifact_id IS NOT NULL
              THEN sfa.merged_into_artifact_id
            ELSE sfa.id
          END,
          sfa.id
        )
    )
  )`;
}

/**
 * Full active-suppression match for one observable (exact OR file-scoped).
 * Parameters: $1 = observable value, $2 = observable type.
 */
export function activeSuppressionMatchSql() {
  return `(
    (
      lower(s.ioc_value) = lower($1)
      AND lower(s.ioc_type) = lower($2)
    )
    OR ${fileScopedSuppressionExistsSql(1, 2)}
  )`;
}

function isMissingArtifactSchema(err) {
  if (!err) return false;
  if (err.code === '42P01' || err.code === '42703') return true;
  const msg = String(err.message || '');
  return msg.includes('file_artifact') || msg.includes('file_artifact_id');
}

/**
 * Resolve survivor artifact id for an IOC item via proven ioc link.
 * Independent of FILE_ARTIFACTS_READ_ENABLED.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {number} iocItemId
 * @returns {Promise<string|null>}
 */
export async function resolveSurvivorArtifactIdForIoc(db, iocItemId) {
  const id = Number(iocItemId);
  if (!Number.isFinite(id) || id <= 0) return null;
  try {
    const { rows } = await db.query(
      `SELECT ${SURVIVOR_ARTIFACT_ID_SQL_FA} AS artifact_id
       FROM file_artifact_ioc_links l
       JOIN file_artifacts fa ON fa.id = l.artifact_id
       WHERE l.ioc_item_id = $1
       LIMIT 1`,
      [id]
    );
    return rows[0]?.artifact_id ? String(rows[0].artifact_id) : null;
  } catch (err) {
    if (isMissingArtifactSchema(err)) return null;
    throw err;
  }
}

/**
 * Resolve survivor artifact id for a proven exact hash (type, value).
 * Returns null when not found or ambiguous (multiple survivors).
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} iocType
 * @param {string} iocValue
 * @returns {Promise<string|null>}
 */
export async function resolveSurvivorArtifactIdForHash(db, iocType, iocValue) {
  const normalized = normalizeExactHash(iocType, iocValue);
  if (!normalized) return null;
  try {
    const { rows } = await db.query(
      `SELECT DISTINCT ${SURVIVOR_ARTIFACT_ID_SQL_FA} AS artifact_id
       FROM file_artifact_hashes h
       JOIN file_artifacts fa ON fa.id = h.artifact_id
       WHERE h.hash_type = $1
         AND h.normalized_hash_value = $2`,
      [normalized.hash_type, normalized.normalized_hash_value]
    );
    if (rows.length !== 1 || !rows[0]?.artifact_id) return null;
    return String(rows[0].artifact_id);
  } catch (err) {
    if (isMissingArtifactSchema(err)) return null;
    throw err;
  }
}

/**
 * Load proven exact hashes for a survivor artifact (includes hashes still on
 * direct merged tombstones pointing at the survivor).
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} artifactId
 * @returns {Promise<Array<{ hash_type: string, normalized_hash_value: string }>>}
 */
export async function loadProvenHashesForArtifact(db, artifactId) {
  if (!artifactId) return [];
  try {
    // GROUP BY (not SELECT DISTINCT + ORDER BY CASE): Postgres requires every
    // ORDER BY expression to appear in a DISTINCT select list.
    const { rows } = await db.query(
      `SELECT h.hash_type, h.normalized_hash_value
       FROM file_artifact_hashes h
       JOIN file_artifacts fa ON fa.id = h.artifact_id
       WHERE ${SURVIVOR_ARTIFACT_ID_SQL_FA} = $1::uuid
       GROUP BY h.hash_type, h.normalized_hash_value
       ORDER BY CASE h.hash_type WHEN 'sha256' THEN 0 WHEN 'sha1' THEN 1 WHEN 'md5' THEN 2 ELSE 9 END`,
      [artifactId]
    );
    return rows || [];
  } catch (err) {
    if (isMissingArtifactSchema(err)) return [];
    throw err;
  }
}

/**
 * IOC item rows linked to a survivor artifact (for status recompute).
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {string} artifactId
 * @returns {Promise<Array<{ id: number, observable_type: string, observable: string }>>}
 */
export async function loadLinkedIocsForArtifact(db, artifactId) {
  if (!artifactId) return [];
  try {
    const { rows } = await db.query(
      `SELECT DISTINCT ON (i.id) i.id, i.observable_type, i.observable
       FROM file_artifact_ioc_links l
       JOIN file_artifacts fa ON fa.id = l.artifact_id
       JOIN ioc_items i ON i.id = l.ioc_item_id AND i.observable_type = l.ioc_observable_type
       WHERE ${SURVIVOR_ARTIFACT_ID_SQL_FA} = $1::uuid
       ORDER BY i.id`,
      [artifactId]
    );
    return rows || [];
  } catch (err) {
    if (isMissingArtifactSchema(err)) return [];
    throw err;
  }
}

/**
 * Expand file-scoped suppression rows into exact (type,value) index entries
 * for every currently-known proven hash of the artifact. Used by the import
 * optimization index so batch checks stay in-memory.
 *
 * New hashes discovered after index load are covered by the DB-path matcher
 * (queryIocSuppressedFromDb) on subsequent recomputes / non-index lookups.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {Array<{ ioc_value?: string, ioc_type?: string, scope?: string, source_name?: string|null, file_artifact_id?: string|null }>} rows
 * @param {{ buildSuppressionIndex: Function, makeSuppressionKey: Function }} deps
 * @returns {Promise<Map<string, { global: boolean, sources: Set<string> }>>}
 */
export async function buildSuppressionIndexWithFileScope(db, rows = [], deps = {}) {
  const buildIndex = deps.buildSuppressionIndex;
  const makeKey = deps.makeSuppressionKey;
  if (typeof buildIndex !== 'function' || typeof makeKey !== 'function') {
    throw new Error('buildSuppressionIndexWithFileScope requires buildSuppressionIndex and makeSuppressionKey deps');
  }
  const index = buildIndex(rows);
  const artifactIds = [
    ...new Set(
      (rows || [])
        .map((r) => (r?.file_artifact_id ? String(r.file_artifact_id) : ''))
        .filter(Boolean)
    )
  ];
  if (!artifactIds.length) return index;

  try {
    const { rows: hashRows } = await db.query(
      `SELECT DISTINCT ${SURVIVOR_ARTIFACT_ID_SQL_FA} AS artifact_id,
              h.hash_type, h.normalized_hash_value
       FROM file_artifact_hashes h
       JOIN file_artifacts fa ON fa.id = h.artifact_id
       WHERE ${SURVIVOR_ARTIFACT_ID_SQL_FA} = ANY(
         SELECT COALESCE(
           CASE
             WHEN sfa.status = 'merged' AND sfa.merged_into_artifact_id IS NOT NULL
               THEN sfa.merged_into_artifact_id
             ELSE sfa.id
           END,
           sfa.id
         )
         FROM file_artifacts sfa
         WHERE sfa.id = ANY($1::uuid[])
       )`,
      [artifactIds]
    );
    for (const h of hashRows || []) {
      const key = makeKey(h.normalized_hash_value, h.hash_type);
      if (!key) continue;
      const entry = index.get(key) || { global: false, sources: new Set() };
      entry.global = true;
      index.set(key, entry);
    }
  } catch (err) {
    if (!isMissingArtifactSchema(err)) {
      console.error('[ioc-suppression] file-scope index expand failed (fail-open):', err?.message || err);
    }
  }
  return index;
}

/**
 * Whether a pair should be checked against file-scoped suppressions.
 */
export function isFileHashSuppressionType(iocType) {
  return isExactFileHashIocType(iocType);
}

/**
 * Describe suppression scope for API/UI.
 * @param {{ file_artifact_id?: string|null }} row
 * @param {number} [knownHashCount]
 */
export function describeSuppressionScope(row, knownHashCount = null) {
  if (row?.file_artifact_id) {
    const out = {
      kind: 'file',
      label: 'File',
      file_artifact_id: String(row.file_artifact_id)
    };
    if (knownHashCount != null) out.known_hash_count = Number(knownHashCount);
    return out;
  }
  return { kind: 'exact', label: 'Exact observable' };
}
