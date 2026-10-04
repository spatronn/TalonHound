/**
 * Shared helpers for integration_source_state UPSERTs.
 *
 * Semantics:
 * - content_hash: deterministic fingerprint of the semantic snapshot
 * - items_json: semantic checkpoint / summary payload (may be large / TOASTed)
 * - updated_at: last successful state write (also used as min-fetch heartbeat
 *   for URLHaus / MalwareBazaar). Advances on every successful upsert call,
 *   even when the large JSON payload is unchanged.
 *
 * When content_hash is unchanged, keep the existing items_json TOAST pointer
 * so PostgreSQL does not rewrite megabytes of identical snapshot bytes.
 */

/**
 * Compact payload for feeds that do not read items_json back for sync.
 * content_hash remains the semantic fingerprint; count is diagnostic only.
 * @param {number} count
 * @returns {{ v: number, count: number }}
 */
export function buildCompactCountPayload(count) {
  return { v: 1, count: Number(count) || 0 };
}

/**
 * @param {import('pg').PoolClient|import('pg').Pool} db
 * @param {string} sourceName
 * @param {string|null} contentHash
 * @param {unknown} itemsJson object/array or pre-stringified JSON
 * @returns {Promise<import('pg').QueryResult>}
 */
export async function upsertIntegrationSourceState(db, sourceName, contentHash, itemsJson) {
  const payload = typeof itemsJson === 'string' ? itemsJson : JSON.stringify(itemsJson ?? []);
  return db.query(
    `INSERT INTO integration_source_state (source_name, content_hash, items_json, updated_at)
     VALUES ($1, $2, $3::jsonb, NOW())
     ON CONFLICT (source_name)
     DO UPDATE SET
       content_hash = EXCLUDED.content_hash,
       items_json = CASE
         WHEN integration_source_state.content_hash IS NOT DISTINCT FROM EXCLUDED.content_hash
         THEN integration_source_state.items_json
         ELSE EXCLUDED.items_json
       END,
       updated_at = NOW()`,
    [sourceName, contentHash, payload]
  );
}
