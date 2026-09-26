/**
 * Import identity for Threat Library URL / PDF reports: the key that turns a
 * re-submission of the same source into a no-op. It is resolved in the import
 * route BEFORE a report row, job or queue entry exists, so a duplicate never
 * reaches fetch, extraction or AI analysis.
 *
 *  - URL: conservative canonical form of the submitted URL, stored once at
 *    import in `threat_reports.source_url_canonical`. `source_url` stays the
 *    analyst-editable provenance value and is never used as the identity.
 *  - PDF: SHA-256 of the original uploaded bytes (existing `source_sha256`).
 *    Exact bytes only; filename, title and content similarity play no part.
 *
 * Only active reports of the same source type count (soft-deleted reports can
 * be imported again). Check-then-insert runs under a transaction-scoped
 * advisory lock on the identity, so two concurrent submissions of the same
 * source serialise and the second one sees the first one's row.
 */

export const IMPORT_DUPLICATE_MESSAGES = Object.freeze({
  url: 'This report has already been imported.',
  sha256: 'This PDF has already been imported.'
});

const SHA256_HEX = /^[0-9a-f]{64}$/;
const LOCK_NAMESPACE = 'threat_library.import_identity';

/**
 * Canonical URL identity. WHATWG parsing already lowercases the scheme and
 * host, drops default ports (:80 / :443) and normalises IDN hosts; on top of
 * that the fragment, credentials, an empty `?` and one trailing slash on a
 * non-root path are dropped. Scheme (http vs https), path case and the query
 * string (content and order) are kept verbatim — query parameters can select
 * a different document.
 * @param {unknown} raw
 * @returns {string|null}
 */
export function canonicalizeReportUrl(raw) {
  const trimmed = String(raw ?? '').trim();
  if (!trimmed) return null;
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
  if (!url.hostname) return null;
  url.hash = '';
  url.username = '';
  url.password = '';
  if (!url.search) url.search = '';
  if (url.pathname.length > 1 && url.pathname.endsWith('/')) {
    url.pathname = url.pathname.slice(0, -1);
  }
  return url.href;
}

/**
 * @param {unknown} value
 * @returns {string|null} lowercase 64-char hex, or null when not a SHA-256
 */
export function normalizeSha256(value) {
  const hex = String(value ?? '').trim().toLowerCase();
  return SHA256_HEX.test(hex) ? hex : null;
}

/**
 * @param {{ kind: 'url'|'sha256', key: string }} identity
 */
function assertIdentity(identity) {
  if (identity?.kind === 'url' && identity.key) return;
  if (identity?.kind === 'sha256' && normalizeSha256(identity.key) === identity.key) return;
  throw Object.assign(new Error('Invalid import identity'), { code: 'invalid_import_identity' });
}

/**
 * Oldest active report carrying this identity (index-backed partial lookups,
 * see migration 031).
 * @param {{ query: Function }} db
 * @param {{ kind: 'url'|'sha256', key: string }} identity
 */
export async function findExistingReportImport(db, identity) {
  assertIdentity(identity);
  const sql = identity.kind === 'url'
    ? `SELECT * FROM threat_reports
       WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical = $1
       ORDER BY created_at ASC, id ASC LIMIT 1`
    : `SELECT * FROM threat_reports
       WHERE source_type = 'pdf' AND deleted_at IS NULL AND source_sha256 = $1
       ORDER BY created_at ASC, id ASC LIMIT 1`;
  const { rows } = await db.query(sql, [identity.key]);
  return rows[0] || null;
}

/**
 * Atomically "look up or create" a report for an import identity. `create`
 * receives the transaction client and must insert the report row with that
 * client; it only runs when no active report has the identity.
 * @param {import('pg').Pool} pool
 * @param {{ kind: 'url'|'sha256', key: string }} identity
 * @param {(client: import('pg').PoolClient) => Promise<object>} create
 * @returns {Promise<{ duplicate: true, report: object } | { duplicate: false, report: object }>}
 */
export async function claimReportImport(pool, identity, create) {
  assertIdentity(identity);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [
      `${LOCK_NAMESPACE}:${identity.kind}:${identity.key}`
    ]);
    const existing = await findExistingReportImport(client, identity);
    if (existing) {
      await client.query('COMMIT');
      return { duplicate: true, report: existing };
    }
    const report = await create(client);
    await client.query('COMMIT');
    return { duplicate: false, report };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Idempotent fill of `source_url_canonical` for URL reports imported before
 * the column existed (run by migrate.js after SQL migrations). Writes only
 * that NULL column — no other report data, not updated_at — and reports, but
 * never merges or deletes, historical duplicates.
 * @param {{ query: Function }} db
 * @returns {Promise<{ scanned: number, updated: number, duplicateGroups: { kind: string, key: string, count: number, report_ids: string[] }[] }>}
 */
export async function backfillReportImportIdentity(db) {
  const { rows } = await db.query(
    `SELECT id, source_url FROM threat_reports
     WHERE source_type = 'url' AND source_url_canonical IS NULL AND source_url IS NOT NULL
     ORDER BY id`
  );
  let updated = 0;
  for (const row of rows) {
    const key = canonicalizeReportUrl(row.source_url);
    if (!key) continue;
    const res = await db.query(
      `UPDATE threat_reports SET source_url_canonical = $2
       WHERE id = $1 AND source_url_canonical IS NULL`,
      [row.id, key]
    );
    updated += res.rowCount || 0;
  }
  const { rows: dupes } = await db.query(
    `SELECT 'url' AS kind, source_url_canonical AS key, COUNT(*)::int AS count,
            array_agg(public_id::text ORDER BY created_at, id) AS report_ids
     FROM threat_reports
     WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical IS NOT NULL
     GROUP BY source_url_canonical HAVING COUNT(*) > 1
     UNION ALL
     SELECT 'sha256', source_sha256, COUNT(*)::int, array_agg(public_id::text ORDER BY created_at, id)
     FROM threat_reports
     WHERE source_type = 'pdf' AND deleted_at IS NULL AND source_sha256 IS NOT NULL
     GROUP BY source_sha256 HAVING COUNT(*) > 1`
  );
  return { scanned: rows.length, updated, duplicateGroups: dupes };
}
