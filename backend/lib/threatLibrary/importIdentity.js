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
 * The same page published under "www.<host>" and "<host>" is one source: a
 * report imported as https://www.vendor.example/blog/x is a duplicate of
 * https://vendor.example/blog/x. Stored canonical values keep the spelling
 * that was submitted; the identity check compares both spellings.
 * @param {string|null} canonical output of canonicalizeReportUrl
 * @returns {string[]} the canonical value and its www-toggled twin (one entry when the host has a single label)
 */
export function reportUrlIdentityVariants(canonical) {
  if (!canonical) return [];
  let url;
  try {
    url = new URL(canonical);
  } catch {
    return [canonical];
  }
  const host = url.hostname;
  const twinHost = host.startsWith('www.') ? host.slice(4) : `www.${host}`;
  const bareHost = host.startsWith('www.') ? twinHost : host;
  if (!bareHost.includes('.') || /^\d+(?:\.\d+){3}$/.test(host) || host.startsWith('[')) return [canonical];
  url.hostname = twinHost;
  return [canonical, url.href];
}

/**
 * www-insensitive key of a canonical URL (the bare-host spelling).
 * @param {string} canonical
 */
export function reportUrlIdentityKey(canonical) {
  const variants = reportUrlIdentityVariants(canonical);
  return variants.find((v) => !new URL(v).hostname.startsWith('www.')) || canonical;
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
 * Query parameters that only carry campaign / click attribution and never
 * select a document. Deliberately short and explicit: any other parameter
 * (id, p, page, lang, ref, …) may select a different resource and is kept.
 */
const TRACKING_PARAM_NAMES = new Set([
  'gclid', 'dclid', 'gbraid', 'wbraid', 'fbclid', 'msclkid', 'yclid', 'igshid', 'twclid',
  'mc_cid', 'mc_eid', '_hsenc', '_hsmi', 'mkt_tok'
]);

function isTrackingParam(rawName) {
  let name;
  try {
    name = decodeURIComponent(String(rawName).replace(/\+/g, ' ')).toLowerCase();
  } catch {
    return false;
  }
  return name.startsWith('utm_') || TRACKING_PARAM_NAMES.has(name);
}

/**
 * Canonical URL with known tracking parameters removed (other parameters keep
 * their order and spelling). Identity only — stored URLs are never rewritten.
 * @param {string} canonical output of canonicalizeReportUrl
 */
export function stripTrackingParams(canonical) {
  const q = canonical.indexOf('?');
  if (q < 0) return canonical;
  const kept = canonical.slice(q + 1).split('&').filter((pair) => pair && !isTrackingParam(pair.split('=')[0]));
  return kept.length ? `${canonical.slice(0, q)}?${kept.join('&')}` : canonical.slice(0, q);
}

/**
 * `url:` identity key (threat_report_identity_keys) of a canonical URL:
 * www-insensitive host, known tracking parameters dropped.
 * @param {string} canonical output of canonicalizeReportUrl
 */
export function urlKeyOfCanonical(canonical) {
  return `url:${stripTrackingParams(reportUrlIdentityKey(canonical))}`;
}

const PRIMARY_CHAIN_SQL = `
  WITH RECURSIVE chain AS (
    SELECT r.id AS origin_id, r.id, r.superseded_by_report_id, 0 AS depth
      FROM threat_reports r WHERE r.id = ANY($1::bigint[])
    UNION ALL
    SELECT c.origin_id, p.id, p.superseded_by_report_id, c.depth + 1
      FROM chain c JOIN threat_reports p ON p.id = c.superseded_by_report_id
     WHERE c.depth < 16
  )
  SELECT c.origin_id AS chain_origin_id, r.*
    FROM chain c JOIN threat_reports r ON r.id = c.id
   WHERE c.superseded_by_report_id IS NULL`;

/**
 * Primary (non-superseded) report of each given report id, following
 * superseded_by_report_id. A report that is not superseded is its own primary.
 * @param {{ query: Function }} db
 * @param {Array<number|string>} reportIds
 * @returns {Promise<Map<number, object>>} origin id -> primary report row
 */
export async function resolvePrimaryReports(db, reportIds) {
  const ids = [...new Set((reportIds || []).map(Number).filter((n) => Number.isSafeInteger(n) && n > 0))];
  const out = new Map();
  if (!ids.length) return out;
  const { rows } = await db.query(PRIMARY_CHAIN_SQL, [ids]);
  for (const row of rows) {
    const { chain_origin_id: origin, ...report } = row;
    out.set(Number(origin), report);
  }
  return out;
}

/**
 * @param {{ query: Function }} db
 * @param {number|string} reportId
 * @returns {Promise<object|null>}
 */
export async function resolvePrimaryReport(db, reportId) {
  const map = await resolvePrimaryReports(db, [reportId]);
  return map.get(Number(reportId)) || null;
}

/**
 * Owners of identity keys, each resolved to its primary report.
 * @param {{ query: Function }} db
 * @param {string[]} keys
 * @returns {Promise<{ identity_key: string, key_report_id: number, primary: object }[]>}
 */
export async function findIdentityKeyOwners(db, keys) {
  const list = [...new Set((keys || []).filter(Boolean))];
  if (!list.length) return [];
  const { rows } = await db.query(
    `SELECT identity_key, report_id FROM threat_report_identity_keys WHERE identity_key = ANY($1::text[])`,
    [list]
  );
  if (!rows.length) return [];
  const primaries = await resolvePrimaryReports(db, rows.map((r) => r.report_id));
  return rows
    .map((r) => ({
      identity_key: r.identity_key,
      key_report_id: Number(r.report_id),
      primary: primaries.get(Number(r.report_id)) || null
    }))
    .filter((r) => r.primary);
}

/**
 * Insert identity keys for a report. A key another report already owns is
 * left untouched (UNIQUE identity_key) and returned in `conflicts`.
 * @param {{ query: Function }} db
 * @param {number|string} reportId
 * @param {{ key: string, evidence?: string[], values?: string[] }[]} keys
 * @param {'import'|'fetch'|'backfill'|'reconciliation'} origin
 */
export async function recordIdentityKeys(db, reportId, keys, origin) {
  const inserted = [];
  const conflicts = [];
  for (const k of keys || []) {
    if (!k?.key) continue;
    const res = await db.query(
      `INSERT INTO threat_report_identity_keys (report_id, identity_key, evidence, source_values, origin)
       VALUES ($1, $2, $3::text[], $4::text[], $5)
       ON CONFLICT (identity_key) DO NOTHING
       RETURNING id`,
      [reportId, k.key, k.evidence || [], (k.values || []).slice(0, 8), origin]
    );
    if (res.rowCount) {
      inserted.push(k.key);
      continue;
    }
    const { rows } = await db.query(
      `SELECT report_id FROM threat_report_identity_keys WHERE identity_key = $1`,
      [k.key]
    );
    if (rows[0] && Number(rows[0].report_id) !== Number(reportId)) {
      conflicts.push({ key: k.key, report_id: Number(rows[0].report_id) });
    }
  }
  return { inserted, conflicts };
}

/**
 * Transaction-scoped advisory locks on identity keys, taken in sorted order so
 * two workers never deadlock on lock order. The lock string of a `url:` key is
 * the one the import route takes for that URL, so the pre-fetch claim and the
 * post-fetch claim of equivalent URLs serialise against each other.
 * @param {{ query: Function }} client inside a transaction
 * @param {string[]} keys
 */
export async function lockIdentityKeys(client, keys) {
  for (const key of [...new Set((keys || []).filter(Boolean))].sort()) {
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [`${LOCK_NAMESPACE}:${key}`]);
  }
}

/**
 * Report that already owns this import identity, resolved to its primary
 * logical report (a superseded report resolves to the report that superseded
 * it). URL identity = proven identity keys (submitted, redirect, corroborated
 * canonical — threat_report_identity_keys), then the submitted-URL column of
 * reports imported before those keys existed (031).
 * @param {{ query: Function }} db
 * @param {{ kind: 'url'|'sha256', key: string }} identity
 */
export async function findExistingReportImport(db, identity) {
  assertIdentity(identity);
  if (identity.kind === 'url') {
    const owners = await findIdentityKeyOwners(db, [urlKeyOfCanonical(identity.key)]);
    const owner = owners.find((o) => o.primary.deleted_at == null);
    if (owner) return owner.primary;
  }
  const sql = identity.kind === 'url'
    ? `SELECT id FROM threat_reports
       WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical = ANY($1::text[])
       ORDER BY created_at ASC, id ASC`
    : `SELECT id FROM threat_reports
       WHERE source_type = 'pdf' AND deleted_at IS NULL AND source_sha256 = $1
       ORDER BY created_at ASC, id ASC`;
  const { rows } = await db.query(sql, [identity.kind === 'url' ? reportUrlIdentityVariants(identity.key) : identity.key]);
  if (!rows.length) return null;
  const primaries = await resolvePrimaryReports(db, rows.map((r) => r.id));
  for (const r of rows) {
    const primary = primaries.get(Number(r.id));
    if (primary && primary.deleted_at == null) return primary;
  }
  return null;
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
    // Lock on the www-insensitive key: "www.host" and "host" submissions
    // serialise, and so does the worker's post-fetch claim of the same URL
    // (same lock string: `threat_library.import_identity:url:<key>`).
    const lockKey = identity.kind === 'url' ? urlKeyOfCanonical(identity.key) : `sha256:${identity.key}`;
    await lockIdentityKeys(client, [lockKey]);
    const existing = await findExistingReportImport(client, identity);
    if (existing) {
      await client.query('COMMIT');
      return { duplicate: true, report: existing };
    }
    const report = await create(client);
    if (identity.kind === 'url' && report?.id) {
      await recordIdentityKeys(client, report.id, [{ key: lockKey, evidence: ['submitted'], values: [identity.key] }], 'import');
    }
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

/**
 * Idempotent fill of `submitted` identity keys (threat_report_identity_keys)
 * for URL reports imported before migration 056, from source_url_canonical.
 * Oldest report first, so where historical duplicates share a submitted URL
 * the oldest keeps the key; the others are reported, never merged. Writes only
 * threat_report_identity_keys. Fetch-derived keys (redirect / canonical /
 * post id) need stored source HTML: scripts/threat-library-source-identity.js.
 * @param {{ query: Function }} db
 * @returns {Promise<{ scanned: number, inserted: number, conflicts: { key: string, report_id: number, owner_report_id: number }[] }>}
 */
export async function backfillReportIdentityKeys(db) {
  const { rows } = await db.query(
    `SELECT id, source_url_canonical FROM threat_reports
      WHERE source_type = 'url' AND deleted_at IS NULL AND source_url_canonical IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM threat_report_identity_keys k WHERE k.report_id = threat_reports.id)
      ORDER BY created_at ASC, id ASC`
  );
  let inserted = 0;
  const conflicts = [];
  for (const row of rows) {
    const key = urlKeyOfCanonical(row.source_url_canonical);
    const res = await recordIdentityKeys(db, row.id, [{ key, evidence: ['submitted'], values: [row.source_url_canonical] }], 'backfill');
    inserted += res.inserted.length;
    for (const c of res.conflicts) conflicts.push({ key: c.key, report_id: Number(row.id), owner_report_id: c.report_id });
  }
  return { scanned: rows.length, inserted, conflicts };
}
