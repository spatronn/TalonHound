/**
 * Threat Library report catalog — read-only discovery of what is already in the
 * library, keyed on the REPORT source URL (never on extracted URL IOCs).
 *
 *  - listReportCatalog: keyset-paged report metadata filtered by import window
 *    (persisted created_at), publication window, publisher, import status and
 *    review phase. Ordering always ends in the id tie-breaker and the cursor
 *    carries created_at at full microsecond precision, so rows sharing a
 *    timestamp are never skipped or repeated between pages.
 *  - checkReportUrls: batch "is this report URL already imported?" using the
 *    import identity itself (canonicalizeReportUrl + the same active URL-report
 *    predicate findExistingReportImport uses), in one indexed query. A second
 *    query finds active non-URL reports (e.g. a PDF upload) whose stored
 *    source_url canonicalizes to the same identity — the same report, but one
 *    URL import dedup would not catch — labelled match_basis 'source_url'.
 *    Every matching active report is returned — several matches are surfaced
 *    as `ambiguous`, never collapsed to an arbitrary row.
 *
 * Both share one row serializer so the list and the URL check always describe
 * a report the same way. Only catalog metadata is selected: no summary, body,
 * AI result, candidates or IOCs. Nothing here writes.
 */

import { createHash } from 'node:crypto';
import {
  canonicalizeReportUrl,
  findIdentityKeyOwners,
  reportUrlIdentityKey,
  reportUrlIdentityVariants,
  urlKeyOfCanonical
} from './importIdentity.js';
import { resolveReportPhase, REPORT_PHASES } from './reportPhase.js';
import { REPORT_LIST_PHASE_SQL } from './reportListQuery.js';
import { serializePublicationDate } from './publicationDate.js';
import { likeEscape } from '../iocSearchDsl/normalize.js';

export const CATALOG_DEFAULT_LIMIT = 50;
export const CATALOG_MAX_LIMIT = 200;
export const CATALOG_URL_CHECK_MAX = 100;
/** Matches returned per queried URL; `match_count` always carries the full number. */
export const CATALOG_URL_MATCHES_MAX = 20;
export const CATALOG_PUBLISHER_MAX_LENGTH = 200;

/** threat_reports.import_status CHECK values. */
export const CATALOG_IMPORT_STATUSES = Object.freeze([
  'draft', 'processing', 'review_required', 'ready', 'imported', 'failed', 'already_imported'
]);
export const CATALOG_REVIEW_PHASES = Object.freeze(['preparing', 'review_ready', 'finalized', 'failed']);
export const CATALOG_SORTS = Object.freeze(['imported_desc', 'imported_asc', 'published_desc', 'published_asc']);

/** Catalog-safe columns only; timestamps also as exact UTC text for cursors. */
const CATALOG_COLUMNS = `r.id, r.public_id, r.title, r.source_type, r.source_name, r.source_url,
  r.source_url_canonical, r.tlp, r.import_status, r.analysis_status, r.failure_stage, r.failure_code,
  r.created_at, r.finalized_at, r.published_at, r.published_at_precision, r.published_at_source,
  r.published_at_raw,
  to_char(r.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_key,
  to_char(r.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS published_at_key`;

export class CatalogInputError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function iso(v) {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

// ---------------------------------------------------------------------------
// Report state (shared by list + URL check)
// ---------------------------------------------------------------------------

/**
 * What the library still needs for a report, from persisted status only.
 *   complete      finalized (review_phase finalized)
 *   needs_review  review_ready: analysis done, analyst review/finalize pending
 *   processing    preparing: fetch / extraction / analysis not finished
 *   failed        import or analysis failed — existing, but not processed
 */
export function catalogProcessingState(row) {
  const phase = resolveReportPhase(row);
  const importFailed = String(row?.import_status || '').toLowerCase() === 'failed';
  if (phase === REPORT_PHASES.FAILED || importFailed) {
    return { processing_state: 'failed', next_action: 'investigate_failure' };
  }
  if (phase === REPORT_PHASES.REVIEW_READY) return { processing_state: 'needs_review', next_action: 'analyst_review' };
  if (phase === REPORT_PHASES.FINALIZED) return { processing_state: 'complete', next_action: 'none' };
  return { processing_state: 'processing', next_action: 'wait_for_processing' };
}

export function serializeCatalogReport(row) {
  const phase = resolveReportPhase(row);
  const { processing_state, next_action } = catalogProcessingState(row);
  const publication = serializePublicationDate(row);
  return {
    report_id: row.public_id,
    title: row.title ?? null,
    publisher: row.source_name ?? null,
    source_type: row.source_type ?? null,
    // Stored provenance value (analyst-editable) and the import identity it was deduplicated on.
    source_url: row.source_url ?? null,
    source_url_identity: row.source_url_canonical ?? null,
    tlp: row.tlp ?? null,
    imported_at: iso(row.created_at),
    published_at: iso(publication.published_at),
    published_date: publication.published_date,
    published_at_precision: publication.published_at_precision,
    import_status: row.import_status ?? null,
    analysis_status: row.analysis_status ?? null,
    review_phase: phase,
    finalized: processing_state === 'complete',
    finalized_at: iso(row.finalized_at),
    processing_state,
    fully_processed: processing_state === 'complete',
    requires_review: processing_state === 'needs_review',
    requires_further_processing: processing_state === 'processing' || processing_state === 'failed',
    next_action,
    failure: processing_state === 'failed'
      ? { stage: row.failure_stage ?? null, code: row.failure_code ?? null }
      : null
  };
}

// ---------------------------------------------------------------------------
// Input parsing
// ---------------------------------------------------------------------------

const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;
const HAS_ZONE = /(Z|[+-]\d{2}:?\d{2})$/i;

/**
 * UTC calendar day or ISO-8601 timestamp. A day is a whole UTC day: as a lower
 * bound it starts at 00:00:00Z (inclusive), as an upper bound it ends before the
 * next day's 00:00:00Z. A timestamp is an exact inclusive bound; one without an
 * offset is read as UTC.
 * @returns {{ op: '>='|'<'|'<=', at: string }|null}
 */
export function parseCatalogBound(value, edge, field) {
  if (value === undefined || value === null || value === '') return null;
  const raw = String(value).trim();
  const day = DATE_ONLY.exec(raw);
  if (day) {
    const start = new Date(Date.UTC(Number(day[1]), Number(day[2]) - 1, Number(day[3])));
    if (Number.isNaN(start.getTime()) || start.toISOString().slice(0, 10) !== raw) {
      throw new CatalogInputError('INVALID_DATE', `${field} is not a valid date: ${raw}`);
    }
    if (edge === 'from') return { op: '>=', at: start.toISOString() };
    return { op: '<', at: new Date(start.getTime() + 86_400_000).toISOString() };
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(raw)) {
    throw new CatalogInputError('INVALID_DATE', `${field} must be a UTC date (YYYY-MM-DD) or an ISO-8601 timestamp`);
  }
  const d = new Date(HAS_ZONE.test(raw) ? raw : `${raw}Z`);
  if (Number.isNaN(d.getTime())) {
    throw new CatalogInputError('INVALID_DATE', `${field} is not a valid timestamp: ${raw}`);
  }
  return { op: edge === 'from' ? '>=' : '<=', at: d.toISOString() };
}

function listOf(value, allowed, field) {
  if (value === undefined || value === null || value === '') return [];
  const items = (Array.isArray(value) ? value : [value]).map((v) => String(v).trim().toLowerCase()).filter(Boolean);
  for (const v of items) {
    if (!allowed.includes(v)) {
      throw new CatalogInputError('INVALID_FILTER', `${field} must be one of: ${allowed.join(', ')}`);
    }
  }
  return [...new Set(items)].sort();
}

function clampLimit(value) {
  if (value === undefined || value === null || value === '') return CATALOG_DEFAULT_LIMIT;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) throw new CatalogInputError('INVALID_LIMIT', 'limit must be a positive integer');
  return Math.min(n, CATALOG_MAX_LIMIT);
}

export function parseCatalogQuery(input = {}) {
  const sort = input.sort ? String(input.sort).trim().toLowerCase() : 'imported_desc';
  if (!CATALOG_SORTS.includes(sort)) {
    throw new CatalogInputError('INVALID_SORT', `sort must be one of: ${CATALOG_SORTS.join(', ')}`);
  }
  const publisher = input.publisher == null ? '' : String(input.publisher).trim();
  if (publisher.length > CATALOG_PUBLISHER_MAX_LENGTH) {
    throw new CatalogInputError('INVALID_FILTER', `publisher must be at most ${CATALOG_PUBLISHER_MAX_LENGTH} characters`);
  }
  const imported = {
    from: parseCatalogBound(input.imported_from, 'from', 'imported_from'),
    to: parseCatalogBound(input.imported_to, 'to', 'imported_to')
  };
  const published = {
    from: parseCatalogBound(input.published_from, 'from', 'published_from'),
    to: parseCatalogBound(input.published_to, 'to', 'published_to')
  };
  return {
    sort,
    limit: clampLimit(input.limit),
    imported,
    published,
    publisher: publisher || null,
    import_status: listOf(input.import_status, CATALOG_IMPORT_STATUSES, 'import_status'),
    review_phase: listOf(input.review_phase, CATALOG_REVIEW_PHASES, 'review_phase'),
    cursor: input.cursor ? String(input.cursor) : null
  };
}

/** Filters + sort a cursor is bound to; a cursor never crosses to another query. */
function queryFingerprint(q) {
  const basis = JSON.stringify([q.sort, q.imported, q.published, q.publisher, q.import_status, q.review_phase]);
  return createHash('sha256').update(basis).digest('hex').slice(0, 16);
}

function encodeCursor(q, row) {
  const payload = {
    v: 1,
    f: queryFingerprint(q),
    c: row.created_at_key,
    i: String(row.id),
    ...(q.sort.startsWith('published') ? { p: row.published_at_key ?? null } : {})
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

const CURSOR_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

function decodeCursor(q) {
  if (!q.cursor) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(q.cursor, 'base64url').toString('utf8'));
  } catch {
    throw new CatalogInputError('INVALID_CURSOR', 'cursor is malformed');
  }
  const ok = payload && payload.v === 1
    && typeof payload.c === 'string' && CURSOR_TS.test(payload.c)
    && typeof payload.i === 'string' && /^\d{1,19}$/.test(payload.i)
    && (!q.sort.startsWith('published') || payload.p === null || (typeof payload.p === 'string' && CURSOR_TS.test(payload.p)));
  if (!ok) throw new CatalogInputError('INVALID_CURSOR', 'cursor is malformed');
  if (payload.f !== queryFingerprint(q)) {
    throw new CatalogInputError('INVALID_CURSOR', 'cursor belongs to a different filter/sort; restart without cursor');
  }
  return payload;
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

function buildCatalogWhere(q, params) {
  const add = (v) => { params.push(v); return `$${params.length}`; };
  const where = ['r.deleted_at IS NULL', 'r.superseded_by_report_id IS NULL'];
  for (const [col, b] of [['r.created_at', q.imported.from], ['r.created_at', q.imported.to],
    ['r.published_at', q.published.from], ['r.published_at', q.published.to]]) {
    if (b) where.push(`${col} ${b.op} ${add(b.at)}::timestamptz`);
  }
  if (q.publisher) {
    where.push(`r.source_name ILIKE ${add(`%${likeEscape(q.publisher)}%`)} ESCAPE '\\'`);
  }
  if (q.import_status.length) where.push(`r.import_status = ANY(${add(q.import_status)}::text[])`);
  if (q.review_phase.length) {
    where.push(`(${q.review_phase.map((p) => REPORT_LIST_PHASE_SQL[p]).join(' OR ')})`);
  }
  return { where, add };
}

/**
 * Keyset predicate + ORDER BY. Every sort ends in (created_at, id) in the same
 * direction; published sorts put reports without a publication date last.
 */
function buildKeyset(q, cursor, add) {
  const desc = q.sort.endsWith('_desc');
  const dir = desc ? 'DESC' : 'ASC';
  const cmp = desc ? '<' : '>';
  const imported = (c) => `(r.created_at, r.id) ${cmp} (${add(c.c)}::timestamptz, ${add(c.i)}::bigint)`;
  if (q.sort.startsWith('imported')) {
    return {
      predicate: cursor ? imported(cursor) : null,
      orderBy: `ORDER BY r.created_at ${dir}, r.id ${dir}`
    };
  }
  const orderBy = `ORDER BY r.published_at ${dir} NULLS LAST, r.created_at ${dir}, r.id ${dir}`;
  if (!cursor) return { predicate: null, orderBy };
  if (cursor.p === null) {
    return { predicate: `(r.published_at IS NULL AND ${imported(cursor)})`, orderBy };
  }
  const p = add(cursor.p);
  return {
    predicate: `(r.published_at ${cmp} ${p}::timestamptz OR r.published_at IS NULL`
      + ` OR (r.published_at = ${p}::timestamptz AND ${imported(cursor)}))`,
    orderBy
  };
}

function appliedFilters(q) {
  const bound = (b) => (b ? { [b.op === '>=' ? 'gte' : b.op === '<' ? 'lt' : 'lte']: b.at } : {});
  const window = (w) => (w.from || w.to ? { ...bound(w.from), ...bound(w.to) } : null);
  return {
    imported_at: window(q.imported),
    published_at: window(q.published),
    publisher: q.publisher,
    import_status: q.import_status.length ? q.import_status : null,
    review_phase: q.review_phase.length ? q.review_phase : null
  };
}

/**
 * @param {{ query: Function }} pool
 * @param {object} input see parseCatalogQuery
 * @throws {CatalogInputError}
 */
export async function listReportCatalog(pool, input = {}) {
  const q = parseCatalogQuery(input);
  const cursor = decodeCursor(q);
  const params = [];
  const { where, add } = buildCatalogWhere(q, params);
  const keyset = buildKeyset(q, cursor, add);
  if (keyset.predicate) where.push(keyset.predicate);
  const { rows } = await pool.query(
    `SELECT ${CATALOG_COLUMNS}
     FROM threat_reports r
     WHERE ${where.join(' AND ')}
     ${keyset.orderBy}
     LIMIT ${add(q.limit + 1)}`,
    params
  );
  const hasMore = rows.length > q.limit;
  const page = hasMore ? rows.slice(0, q.limit) : rows;
  return {
    items: page.map(serializeCatalogReport),
    count: page.length,
    limit: q.limit,
    sort: q.sort,
    has_more: hasMore,
    next_cursor: hasMore ? encodeCursor(q, page[page.length - 1]) : null,
    filters: appliedFilters(q)
  };
}

// ---------------------------------------------------------------------------
// Batch URL check
// ---------------------------------------------------------------------------

/** SQL for importIdentity.reportUrlIdentityKey: the stored canonical URL with a leading "www." host label dropped. */
const WWW_INSENSITIVE_IDENTITY_SQL = `regexp_replace(r.source_url_canonical, '^(https?://)www\\.', '\\1')`;

/**
 * @param {{ query: Function }} pool
 * @param {unknown[]} urls report source URLs, answered in input order
 * @throws {CatalogInputError}
 */
export async function checkReportUrls(pool, urls) {
  if (!Array.isArray(urls) || urls.length === 0) {
    throw new CatalogInputError('INVALID_URLS', 'urls must be a non-empty array');
  }
  if (urls.length > CATALOG_URL_CHECK_MAX) {
    throw new CatalogInputError('TOO_MANY_URLS', `At most ${CATALOG_URL_CHECK_MAX} URLs per request`);
  }
  const queried = urls.map((raw) => {
    const text = typeof raw === 'string' ? raw : null;
    return { raw: text, identity: text === null ? null : canonicalizeReportUrl(text) };
  });
  const identities = [...new Set(queried.map((x) => x.identity).filter(Boolean))];
  // "www.host" and "host" spell one import identity (importIdentity.reportUrlIdentityVariants):
  // query both spellings, file every match under the www-insensitive key.
  const lookup = [...new Set(identities.flatMap((u) => reportUrlIdentityVariants(u)))];

  const byIdentity = new Map();
  const entryFor = (identity) => {
    const key = reportUrlIdentityKey(identity);
    if (!byIdentity.has(key)) byIdentity.set(key, { count: 0, importIdentity: 0, reports: [] });
    return byIdentity.get(key);
  };
  if (identities.length) {
    // Same predicate as the import duplicate check (findExistingReportImport),
    // served by idx_threat_reports_url_import_identity; one statement per batch.
    const { rows } = await pool.query(
      `SELECT * FROM (
         SELECT ${CATALOG_COLUMNS},
                COUNT(*) OVER (PARTITION BY ${WWW_INSENSITIVE_IDENTITY_SQL})::int AS identity_match_count,
                ROW_NUMBER() OVER (PARTITION BY ${WWW_INSENSITIVE_IDENTITY_SQL} ORDER BY r.created_at ASC, r.id ASC) AS identity_rank
         FROM threat_reports r
         WHERE r.source_type = 'url' AND r.deleted_at IS NULL
           AND r.superseded_by_report_id IS NULL
           AND r.source_url_canonical = ANY($1::text[])
       ) m
       WHERE m.identity_rank <= $2
       ORDER BY m.source_url_canonical, m.identity_rank`,
      [lookup, CATALOG_URL_MATCHES_MAX]
    );
    for (const row of rows) {
      const entry = entryFor(row.source_url_canonical);
      entry.count = row.identity_match_count;
      entry.importIdentity = row.identity_match_count;
      entry.reports.push({ ...serializeCatalogReport(row), match_basis: 'import_identity', created_at_key: row.created_at_key, id: row.id });
    }

    // Proven source identity (redirect target, corroborated canonical URL,
    // and the submitted URL of reports superseded into another one) — the
    // same keys the import duplicate check reads — resolved to the primary
    // logical report.
    const identitiesByKey = new Map();
    for (const u of identities) {
      const k = urlKeyOfCanonical(u);
      if (!identitiesByKey.has(k)) identitiesByKey.set(k, []);
      identitiesByKey.get(k).push(u);
    }
    const identityKeys = [...identitiesByKey.keys()];
    const owners = (await findIdentityKeyOwners(pool, identityKeys))
      .filter((o) => o.primary.deleted_at == null);
    if (owners.length) {
      const { rows: primaryRows } = await pool.query(
        `SELECT ${CATALOG_COLUMNS} FROM threat_reports r WHERE r.id = ANY($1::bigint[])`,
        [[...new Set(owners.map((o) => Number(o.primary.id)))]]
      );
      const primaryById = new Map(primaryRows.map((r) => [Number(r.id), r]));
      for (const owner of owners) {
        const row = primaryById.get(Number(owner.primary.id));
        if (!row) continue;
        for (const queriedIdentity of identitiesByKey.get(owner.identity_key) || []) {
          const entry = entryFor(queriedIdentity);
          if (entry.reports.some((r) => Number(r.id) === Number(row.id))) continue;
          entry.count += 1;
          entry.importIdentity += 1;
          entry.reports.push({ ...serializeCatalogReport(row), match_basis: 'source_identity', created_at_key: row.created_at_key, id: row.id });
        }
      }
    }

    // Non-URL reports (PDF / THIB) carry no import identity, only the stored
    // source_url. Prefilter on the URL's host in SQL, then require the exact
    // same canonical form as the import identity — no looser matching.
    const hosts = [...new Set(lookup.map((u) => new URL(u).hostname))];
    const { rows: byStoredUrl } = await pool.query(
      `SELECT ${CATALOG_COLUMNS}
       FROM threat_reports r
       WHERE r.source_type <> 'url' AND r.deleted_at IS NULL AND r.superseded_by_report_id IS NULL AND r.source_url IS NOT NULL
         AND lower(regexp_replace(regexp_replace(
               substring(btrim(r.source_url) from '^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)'),
               '^.*@', ''), ':[0-9]*$', '')) = ANY($1::text[])
       ORDER BY r.created_at ASC, r.id ASC`,
      [hosts]
    );
    for (const row of byStoredUrl) {
      const identity = canonicalizeReportUrl(row.source_url);
      if (!identity || !lookup.includes(identity)) continue;
      const entry = entryFor(identity);
      entry.count += 1;
      entry.reports.push({ ...serializeCatalogReport(row), match_basis: 'source_url', created_at_key: row.created_at_key, id: row.id });
    }
    for (const entry of byIdentity.values()) {
      entry.reports.sort((a, b) => (a.created_at_key < b.created_at_key ? -1 : a.created_at_key > b.created_at_key ? 1 : Number(a.id) - Number(b.id)));
      entry.reports = entry.reports.slice(0, CATALOG_URL_MATCHES_MAX).map(({ created_at_key, id, ...report }) => report);
    }
  }

  const results = queried.map(({ raw, identity }, index) => {
    if (!identity) {
      return {
        index,
        queried_url: raw,
        normalized_url: null,
        valid: false,
        invalid_reason: raw === null || raw.trim() === '' ? 'empty' : 'not_http_url',
        exists: false,
        match_count: 0,
        ambiguous: false,
        import_would_deduplicate: false,
        matched_report_id: null,
        finalized: false,
        requires_further_processing: false,
        requires_review: false,
        report: null,
        matches: []
      };
    }
    const entry = byIdentity.get(reportUrlIdentityKey(identity));
    const matches = entry?.reports || [];
    const matchCount = entry?.count || 0;
    const single = matchCount === 1 ? matches[0] : null;
    return {
      index,
      queried_url: raw,
      normalized_url: identity,
      valid: true,
      invalid_reason: null,
      exists: matchCount > 0,
      match_count: matchCount,
      ambiguous: matchCount > 1,
      // threat_library_import_url would answer already_exists (URL import identity hit).
      import_would_deduplicate: (entry?.importIdentity || 0) > 0,
      // Only an unambiguous match is named; with several, read `matches`.
      matched_report_id: single ? single.report_id : null,
      // Conservative across duplicates: finalized only when every match is.
      finalized: matchCount > 0 && matches.every((m) => m.finalized),
      requires_further_processing: matches.some((m) => m.requires_further_processing),
      requires_review: matches.some((m) => m.requires_review),
      report: single,
      matches
    };
  });

  return {
    results,
    summary: {
      queried: results.length,
      valid: results.filter((r) => r.valid).length,
      invalid: results.filter((r) => !r.valid).length,
      existing: results.filter((r) => r.exists).length,
      missing: results.filter((r) => r.valid && !r.exists).length,
      ambiguous: results.filter((r) => r.ambiguous).length,
      finalized: results.filter((r) => r.finalized).length,
      requiring_action: results.filter((r) => r.requires_further_processing || r.requires_review).length
    }
  };
}
