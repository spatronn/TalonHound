/**
 * Threat Library report-list query helpers: search normalisation and the
 * shared WHERE clause used by both the page and the count query.
 *
 * This is library navigation search over stored report metadata only
 * (title / source / file name / report tag names). It never touches
 * extracted bodies, candidates, entities or AI results, and never calls a
 * provider.
 *
 * Only fields the list actually shows are searched: a row must never match
 * on a value the user cannot see in the list. `report_type` (AI-chosen free
 * text, removed from the list UI) is therefore not a search column even
 * though the API and detail page still carry it. Report tags are rendered as
 * row chips, so their (enabled) names are searchable.
 */

import { likeEscape } from '../iocSearchDsl/normalize.js';

export const REPORT_LIST_DEFAULT_LIMIT = 50;
export const REPORT_LIST_MAX_LIMIT = 200;
export const REPORT_LIST_SEARCH_MAX_LENGTH = 200;

/** Page sizes the Threat Library list UI offers; the HTTP route accepts only these. */
export const REPORT_LIST_PAGE_SIZES = Object.freeze([25, 50]);
export const REPORT_LIST_DEFAULT_PAGE_SIZE = 25;

/**
 * HTTP `limit` for the report list: one of REPORT_LIST_PAGE_SIZES, anything
 * else (missing, junk, 10, 200, repeated params) falls back to the default so
 * a hand-edited URL can never widen the page or error.
 * @param {unknown} value
 * @returns {number}
 */
export function parseReportListPageSize(value) {
  const n = typeof value === 'string' && /^\d+$/.test(value.trim()) ? Number(value.trim()) : value;
  return REPORT_LIST_PAGE_SIZES.includes(n) ? n : REPORT_LIST_DEFAULT_PAGE_SIZE;
}

/** Metadata columns a report-list search matches against (substring, case-insensitive). */
export const REPORT_LIST_SEARCH_COLUMNS = Object.freeze([
  'r.title',
  'r.source_name',
  'r.source_url',
  'r.source_file_name'
]);

/**
 * Report tags are shown as chips on every list row, so a search also matches
 * an enabled tag name (the same enabled-only set loadReportTagsByReportIds
 * returns). EXISTS over the (report_id, tag_id) primary key: no row fan-out.
 * @param {string} p bound parameter placeholder, e.g. `$1`
 */
export function reportListTagSearchSql(p) {
  return `EXISTS (SELECT 1 FROM threat_report_tags rt JOIN tags t ON t.id = rt.tag_id AND t.enabled = TRUE WHERE rt.report_id = r.id AND t.name ILIKE ${p} ESCAPE '\\')`;
}

/**
 * Status filter = report presentation phase (reportPhase.js). The SQL is the
 * same mapping as resolveReportPhase over the persisted analysis_status:
 *   finalized    ready / skipped
 *   review_ready review_required
 *   failed       failed / cancelled
 *   preparing    everything else (pending / fetching / extracting / analyzing / matching)
 */
export const REPORT_LIST_STATUS_FILTERS = Object.freeze(['preparing', 'review_ready', 'finalized', 'failed']);

export const REPORT_LIST_PHASE_SQL = Object.freeze({
  finalized: `r.analysis_status IN ('ready', 'skipped')`,
  review_ready: `r.analysis_status = 'review_required'`,
  failed: `r.analysis_status IN ('failed', 'cancelled')`,
  preparing: `r.analysis_status NOT IN ('ready', 'skipped', 'review_required', 'failed', 'cancelled')`
});

/** threat_reports.tlp CHECK values. */
export const REPORT_LIST_TLP_FILTERS = Object.freeze(['clear', 'green', 'amber', 'amber_strict', 'red']);

/** threat_reports.source_type CHECK values. */
export const REPORT_LIST_SOURCE_FILTERS = Object.freeze(['url', 'pdf', 'thib']);

/** Imported (created_at) windows. SQL comes from this map, never from input. */
export const REPORT_LIST_IMPORTED_WINDOWS = Object.freeze({
  '24h': `r.created_at >= NOW() - INTERVAL '24 hours'`,
  '7d': `r.created_at >= NOW() - INTERVAL '7 days'`,
  '30d': `r.created_at >= NOW() - INTERVAL '30 days'`,
  '90d': `r.created_at >= NOW() - INTERVAL '90 days'`
});

function pickFilter(value, allowed) {
  const v = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return allowed.includes(v) ? v : null;
}

/**
 * Whitelisted list filters. Unknown / repeated / object-shaped values are
 * "no filter", so a hand-edited URL can never error or reach SQL.
 * @param {Record<string, unknown>} [query]
 * @returns {{ status: string|null, tlp: string|null, source: string|null, imported: string|null }}
 */
export function parseReportListFilters(query = {}) {
  return {
    status: pickFilter(query.status, REPORT_LIST_STATUS_FILTERS),
    tlp: pickFilter(query.tlp, REPORT_LIST_TLP_FILTERS),
    source: pickFilter(query.source, REPORT_LIST_SOURCE_FILTERS),
    imported: pickFilter(query.imported, Object.keys(REPORT_LIST_IMPORTED_WINDOWS))
  };
}

/**
 * Trim, bound and sanitise a raw `search` query value. Non-string input
 * (repeated params, objects) and control characters are treated as "no search"
 * / dropped so malformed input can never reach the database as an error.
 * @param {unknown} value
 * @returns {string}
 */
export function normalizeReportListSearch(value) {
  if (typeof value !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  if (!cleaned) return '';
  return cleaned.slice(0, REPORT_LIST_SEARCH_MAX_LENGTH).trim();
}

/**
 * Parse the list endpoint query string into bounded list options.
 * @param {Record<string, unknown>} [query]
 */
/**
 * Whitelisted list-sort keys. SQL expressions are looked up from this map —
 * user input is never interpolated into ORDER BY.
 */
export const REPORT_LIST_SORT_FIELDS = Object.freeze([
  'report',
  'source',
  'tlp',
  'entities',
  'indicators',
  'matched',
  'status',
  'published',
  'imported'
]);

export const REPORT_LIST_DEFAULT_ORDER_SQL = 'ORDER BY r.created_at DESC';
export const REPORT_LIST_SORT_TIEBREAK_SQL = 'r.created_at DESC, r.id DESC';

/** Same display source the list cell uses (source_name, else type-specific fallback). */
const REPORT_LIST_SOURCE_SORT_SQL = `LOWER(COALESCE(
  NULLIF(BTRIM(r.source_name), ''),
  CASE r.source_type
    WHEN 'url' THEN NULLIF(BTRIM(r.source_url), '')
    WHEN 'pdf' THEN NULLIF(BTRIM(r.source_file_name), '')
    WHEN 'thib' THEN 'THIB bundle'
    ELSE NULLIF(BTRIM(r.source_type), '')
  END
))`;

/** TLP 2.0 restriction rank stored on threat_reports.tlp (NOT NULL, CHECK). */
const REPORT_LIST_TLP_SORT_SQL = `CASE r.tlp
  WHEN 'clear' THEN 0
  WHEN 'green' THEN 1
  WHEN 'amber' THEN 2
  WHEN 'amber_strict' THEN 3
  WHEN 'red' THEN 4
  ELSE 5
END`;

/**
 * Parse an explicit list sort. Unsupported field or direction (including
 * injection-shaped values) falls back to the canonical default order.
 * Both `sort` and `order` must be valid; a partial pair is ignored.
 * @param {unknown} sort
 * @param {unknown} order
 * @returns {{ sort: string|null, order: 'asc'|'desc'|null }}
 */
export function parseReportListSort(sort, order) {
  const field = typeof sort === 'string' ? sort.trim().toLowerCase() : '';
  const dir = typeof order === 'string' ? order.trim().toLowerCase() : '';
  if (!REPORT_LIST_SORT_FIELDS.includes(field) || (dir !== 'asc' && dir !== 'desc')) {
    return { sort: null, order: null };
  }
  return { sort: field, order: dir };
}

function directionSql(order) {
  return order === 'asc' ? 'ASC' : 'DESC';
}

/**
 * ORDER BY for the report list. Default is exactly `r.created_at DESC`
 * (pre-sort behaviour). Explicit sorts use NULLS LAST where the column can
 * be unknown, plus a created_at/id tie-breaker so ties do not jump pages.
 * @param {{ sort?: unknown, order?: unknown }} [opts]
 * @returns {{ sql: string, sort: string|null, order: 'asc'|'desc'|null }}
 */
export function buildReportListOrderBy({ sort, order } = {}) {
  const parsed = parseReportListSort(sort, order);
  if (!parsed.sort) {
    return { sql: REPORT_LIST_DEFAULT_ORDER_SQL, sort: null, order: null };
  }
  const dir = directionSql(parsed.order);
  const tie = REPORT_LIST_SORT_TIEBREAK_SQL;
  const expressions = {
    report: `LOWER(NULLIF(BTRIM(r.title), '')) ${dir} NULLS LAST, ${tie}`,
    source: `${REPORT_LIST_SOURCE_SORT_SQL} ${dir} NULLS LAST, ${tie}`,
    tlp: `${REPORT_LIST_TLP_SORT_SQL} ${dir}, ${tie}`,
    entities: `entity_count ${dir}, ${tie}`,
    // Sort by Total Unique Indicators (same field the list Indicators cell shows).
    indicators: `total_unique_indicator_count ${dir}, ${tie}`,
    matched: `matched_count ${dir}, ${tie}`,
    status: `r.analysis_status ${dir} NULLS LAST, ${tie}`,
    published: `r.published_at ${dir} NULLS LAST, ${tie}`,
    imported: parsed.order === 'asc' ? 'r.created_at ASC, r.id ASC' : 'r.created_at DESC, r.id DESC'
  };
  return { sql: `ORDER BY ${expressions[parsed.sort]}`, sort: parsed.sort, order: parsed.order };
}

export function parseReportListQuery(query = {}) {
  const lim = Math.min(Math.max(Math.floor(Number(query.limit)) || REPORT_LIST_DEFAULT_LIMIT, 1), REPORT_LIST_MAX_LIMIT);
  // Non-finite / non-integer offsets (e.g. "1e400", "abc", 2.5) fall back to 0
  // rather than reaching the driver as an invalid bigint.
  const rawOff = Math.floor(Number(query.offset));
  const off = Number.isSafeInteger(rawOff) && rawOff > 0 ? rawOff : 0;
  const parsedSort = parseReportListSort(query.sort, query.order);
  return {
    limit: lim,
    offset: off,
    search: normalizeReportListSearch(query.search),
    sort: parsedSort.sort,
    order: parsedSort.order,
    ...parseReportListFilters(query)
  };
}

/**
 * Build the WHERE clause for the report list. Always excludes soft-deleted rows;
 * with a search term it adds a parameterised, escape-aware ILIKE across the
 * metadata columns and enabled tag names so `%` / `_` / `\` in user input
 * match literally. TLP / source / imported filters are whitelisted values
 * (bound or looked up, never interpolated).
 *
 * The status (phase) filter is deliberately NOT part of this clause: the
 * count query needs the same base set to report per-phase counts for the
 * status tabs, and applies the phase predicate itself (see statusSql).
 * @param {{ search?: string, tlp?: string|null, source?: string|null, imported?: string|null }} opts
 * @param {number} [startParamIndex]
 * @returns {{ sql: string, params: unknown[], nextParamIndex: number }}
 */
export function buildReportListWhere({ search = '', tlp = null, source = null, imported = null } = {}, startParamIndex = 1) {
  const parts = ['r.deleted_at IS NULL'];
  const params = [];
  let i = startParamIndex;
  const term = normalizeReportListSearch(search);
  if (term) {
    params.push(`%${likeEscape(term)}%`);
    const p = `$${i}`;
    i += 1;
    parts.push(`(${[
      ...REPORT_LIST_SEARCH_COLUMNS.map((col) => `${col} ILIKE ${p} ESCAPE '\\'`),
      reportListTagSearchSql(p)
    ].join(' OR ')})`);
  }
  const filters = parseReportListFilters({ tlp, source, imported });
  if (filters.tlp) {
    params.push(filters.tlp);
    parts.push(`r.tlp = $${i}`);
    i += 1;
  }
  if (filters.source) {
    params.push(filters.source);
    parts.push(`r.source_type = $${i}`);
    i += 1;
  }
  if (filters.imported) parts.push(REPORT_LIST_IMPORTED_WINDOWS[filters.imported]);
  return { sql: `WHERE ${parts.join(' AND ')}`, params, nextParamIndex: i };
}

/** Phase predicate for a whitelisted status filter, or null for "all". */
export function reportListStatusSql(status) {
  const s = pickFilter(status, REPORT_LIST_STATUS_FILTERS);
  return s ? REPORT_LIST_PHASE_SQL[s] : null;
}

/**
 * One aggregate over the base (non-status) filtered set: `total` honours the
 * status filter, the per-phase counts and `all` ignore it so the status tabs
 * always show the distribution of the current search + filters. Single scan
 * of threat_reports — no per-report subselects.
 * @param {string} whereSql output of buildReportListWhere
 * @param {string|null} status
 */
export function buildReportListCountSql(whereSql, status) {
  const statusSql = reportListStatusSql(status);
  const total = statusSql ? `COUNT(*) FILTER (WHERE ${statusSql})::int AS total` : 'COUNT(*)::int AS total';
  const phases = REPORT_LIST_STATUS_FILTERS
    .map((phase) => `COUNT(*) FILTER (WHERE ${REPORT_LIST_PHASE_SQL[phase]})::int AS phase_${phase}`)
    .join(', ');
  return `SELECT ${total}, COUNT(*)::int AS phase_all, ${phases} FROM threat_reports r ${whereSql}`;
}

/** `{ all, preparing, review_ready, finalized, failed }` from the count row. */
export function reportListPhaseCounts(row = {}) {
  const out = { all: Number(row.phase_all) || 0 };
  for (const phase of REPORT_LIST_STATUS_FILTERS) out[phase] = Number(row[`phase_${phase}`]) || 0;
  return out;
}
