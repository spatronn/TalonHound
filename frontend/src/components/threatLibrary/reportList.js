/**
 * Threat Library report-list helpers: search normalisation, pagination maths,
 * request params, URL state and the list empty-state descriptor. Pure
 * functions so the page behaviour is unit-testable without a DOM. Mirrors the
 * threat-actor / tag manager list conventions (25 per page, ?search=&page=),
 * plus a 25 / 50 rows-per-page choice carried as ?limit= (the API parameter).
 */

/** Default rows per page. */
export const REPORT_LIST_PAGE_SIZE = 25;
/** Rows-per-page choices; the API serves exactly these (anything else -> 25). */
export const REPORT_LIST_PAGE_SIZE_OPTIONS = Object.freeze([25, 50]);
export const REPORT_LIST_SEARCH_DEBOUNCE_MS = 300;
export const REPORT_LIST_SEARCH_MAX_LENGTH = 200;
export const REPORT_LIST_SEARCH_PARAM = 'search';
export const REPORT_LIST_PAGE_PARAM = 'page';
export const REPORT_LIST_LIMIT_PARAM = 'limit';

/** Trim and bound the search term; anything else is "no search". */
export function normalizeReportListSearch(value) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, REPORT_LIST_SEARCH_MAX_LENGTH).trim();
}

/** A page number is a safe positive integer; anything else is page 1. */
export function normalizeReportListPage(value) {
  const n = typeof value === 'number' ? value : Number(String(value ?? '').trim());
  return Number.isSafeInteger(n) && n >= 1 ? n : 1;
}

/** One of REPORT_LIST_PAGE_SIZE_OPTIONS; anything else is the default (25). */
export function normalizeReportListPageSize(value) {
  const n = typeof value === 'number' ? value : Number(String(value ?? '').trim());
  return REPORT_LIST_PAGE_SIZE_OPTIONS.includes(n) ? n : REPORT_LIST_PAGE_SIZE;
}

/** Last page that still has rows (1 when the list is empty). */
export function reportListTotalPages(total, pageSize = REPORT_LIST_PAGE_SIZE) {
  const t = Math.max(0, Number(total) || 0);
  const size = Math.max(1, Number(pageSize) || REPORT_LIST_PAGE_SIZE);
  return Math.max(1, Math.ceil(t / size) || 1);
}

/** Clamp a requested page into [1, totalPages] for the given total. */
export function clampReportListPage(page, total, pageSize = REPORT_LIST_PAGE_SIZE) {
  return Math.min(normalizeReportListPage(page), reportListTotalPages(total, pageSize));
}

/**
 * Query params for GET /threat-library/reports. Pagination is expressed as
 * limit/offset (the API contract); `search` is only sent when non-blank so an
 * empty field on page 1 is byte-for-byte the unfiltered first-page request.
 */
export function buildReportListQueryParams({ search = '', page = 1, pageSize = REPORT_LIST_PAGE_SIZE } = {}) {
  const size = normalizeReportListPageSize(pageSize);
  const p = normalizeReportListPage(page);
  const params = { limit: size, offset: (p - 1) * size };
  const q = normalizeReportListSearch(search);
  if (q) params[REPORT_LIST_SEARCH_PARAM] = q;
  return params;
}

/** URL state: `?search=` only when active, `?page=` only past page 1, `?limit=` only when not the default. */
export function parseReportListUrlState(searchParams) {
  const params = searchParams && typeof searchParams.get === 'function'
    ? searchParams
    : new URLSearchParams(String(searchParams || ''));
  return {
    search: normalizeReportListSearch(params.get(REPORT_LIST_SEARCH_PARAM) || ''),
    page: normalizeReportListPage(params.get(REPORT_LIST_PAGE_PARAM)),
    pageSize: normalizeReportListPageSize(params.get(REPORT_LIST_LIMIT_PARAM))
  };
}

export function buildReportListUrlSearchParams({ search = '', page = 1, pageSize = REPORT_LIST_PAGE_SIZE } = {}) {
  const next = new URLSearchParams();
  const q = normalizeReportListSearch(search);
  if (q) next.set(REPORT_LIST_SEARCH_PARAM, q);
  const p = normalizeReportListPage(page);
  if (p > 1) next.set(REPORT_LIST_PAGE_PARAM, String(p));
  const size = normalizeReportListPageSize(pageSize);
  if (size !== REPORT_LIST_PAGE_SIZE) next.set(REPORT_LIST_LIMIT_PARAM, String(size));
  return next;
}

/**
 * Footer pagination state for a loaded page. `page` is clamped to the total,
 * so a page that no longer exists (result set shrank) reports the last valid
 * page and the caller can navigate there.
 */
export function describeReportListPagination({ page = 1, total = 0, pageSize = REPORT_LIST_PAGE_SIZE } = {}) {
  const t = Math.max(0, Number(total) || 0);
  const size = Math.max(1, Number(pageSize) || REPORT_LIST_PAGE_SIZE);
  const totalPages = reportListTotalPages(t, size);
  const safePage = clampReportListPage(page, t, size);
  const from = t === 0 ? 0 : (safePage - 1) * size + 1;
  const to = t === 0 ? 0 : Math.min(safePage * size, t);
  return {
    page: safePage,
    pageSize: size,
    total: t,
    totalPages,
    from,
    to,
    hasPrevious: t > 0 && safePage > 1,
    hasNext: t > 0 && safePage < totalPages,
    pageLabel: `Page ${safePage} of ${totalPages}`
  };
}

/**
 * Which table placeholder to render. The genuine "library is empty" copy is
 * reserved for an unfiltered empty result; a search with zero hits gets its
 * own message so the user never thinks the library was wiped. An empty page
 * while `total` is still positive is an out-of-range page that the page-clamp
 * is about to correct, so it stays on the loading placeholder.
 * @returns {{ kind: 'none'|'loading'|'empty'|'no_match', message: string, hint: string }}
 */
export function describeReportListEmptyState({ loading = false, itemCount = 0, total = 0, search = '', canWrite = false } = {}) {
  if (loading) return { kind: 'loading', message: 'Loading…', hint: '' };
  if (itemCount > 0) return { kind: 'none', message: '', hint: '' };
  if ((Number(total) || 0) > 0) return { kind: 'loading', message: 'Loading…', hint: '' };
  if (normalizeReportListSearch(search)) {
    return {
      kind: 'no_match',
      message: 'No reports match your search.',
      hint: 'Try another title, source, or report type.'
    };
  }
  return {
    kind: 'empty',
    message: 'No reports yet.',
    hint: canWrite ? 'Use Import Intelligence to add the first one.' : ''
  };
}

/** "Showing 1–25 of 157 reports" — the total is the filtered total when a search is active. */
export function formatReportListShowingLabel({ from = 0, to = 0, total = 0, search = '' } = {}) {
  const t = Math.max(0, Number(total) || 0);
  const noun = `report${t === 1 ? '' : 's'}`;
  const suffix = normalizeReportListSearch(search) ? ' matching your search' : '';
  if (t === 0) return `Showing 0 of 0 ${noun}${suffix}`;
  const a = Math.max(0, Number(from) || 0);
  const b = Math.max(a, Number(to) || 0);
  return `Showing ${a}–${b} of ${t} ${noun}${suffix}`;
}
