/**
 * Threat Library report-list helpers: search normalisation, request params,
 * URL state and the list empty-state descriptor. Pure functions so the page
 * behaviour is unit-testable without a DOM.
 */

export const REPORT_LIST_PAGE_SIZE = 100;
export const REPORT_LIST_SEARCH_DEBOUNCE_MS = 300;
export const REPORT_LIST_SEARCH_MAX_LENGTH = 200;
export const REPORT_LIST_SEARCH_PARAM = 'search';

/** Trim and bound the search term; anything else is "no search". */
export function normalizeReportListSearch(value) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, REPORT_LIST_SEARCH_MAX_LENGTH).trim();
}

/**
 * Query params for GET /threat-library/reports. `search` is only sent when
 * non-blank so an empty field is byte-for-byte the pre-search request.
 */
export function buildReportListQueryParams({ search = '', limit = REPORT_LIST_PAGE_SIZE, offset = 0 } = {}) {
  const params = { limit, offset };
  const q = normalizeReportListSearch(search);
  if (q) params[REPORT_LIST_SEARCH_PARAM] = q;
  return params;
}

/** URL state: `?search=` only when active (same convention as the other list pages). */
export function parseReportListUrlState(searchParams) {
  const params = searchParams && typeof searchParams.get === 'function'
    ? searchParams
    : new URLSearchParams(String(searchParams || ''));
  return { search: normalizeReportListSearch(params.get(REPORT_LIST_SEARCH_PARAM) || '') };
}

export function buildReportListUrlSearchParams({ search = '' } = {}) {
  const next = new URLSearchParams();
  const q = normalizeReportListSearch(search);
  if (q) next.set(REPORT_LIST_SEARCH_PARAM, q);
  return next;
}

/**
 * Which table placeholder to render. The genuine "library is empty" copy is
 * reserved for an unfiltered empty result; a search with zero hits gets its
 * own message so the user never thinks the library was wiped.
 * @returns {{ kind: 'none'|'loading'|'empty'|'no_match', message: string, hint: string }}
 */
export function describeReportListEmptyState({ loading = false, itemCount = 0, search = '', canWrite = false } = {}) {
  if (loading) return { kind: 'loading', message: 'Loading…', hint: '' };
  if (itemCount > 0) return { kind: 'none', message: '', hint: '' };
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

/** "Showing X of Y reports" — Y is the filtered total when a search is active. */
export function formatReportListShowingLabel({ shown = 0, total = 0, search = '' } = {}) {
  const t = Math.max(0, Number(total) || 0);
  const s = Math.max(0, Number(shown) || 0);
  const noun = `report${t === 1 ? '' : 's'}`;
  const suffix = normalizeReportListSearch(search) ? ' matching your search' : '';
  return `Showing ${s} of ${t} ${noun}${suffix}`;
}
