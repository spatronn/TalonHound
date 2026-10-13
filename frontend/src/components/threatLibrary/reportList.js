/**
 * Threat Library report-list helpers: search normalisation, pagination maths,
 * request params, URL state and the list empty-state descriptor. Pure
 * functions so the page behaviour is unit-testable without a DOM. Mirrors the
 * threat-actor / tag manager list conventions (25 per page, ?search=&page=),
 * plus a 25 / 50 rows-per-page choice carried as ?limit= (the API parameter),
 * an optional explicit sort as ?sort=&order= and the server-side filters
 * ?status=&tlp=&source=&imported= (same names as the API parameters).
 */

import { TLP_LABELS } from './tlpValues.js';

/** Default rows per page. */
export const REPORT_LIST_PAGE_SIZE = 25;
/** Rows-per-page choices; the API serves exactly these (anything else -> 25). */
export const REPORT_LIST_PAGE_SIZE_OPTIONS = Object.freeze([25, 50]);
export const REPORT_LIST_SEARCH_DEBOUNCE_MS = 300;
export const REPORT_LIST_SEARCH_MAX_LENGTH = 200;
export const REPORT_LIST_SEARCH_PARAM = 'search';
export const REPORT_LIST_PAGE_PARAM = 'page';
export const REPORT_LIST_LIMIT_PARAM = 'limit';
export const REPORT_LIST_SORT_PARAM = 'sort';
export const REPORT_LIST_ORDER_PARAM = 'order';

/** Keys accepted by GET /threat-library/reports?sort=&order=. */
export const REPORT_LIST_SORTABLE_COLUMNS = Object.freeze([
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

/**
 * Status tabs = report presentation phase (reportPhase.js / backend
 * reportPhase.js). Values are the API `status` filter; '' is All. Counts come
 * from the API `phase_counts` (whole filtered set, never the loaded page).
 */
export const REPORT_LIST_STATUS_TABS = Object.freeze([
  { value: '', countKey: 'all', label: 'All', tone: 'all', title: 'All reports matching the search and filters' },
  { value: 'finalized', countKey: 'finalized', label: 'Ready', tone: 'ready', title: 'Analysis complete (including imported THIB bundles)' },
  { value: 'review_ready', countKey: 'review_ready', label: 'Needs Review', tone: 'review', title: 'Analysis complete; Indicators await analyst review' },
  { value: 'preparing', countKey: 'preparing', label: 'Processing', tone: 'processing', title: 'Queued, fetching, extracting, analyzing or matching' },
  { value: 'failed', countKey: 'failed', label: 'Failed', tone: 'failed', title: 'Analysis failed; open the report to retry' }
]);

/** threat_reports.tlp values, most permissive first. */
export const REPORT_LIST_TLP_OPTIONS = Object.freeze([
  { value: '', label: 'All' },
  ...['clear', 'green', 'amber', 'amber_strict', 'red'].map((value) => ({ value, label: TLP_LABELS[value] }))
]);

/** threat_reports.source_type values. */
export const REPORT_LIST_SOURCE_OPTIONS = Object.freeze([
  { value: '', label: 'All' },
  { value: 'url', label: 'URL' },
  { value: 'pdf', label: 'PDF' },
  { value: 'thib', label: 'THIB bundle' }
]);

/** Imported (created_at) windows the API accepts. */
export const REPORT_LIST_IMPORTED_OPTIONS = Object.freeze([
  { value: '', label: 'All time' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' }
]);

const FILTER_OPTIONS = Object.freeze({
  status: REPORT_LIST_STATUS_TABS,
  tlp: REPORT_LIST_TLP_OPTIONS,
  source: REPORT_LIST_SOURCE_OPTIONS,
  imported: REPORT_LIST_IMPORTED_OPTIONS
});

/** URL + API parameter names of the list filters. */
export const REPORT_LIST_FILTER_KEYS = Object.freeze(Object.keys(FILTER_OPTIONS));

/** One supported value of a filter, or '' (= no filter). */
export function normalizeReportListFilter(key, value) {
  const options = FILTER_OPTIONS[key];
  if (!options) return '';
  const v = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return v && options.some((o) => o.value === v) ? v : '';
}

/** Each filter key -> normalised value ('' when unset). */
export function normalizeReportListFilters(state = {}) {
  const out = {};
  for (const key of REPORT_LIST_FILTER_KEYS) out[key] = normalizeReportListFilter(key, state?.[key]);
  return out;
}

/** True when anything narrows the list (search or any filter). */
export function hasActiveReportListFilters(state = {}) {
  if (normalizeReportListSearch(state?.search)) return true;
  return REPORT_LIST_FILTER_KEYS.some((key) => normalizeReportListFilter(key, state?.[key]));
}

/** Option label for a filter value (e.g. tlp amber -> TLP:AMBER). */
export function reportListFilterLabel(key, value) {
  const v = normalizeReportListFilter(key, value);
  return (FILTER_OPTIONS[key] || []).find((o) => o.value === v)?.label || '';
}

/**
 * `phase_counts` from the API, or null when the server did not send them
 * (the tabs then render without numbers instead of guessing).
 */
export function normalizeReportListPhaseCounts(value) {
  if (!value || typeof value !== 'object') return null;
  const out = {};
  for (const tab of REPORT_LIST_STATUS_TABS) {
    const n = Number(value[tab.countKey]);
    if (!Number.isFinite(n) || n < 0) return null;
    out[tab.countKey] = Math.floor(n);
  }
  return out;
}

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
/** Whitelisted sort field, or '' for the canonical default order. */
export function normalizeReportListSort(value) {
  const v = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return REPORT_LIST_SORTABLE_COLUMNS.includes(v) ? v : '';
}

/** `asc` / `desc` only; anything else is no explicit order. */
export function normalizeReportListOrder(value) {
  const v = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return v === 'asc' || v === 'desc' ? v : '';
}

/** Both sort and order must be valid; a partial or junk pair is the default. */
export function parseReportListSortState(sort, order) {
  const nextSort = normalizeReportListSort(sort);
  const nextOrder = normalizeReportListOrder(order);
  if (!nextSort || !nextOrder) return { sort: '', order: '' };
  return { sort: nextSort, order: nextOrder };
}

/**
 * Three-state cycle for one column: default → ASC → DESC → default.
 * Clicking a different column starts that column at ASC.
 */
export function cycleReportListSort(currentSort, currentOrder, column) {
  const col = normalizeReportListSort(column);
  if (!col) return { sort: '', order: '' };
  const active = parseReportListSortState(currentSort, currentOrder);
  if (active.sort !== col) return { sort: col, order: 'asc' };
  if (active.order === 'asc') return { sort: col, order: 'desc' };
  return { sort: '', order: '' };
}

export function reportListAriaSort(currentSort, currentOrder, column) {
  const active = parseReportListSortState(currentSort, currentOrder);
  if (active.sort !== column) return 'none';
  return active.order === 'desc' ? 'descending' : 'ascending';
}

export function reportListSortMarker(currentSort, currentOrder, column) {
  const active = parseReportListSortState(currentSort, currentOrder);
  if (active.sort !== column) return '';
  return active.order === 'desc' ? ' ↓' : ' ↑';
}

export function buildReportListQueryParams({
  search = '',
  page = 1,
  pageSize = REPORT_LIST_PAGE_SIZE,
  sort = '',
  order = '',
  ...filters
} = {}) {
  const size = normalizeReportListPageSize(pageSize);
  const p = normalizeReportListPage(page);
  const params = { limit: size, offset: (p - 1) * size };
  const q = normalizeReportListSearch(search);
  if (q) params[REPORT_LIST_SEARCH_PARAM] = q;
  const parsed = parseReportListSortState(sort, order);
  if (parsed.sort) {
    params[REPORT_LIST_SORT_PARAM] = parsed.sort;
    params[REPORT_LIST_ORDER_PARAM] = parsed.order;
  }
  // Filters are only sent when set, so the unfiltered request is unchanged.
  const f = normalizeReportListFilters(filters);
  for (const key of REPORT_LIST_FILTER_KEYS) if (f[key]) params[key] = f[key];
  return params;
}

/** URL state: `?search=` only when active, `?page=` only past page 1, `?limit=` only when not the default. */
export function parseReportListUrlState(searchParams) {
  const params = searchParams && typeof searchParams.get === 'function'
    ? searchParams
    : new URLSearchParams(String(searchParams || ''));
  const parsed = parseReportListSortState(
    params.get(REPORT_LIST_SORT_PARAM),
    params.get(REPORT_LIST_ORDER_PARAM)
  );
  const filters = {};
  for (const key of REPORT_LIST_FILTER_KEYS) filters[key] = params.get(key);
  return {
    search: normalizeReportListSearch(params.get(REPORT_LIST_SEARCH_PARAM) || ''),
    page: normalizeReportListPage(params.get(REPORT_LIST_PAGE_PARAM)),
    pageSize: normalizeReportListPageSize(params.get(REPORT_LIST_LIMIT_PARAM)),
    sort: parsed.sort,
    order: parsed.order,
    ...normalizeReportListFilters(filters)
  };
}

export function buildReportListUrlSearchParams({
  search = '',
  page = 1,
  pageSize = REPORT_LIST_PAGE_SIZE,
  sort = '',
  order = '',
  ...filters
} = {}) {
  const next = new URLSearchParams();
  const q = normalizeReportListSearch(search);
  if (q) next.set(REPORT_LIST_SEARCH_PARAM, q);
  const f = normalizeReportListFilters(filters);
  for (const key of REPORT_LIST_FILTER_KEYS) if (f[key]) next.set(key, f[key]);
  const p = normalizeReportListPage(page);
  if (p > 1) next.set(REPORT_LIST_PAGE_PARAM, String(p));
  const size = normalizeReportListPageSize(pageSize);
  if (size !== REPORT_LIST_PAGE_SIZE) next.set(REPORT_LIST_LIMIT_PARAM, String(size));
  const parsed = parseReportListSortState(sort, order);
  if (parsed.sort) {
    next.set(REPORT_LIST_SORT_PARAM, parsed.sort);
    next.set(REPORT_LIST_ORDER_PARAM, parsed.order);
  }
  return next;
}

/**
 * Sort menu presets: each maps onto the same ?sort=&order= state the column
 * headers cycle, so the menu and the headers can never disagree. '' is the
 * canonical default order (newest import first).
 */
export const REPORT_LIST_SORT_PRESETS = Object.freeze([
  { value: '', sort: '', order: '', label: 'Newest imported' },
  { value: 'imported:asc', sort: 'imported', order: 'asc', label: 'Oldest imported' },
  { value: 'published:desc', sort: 'published', order: 'desc', label: 'Newest published' },
  { value: 'published:asc', sort: 'published', order: 'asc', label: 'Oldest published' },
  { value: 'report:asc', sort: 'report', order: 'asc', label: 'Title A–Z' },
  { value: 'indicators:desc', sort: 'indicators', order: 'desc', label: 'Most Indicators' },
  { value: 'matched:desc', sort: 'matched', order: 'desc', label: 'Most matched IOCs' },
  { value: 'entities:desc', sort: 'entities', order: 'desc', label: 'Most entities' },
  { value: 'tlp:desc', sort: 'tlp', order: 'desc', label: 'Most restrictive TLP' }
]);

const SORT_COLUMN_LABELS = Object.freeze({
  report: 'Report',
  source: 'Source',
  tlp: 'TLP',
  entities: 'Entities',
  indicators: 'Indicators',
  matched: 'Matched IOCs',
  status: 'Status',
  published: 'Published',
  imported: 'Imported'
});

/**
 * Sort menu model for the active sort. A header-only combination (e.g.
 * Source ↑) is appended as its own option so the menu always shows the
 * real active order instead of silently claiming the default.
 * @returns {{ value: string, options: { value: string, label: string }[] }}
 */
export function describeReportListSortMenu(sort, order) {
  const active = parseReportListSortState(sort, order);
  const value = active.sort ? `${active.sort}:${active.order}` : '';
  const options = REPORT_LIST_SORT_PRESETS.map(({ value: v, label }) => ({ value: v, label }));
  if (!options.some((o) => o.value === value)) {
    options.push({ value, label: `${SORT_COLUMN_LABELS[active.sort]} ${active.order === 'desc' ? '↓' : '↑'}` });
  }
  return { value, options };
}

/** Sort menu value -> { sort, order } (junk -> default order). */
export function parseReportListSortMenuValue(value) {
  const [sort, order] = String(value || '').split(':');
  return parseReportListSortState(sort, order);
}

/**
 * Page buttons for the pager: first, last, the current page ±1, and 'gap'
 * markers where pages are skipped (a single skipped page is shown instead of
 * a gap). Never longer than 7 entries.
 * @returns {(number|'gap-start'|'gap-end')[]}
 */
export function buildReportListPageItems(page, totalPages) {
  const last = Math.max(1, Math.floor(Number(totalPages)) || 1);
  const current = Math.min(Math.max(1, Math.floor(Number(page)) || 1), last);
  if (last <= 7) return Array.from({ length: last }, (_, i) => i + 1);
  let start = Math.max(2, current - 1);
  let end = Math.min(last - 1, current + 1);
  if (current <= 3) { start = 2; end = 5; }
  if (current >= last - 2) { start = last - 4; end = last - 1; }
  // A gap that would hide exactly one page shows that page instead.
  if (start === 3) start = 2;
  if (end === last - 2) end = last - 1;
  const items = [1];
  if (start > 2) items.push('gap-start');
  for (let n = start; n <= end; n += 1) items.push(n);
  if (end < last - 1) items.push('gap-end');
  items.push(last);
  return items;
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
 * A failed request gets its own state so an error is never presented as an
 * empty library. Filters (status / TLP / source / imported) get the filter
 * copy; a plain search keeps the search copy.
 * @returns {{ kind: 'none'|'loading'|'error'|'empty'|'no_match', message: string, hint: string }}
 */
export function describeReportListEmptyState({
  loading = false,
  itemCount = 0,
  total = 0,
  search = '',
  canWrite = false,
  error = '',
  filters = {}
} = {}) {
  if (loading) return { kind: 'loading', message: 'Loading…', hint: '' };
  if (itemCount > 0) return { kind: 'none', message: '', hint: '' };
  if (error) return { kind: 'error', message: 'Reports could not be loaded.', hint: 'Use Refresh to try again.' };
  if ((Number(total) || 0) > 0) return { kind: 'loading', message: 'Loading…', hint: '' };
  if (REPORT_LIST_FILTER_KEYS.some((key) => normalizeReportListFilter(key, filters?.[key]))) {
    return {
      kind: 'no_match',
      message: 'No reports match the current filters.',
      hint: 'Clear filters to see the whole library.'
    };
  }
  if (normalizeReportListSearch(search)) {
    return {
      kind: 'no_match',
      message: 'No reports match your search.',
      hint: 'Try another title, source, or tag.'
    };
  }
  return {
    kind: 'empty',
    message: 'No reports yet.',
    hint: canWrite ? 'Use Import Intelligence to add the first one.' : ''
  };
}

/**
 * "Showing 1–25 of 157 reports" — the total is the filtered total when a
 * search or filter is active.
 */
export function formatReportListShowingLabel({ from = 0, to = 0, total = 0, search = '', filtered = false } = {}) {
  const t = Math.max(0, Number(total) || 0);
  const noun = `report${t === 1 ? '' : 's'}`;
  const suffix = filtered ? ' matching your filters' : normalizeReportListSearch(search) ? ' matching your search' : '';
  if (t === 0) return `Showing 0 of 0 ${noun}${suffix}`;
  const a = Math.max(0, Number(from) || 0);
  const b = Math.max(a, Number(to) || 0);
  return `Showing ${a}–${b} of ${t} ${noun}${suffix}`;
}
