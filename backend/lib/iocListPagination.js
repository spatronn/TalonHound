/** IOC List table browse/search window — summary cards use uncapped global totals. */
export const IOC_LIST_BROWSE_CAP = 2000;
export const IOC_LIST_DEFAULT_PAGE_SIZE = 25;
export const IOC_LIST_ALLOWED_PAGE_SIZES = [25, 50, 100];

/**
 * @param {unknown} raw
 */
export function normalizeIocListPageSize(raw) {
  const n = Number(raw);
  return IOC_LIST_ALLOWED_PAGE_SIZES.includes(n) ? n : IOC_LIST_DEFAULT_PAGE_SIZE;
}

/**
 * @param {number} listedItems
 * @param {number} pageSize
 */
export function iocListPageCount(listedItems, pageSize) {
  const listed = Math.max(Number(listedItems) || 0, 0);
  const size = Math.max(Number(pageSize) || IOC_LIST_DEFAULT_PAGE_SIZE, 1);
  if (listed === 0) return 1;
  return Math.max(Math.ceil(listed / size), 1);
}

/**
 * @param {{
 *   mode?: 'browse'|'search'|'filter',
 *   globalTotal?: number|null,
 *   matchCount?: number|null,
 *   page?: number,
 *   pageSize?: number,
 *   browseCap?: number,
 *   statusFilter?: string,
 * }} opts
 */
export function buildIocListPagination(opts = {}) {
  const mode = opts.mode || 'browse';
  const page = Math.max(Number(opts.page) || 1, 1);
  const pageSize = normalizeIocListPageSize(opts.pageSize);
  const browseCap = Math.max(Number(opts.browseCap) || IOC_LIST_BROWSE_CAP, 1);
  const statusFilter = String(opts.statusFilter || 'active');

  let listedItems;
  let isCapped;

  if (mode === 'search') {
    const matches = Math.max(Number(opts.matchCount) || 0, 0);
    listedItems = Math.min(matches, browseCap);
    isCapped = matches > browseCap;
  } else {
    if (opts.globalTotal == null && opts.globalTotalUnknown) {
      listedItems = browseCap;
      isCapped = true;
    } else {
      const globalTotal = Math.max(Number(opts.globalTotal) || 0, 0);
      listedItems = Math.min(globalTotal, browseCap);
      isCapped = globalTotal > browseCap;
    }
  }

  const pageCount = iocListPageCount(listedItems, pageSize);

  return {
    page,
    page_size: pageSize,
    global_total: opts.globalTotal ?? null,
    listed_items: listedItems,
    browse_cap: browseCap,
    is_capped: isCapped,
    page_count: pageCount,
    mode,
    status_filter: statusFilter,
    // Back-compat for older clients
    total: listedItems,
    total_pages: pageCount
  };
}

/**
 * @param {string} statusFilter
 */
export function iocListStatusLabel(statusFilter) {
  const v = String(statusFilter || 'active').toLowerCase();
  if (v === 'expired') return 'expired';
  if (v === 'suppressed') return 'suppressed';
  if (v === 'all' || v === 'historical') return 'historical';
  if (v === 'disabled') return 'disabled';
  return 'active';
}

/**
 * @param {ReturnType<typeof buildIocListPagination>} pagination
 * @param {{ total?: number }} [summary]
 * @param {string} [search]
 */
export function formatIocListPaginationLabel(pagination, summary = {}, search = '') {
  const fmt = (n) => Number(n || 0).toLocaleString('en-US');
  const page = pagination.page ?? 1;
  const pageCount = pagination.page_count ?? pagination.total_pages ?? 1;
  const listed = pagination.listed_items ?? pagination.total ?? 0;
  const global = pagination.global_total ?? summary.total ?? listed;
  const mode = pagination.mode ?? (search ? 'search' : 'browse');
  const statusLabel = iocListStatusLabel(pagination.status_filter);

  let scope;
  if (mode === 'search' || search) {
    if (listed === 0) {
      scope = 'No matching IOC found across active, expired, and suppressed records';
    } else if (!pagination.is_capped && listed < IOC_LIST_BROWSE_CAP) {
      scope = `Showing ${fmt(listed)} matching IOC${listed === 1 ? '' : 's'} across all statuses`;
    } else {
      scope = `Showing first ${fmt(listed)} matches across all statuses`;
    }
  } else if (mode === 'filter') {
    if (pagination.is_capped) {
      scope = `Showing latest ${fmt(listed)} ${statusLabel} IOCs`;
    } else {
      scope = `Showing ${fmt(listed)} ${statusLabel} IOC${listed === 1 ? '' : 's'}`;
    }
  } else if (pagination.is_capped && statusLabel === 'active') {
    scope = `Showing latest ${fmt(listed)} active IOCs`;
  } else if (pagination.is_capped) {
    scope = `Showing latest ${fmt(listed)} of ${fmt(global)} ${statusLabel} IOCs`;
  } else {
    scope = `Showing ${fmt(listed)} ${statusLabel} IOC${listed === 1 ? '' : 's'}`;
  }

  return `${scope} | Page ${page} / ${pageCount}`;
}
