import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_LIST_PAGE_SIZE,
  REPORT_LIST_PAGE_SIZE_OPTIONS,
  REPORT_LIST_SEARCH_DEBOUNCE_MS,
  REPORT_LIST_SEARCH_MAX_LENGTH,
  buildReportListQueryParams,
  buildReportListUrlSearchParams,
  clampReportListPage,
  describeReportListEmptyState,
  describeReportListPagination,
  formatReportListShowingLabel,
  normalizeReportListPage,
  normalizeReportListPageSize,
  normalizeReportListSearch,
  parseReportListUrlState,
  reportListTotalPages
} from './reportList.js';

test('debounce sits in the 250-350ms window and the page size follows the app convention (25)', () => {
  assert.ok(REPORT_LIST_SEARCH_DEBOUNCE_MS >= 250 && REPORT_LIST_SEARCH_DEBOUNCE_MS <= 350);
  assert.equal(REPORT_LIST_PAGE_SIZE, 25);
});

test('normalizeReportListSearch trims, bounds and rejects non-strings', () => {
  assert.equal(normalizeReportListSearch('  Iranian  '), 'Iranian');
  assert.equal(normalizeReportListSearch('   '), '');
  assert.equal(normalizeReportListSearch(null), '');
  assert.equal(normalizeReportListSearch(undefined), '');
  assert.equal(normalizeReportListSearch(['a']), '');
  assert.equal(normalizeReportListSearch('x'.repeat(REPORT_LIST_SEARCH_MAX_LENGTH + 50)).length, REPORT_LIST_SEARCH_MAX_LENGTH);
});

test('normalizeReportListPage accepts safe positive integers only', () => {
  assert.equal(normalizeReportListPage('3'), 3);
  assert.equal(normalizeReportListPage(7), 7);
  for (const bad of ['0', '-4', 'abc', '', null, undefined, 'NaN', '2.5', '1e400', 'Infinity', '9007199254740993', ' ']) {
    assert.equal(normalizeReportListPage(bad), 1, `page ${JSON.stringify(bad)} -> 1`);
  }
});

// --- request params -----------------------------------------------------------

test('initial (page 1, no search) request is limit 25 / offset 0 with no search param', () => {
  assert.deepEqual(buildReportListQueryParams({}), { limit: 25, offset: 0 });
  assert.deepEqual(buildReportListQueryParams({ search: '', page: 1 }), { limit: 25, offset: 0 });
  assert.deepEqual(buildReportListQueryParams({ search: '   ' }), { limit: 25, offset: 0 });
});

test('Next / Previous map to the next and previous offsets', () => {
  assert.deepEqual(buildReportListQueryParams({ page: 2 }), { limit: 25, offset: 25 });
  assert.deepEqual(buildReportListQueryParams({ page: 3 }), { limit: 25, offset: 50 });
  assert.deepEqual(buildReportListQueryParams({ page: 7 }), { limit: 25, offset: 150 });
  assert.deepEqual(buildReportListQueryParams({ page: 2 - 1 }), { limit: 25, offset: 0 });
});

test('a search term is sent alongside pagination, trimmed', () => {
  assert.deepEqual(buildReportListQueryParams({ search: ' ncsc ', page: 4 }), { limit: 25, offset: 75, search: 'ncsc' });
  // Invalid page in params falls back to the first page.
  assert.deepEqual(buildReportListQueryParams({ search: 'x', page: -9 }), { limit: 25, offset: 0, search: 'x' });
});

// --- URL state ----------------------------------------------------------------

test('URL seeds search and page; page=1 and blank search are omitted when serialising', () => {
  assert.deepEqual(parseReportListUrlState(new URLSearchParams('search=iranian&page=2')), { search: 'iranian', page: 2, pageSize: 25, sort: '', order: '', status: '', tlp: '', source: '', imported: '' });
  assert.deepEqual(parseReportListUrlState('search=%20socradar%20'), { search: 'socradar', page: 1, pageSize: 25, sort: '', order: '', status: '', tlp: '', source: '', imported: '' });
  assert.deepEqual(parseReportListUrlState(new URLSearchParams('page=5')), { search: '', page: 5, pageSize: 25, sort: '', order: '', status: '', tlp: '', source: '', imported: '' });
  assert.deepEqual(parseReportListUrlState(null), { search: '', page: 1, pageSize: 25, sort: '', order: '', status: '', tlp: '', source: '', imported: '' });
  assert.equal(buildReportListUrlSearchParams({ search: 'threat_report', page: 3 }).toString(), 'search=threat_report&page=3');
  assert.equal(buildReportListUrlSearchParams({ search: 'threat_report', page: 1 }).toString(), 'search=threat_report');
  assert.equal(buildReportListUrlSearchParams({ search: '', page: 2 }).toString(), 'page=2');
  assert.equal(buildReportListUrlSearchParams({ search: '', page: 1 }).toString(), '');
  const roundTrip = parseReportListUrlState(buildReportListUrlSearchParams({ search: 'cta-nk', page: 4 }));
  assert.deepEqual(roundTrip, { search: 'cta-nk', page: 4, pageSize: 25, sort: '', order: '', status: '', tlp: '', source: '', imported: '' });
});

// --- rows per page (25 / 50) ------------------------------------------------------

test('page size options are 25 / 50 with 25 as the default; anything else normalises to 25', () => {
  assert.deepEqual([...REPORT_LIST_PAGE_SIZE_OPTIONS], [25, 50]);
  assert.equal(normalizeReportListPageSize(50), 50);
  assert.equal(normalizeReportListPageSize('50'), 50);
  assert.equal(normalizeReportListPageSize(' 25 '), 25);
  for (const junk of [undefined, null, '', '10', '100', '200', 'abc', '-50', '50.5', 0, NaN]) {
    assert.equal(normalizeReportListPageSize(junk), 25, String(junk));
  }
});

test('limit=50 is requested with 50-row offsets; an invalid size never reaches the API', () => {
  assert.deepEqual(buildReportListQueryParams({ page: 1, pageSize: 50 }), { limit: 50, offset: 0 });
  assert.deepEqual(buildReportListQueryParams({ page: 3, pageSize: 50 }), { limit: 50, offset: 100 });
  assert.deepEqual(buildReportListQueryParams({ search: 'apt', page: 2, pageSize: 50 }), { limit: 50, offset: 50, search: 'apt' });
  assert.deepEqual(buildReportListQueryParams({ page: 2, pageSize: 10 }), { limit: 25, offset: 25 });
  assert.deepEqual(buildReportListQueryParams({ page: 2, pageSize: 1000 }), { limit: 25, offset: 25 });
});

test('URL carries ?limit= only for a non-default size and round-trips with search + page', () => {
  assert.equal(buildReportListUrlSearchParams({ search: 'apt', page: 2, pageSize: 50 }).toString(), 'search=apt&page=2&limit=50');
  assert.equal(buildReportListUrlSearchParams({ page: 1, pageSize: 50 }).toString(), 'limit=50');
  assert.equal(buildReportListUrlSearchParams({ page: 1, pageSize: 25 }).toString(), '', 'the default size is not written');
  assert.equal(buildReportListUrlSearchParams({ page: 1, pageSize: 999 }).toString(), '');
  assert.deepEqual(parseReportListUrlState('search=apt&page=2&limit=50'), { search: 'apt', page: 2, pageSize: 50, sort: '', order: '', status: '', tlp: '', source: '', imported: '' });
  for (const q of ['limit=10', 'limit=100', 'limit=abc', 'limit=', 'limit=-50']) {
    assert.equal(parseReportListUrlState(q).pageSize, 25, q);
  }
  // Parsed state serialises to a fixed point, so the page's canonicalising effect cannot loop.
  const canonical = buildReportListUrlSearchParams(parseReportListUrlState('limit=50&page=3&search=%20apt%20'));
  assert.equal(canonical.toString(), 'search=apt&page=3&limit=50');
  assert.equal(buildReportListUrlSearchParams(parseReportListUrlState(canonical)).toString(), canonical.toString());
});

test('50 rows per page: footer maths, last page and filtered totals', () => {
  const first = describeReportListPagination({ page: 1, total: 157, pageSize: 50 });
  assert.deepEqual([first.from, first.to, first.totalPages, first.pageLabel, first.hasPrevious, first.hasNext], [1, 50, 4, 'Page 1 of 4', false, true]);
  const last = describeReportListPagination({ page: 4, total: 157, pageSize: 50 });
  assert.deepEqual([last.from, last.to, last.hasNext, last.hasPrevious], [151, 157, false, true]);
  assert.equal(formatReportListShowingLabel({ from: last.from, to: last.to, total: 157 }), 'Showing 151–157 of 157 reports');
  // Same library at 25/page has 7 pages; page 7 at 25 is out of range at 50 and clamps to 4.
  assert.equal(describeReportListPagination({ page: 7, total: 157, pageSize: 25 }).page, 7);
  assert.equal(clampReportListPage(7, 157, 50), 4);
  const filtered = describeReportListPagination({ page: 1, total: 40, pageSize: 50 });
  assert.deepEqual([filtered.totalPages, filtered.to, filtered.hasNext], [1, 40, false]);
});

test('invalid URL page values fall back to page 1 without throwing', () => {
  for (const q of ['page=0', 'page=-1', 'page=abc', 'page=', 'page=NaN', 'page=1e400', 'page=2.5', 'page=99999999999999999999']) {
    assert.equal(parseReportListUrlState(new URLSearchParams(q)).page, 1, q);
  }
});

// --- pagination maths -----------------------------------------------------------

test('total pages and clamping', () => {
  assert.equal(reportListTotalPages(0), 1);
  assert.equal(reportListTotalPages(1), 1);
  assert.equal(reportListTotalPages(25), 1);
  assert.equal(reportListTotalPages(26), 2);
  assert.equal(reportListTotalPages(157), 7);
  assert.equal(clampReportListPage(6, 30), 2, 'page 6 of a 2-page set -> last valid page');
  assert.equal(clampReportListPage(6, 0), 1, 'empty set -> page 1');
  assert.equal(clampReportListPage(3, 157), 3);
  assert.equal(clampReportListPage('abc', 157), 1);
});

test('Page X of Y, Showing A-B of N, and Previous/Next enablement across a 157-row library', () => {
  const p1 = describeReportListPagination({ page: 1, total: 157 });
  assert.equal(p1.pageLabel, 'Page 1 of 7');
  assert.deepEqual([p1.from, p1.to, p1.hasPrevious, p1.hasNext], [1, 25, false, true]);
  assert.equal(formatReportListShowingLabel({ from: p1.from, to: p1.to, total: 157 }), 'Showing 1–25 of 157 reports');

  const p4 = describeReportListPagination({ page: 4, total: 157 });
  assert.deepEqual([p4.from, p4.to, p4.hasPrevious, p4.hasNext], [76, 100, true, true]);

  const p7 = describeReportListPagination({ page: 7, total: 157 });
  assert.equal(p7.pageLabel, 'Page 7 of 7');
  assert.deepEqual([p7.from, p7.to, p7.hasPrevious, p7.hasNext], [151, 157, true, false]);
  assert.equal(formatReportListShowingLabel({ from: p7.from, to: p7.to, total: 157 }), 'Showing 151–157 of 157 reports');
});

test('filtered pagination uses the filtered total (78 matches -> 4 pages)', () => {
  const p1 = describeReportListPagination({ page: 1, total: 78 });
  assert.equal(p1.pageLabel, 'Page 1 of 4');
  assert.equal(formatReportListShowingLabel({ from: p1.from, to: p1.to, total: 78, search: 'threat_report' }), 'Showing 1–25 of 78 reports matching your search');
  const p4 = describeReportListPagination({ page: 4, total: 78 });
  assert.deepEqual([p4.from, p4.to, p4.hasNext], [76, 78, false]);
});

test('zero results: both buttons disabled, Page 1 of 1, Showing 0 of 0', () => {
  const p = describeReportListPagination({ page: 3, total: 0 });
  assert.deepEqual([p.page, p.totalPages, p.from, p.to, p.hasPrevious, p.hasNext], [1, 1, 0, 0, false, false]);
  assert.equal(formatReportListShowingLabel({ from: 0, to: 0, total: 0 }), 'Showing 0 of 0 reports');
  assert.equal(formatReportListShowingLabel({ from: 1, to: 1, total: 1 }), 'Showing 1–1 of 1 report');
});

test('an out-of-range page is clamped so the footer never shows a stranded page (page 6 of 2)', () => {
  const p = describeReportListPagination({ page: 6, total: 30 });
  assert.equal(p.page, 2);
  assert.equal(p.pageLabel, 'Page 2 of 2');
  assert.deepEqual([p.from, p.to, p.hasPrevious, p.hasNext], [26, 30, true, false]);
});

// --- empty state ----------------------------------------------------------------

test('empty-state: loading wins, then rows, then a positive total (out-of-range page), then search vs genuine-empty copy', () => {
  assert.equal(describeReportListEmptyState({ loading: true, itemCount: 0, search: 'x' }).kind, 'loading');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 3, search: 'x' }).kind, 'none');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 3, search: '' }).kind, 'none');
  // Zero rows on this page but the filtered set is not empty: a page clamp is pending, keep the placeholder.
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 0, total: 30, search: 'x' }).kind, 'loading');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 0, total: 30, search: '' }).kind, 'loading');

  const noMatch = describeReportListEmptyState({ loading: false, itemCount: 0, total: 0, search: 'zzz' });
  assert.equal(noMatch.kind, 'no_match');
  assert.equal(noMatch.message, 'No reports match your search.');
  assert.equal(noMatch.hint, 'Try another title, source, or tag.');

  const empty = describeReportListEmptyState({ loading: false, itemCount: 0, total: 0, search: '', canWrite: true });
  assert.equal(empty.kind, 'empty');
  assert.equal(empty.message, 'No reports yet.');
  assert.equal(empty.hint, 'Use Import Intelligence to add the first one.');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 0, search: '', canWrite: false }).hint, '');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 0, search: '   ' }).kind, 'empty');
});

// --- Filters / status tabs / sort menu / pager (list modernisation) ---------

test('filters round-trip through the URL and the API params; junk values are dropped', async () => {
  const {
    buildReportListQueryParams: q,
    buildReportListUrlSearchParams: u,
    parseReportListUrlState: parse,
    hasActiveReportListFilters,
    normalizeReportListFilters
  } = await import('./reportList.js');
  const url = u({ search: 'apt', page: 3, status: 'failed', tlp: 'amber_strict', source: 'thib', imported: '30d' });
  assert.equal(url.toString(), 'search=apt&status=failed&tlp=amber_strict&source=thib&imported=30d&page=3');
  assert.deepEqual(parse(url), {
    search: 'apt', page: 3, pageSize: 25, sort: '', order: '', status: 'failed', tlp: 'amber_strict', source: 'thib', imported: '30d'
  });
  assert.deepEqual(q({ page: 2, status: 'preparing', imported: '24h' }), { limit: 25, offset: 25, status: 'preparing', imported: '24h' });
  assert.deepEqual(normalizeReportListFilters({ status: 'ready', tlp: 'white', source: 'feed', imported: '1y' }), {
    status: '', tlp: '', source: '', imported: ''
  }, 'only real API values: "ready" is an analysis_status, not a phase filter');
  assert.equal(parse('status=Review_Ready').status, 'review_ready');
  assert.equal(hasActiveReportListFilters({}), false);
  assert.equal(hasActiveReportListFilters({ search: '  ' }), false);
  assert.equal(hasActiveReportListFilters({ search: 'x' }), true);
  assert.equal(hasActiveReportListFilters({ tlp: 'red' }), true);
});

test('status tabs are the four report phases plus All, keyed to phase_counts', async () => {
  const { REPORT_LIST_STATUS_TABS, normalizeReportListPhaseCounts } = await import('./reportList.js');
  assert.deepEqual(REPORT_LIST_STATUS_TABS.map((t) => [t.value, t.label, t.countKey]), [
    ['', 'All', 'all'],
    ['finalized', 'Ready', 'finalized'],
    ['review_ready', 'Needs Review', 'review_ready'],
    ['preparing', 'Processing', 'preparing'],
    ['failed', 'Failed', 'failed']
  ]);
  assert.equal(normalizeReportListPhaseCounts(undefined), null);
  assert.equal(normalizeReportListPhaseCounts({ all: 3 }), null, 'partial counts are not shown');
  assert.deepEqual(
    normalizeReportListPhaseCounts({ all: '4', preparing: 1, review_ready: 1, finalized: 1, failed: 1 }),
    { all: 4, preparing: 1, review_ready: 1, finalized: 1, failed: 1 }
  );
});

test('sort menu mirrors the header sort state, including header-only combinations', async () => {
  const { describeReportListSortMenu, parseReportListSortMenuValue, REPORT_LIST_SORT_PRESETS } = await import('./reportList.js');
  assert.equal(describeReportListSortMenu('', '').value, '');
  assert.equal(describeReportListSortMenu('', '').options.length, REPORT_LIST_SORT_PRESETS.length);
  assert.equal(describeReportListSortMenu('indicators', 'desc').value, 'indicators:desc');
  const custom = describeReportListSortMenu('source', 'asc');
  assert.equal(custom.value, 'source:asc');
  assert.deepEqual(custom.options.at(-1), { value: 'source:asc', label: 'Source ↑' });
  assert.deepEqual(parseReportListSortMenuValue('published:desc'), { sort: 'published', order: 'desc' });
  assert.deepEqual(parseReportListSortMenuValue(''), { sort: '', order: '' });
  assert.deepEqual(parseReportListSortMenuValue('drop:table'), { sort: '', order: '' });
  for (const preset of REPORT_LIST_SORT_PRESETS) {
    assert.deepEqual(parseReportListSortMenuValue(preset.value), { sort: preset.sort, order: preset.order });
  }
});

test('pager items: all pages up to 7, otherwise first/last/current±1 with gaps (never a 1-page gap)', async () => {
  const { buildReportListPageItems: items } = await import('./reportList.js');
  assert.deepEqual(items(1, 1), [1]);
  assert.deepEqual(items(3, 7), [1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(items(1, 20), [1, 2, 3, 4, 5, 'gap-end', 20]);
  assert.deepEqual(items(10, 20), [1, 'gap-start', 9, 10, 11, 'gap-end', 20]);
  assert.deepEqual(items(20, 20), [1, 'gap-start', 16, 17, 18, 19, 20]);
  assert.deepEqual(items(4, 9), [1, 2, 3, 4, 5, 'gap-end', 9]);
  assert.deepEqual(items(6, 9), [1, 'gap-start', 5, 6, 7, 8, 9]);
  assert.deepEqual(items(99, 9).at(-1), 9, 'out-of-range page clamps');
  for (let last = 1; last <= 40; last += 1) {
    for (let p = 1; p <= last; p += 1) {
      const list = items(p, last);
      assert.ok(list.length <= 7, `${p}/${last}`);
      assert.ok(list.includes(p));
    }
  }
});

test('empty state: request error is never shown as an empty library; filters get filter copy', async () => {
  const { describeReportListEmptyState: d, formatReportListShowingLabel: f } = await import('./reportList.js');
  assert.equal(d({ error: 'Failed to load Threat Library' }).kind, 'error');
  assert.equal(d({ error: 'x', itemCount: 3 }).kind, 'none');
  const filtered = d({ filters: { tlp: 'red' } });
  assert.equal(filtered.kind, 'no_match');
  assert.equal(filtered.message, 'No reports match the current filters.');
  assert.equal(d({ search: 'x' }).message, 'No reports match your search.');
  assert.equal(d({}).kind, 'empty');
  assert.equal(f({ from: 1, to: 2, total: 2, filtered: true }), 'Showing 1–2 of 2 reports matching your filters');
});
