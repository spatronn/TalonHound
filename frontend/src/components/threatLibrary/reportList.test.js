import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_LIST_PAGE_SIZE,
  REPORT_LIST_SEARCH_DEBOUNCE_MS,
  REPORT_LIST_SEARCH_MAX_LENGTH,
  buildReportListQueryParams,
  buildReportListUrlSearchParams,
  clampReportListPage,
  describeReportListEmptyState,
  describeReportListPagination,
  formatReportListShowingLabel,
  normalizeReportListPage,
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
  assert.deepEqual(parseReportListUrlState(new URLSearchParams('search=iranian&page=2')), { search: 'iranian', page: 2 });
  assert.deepEqual(parseReportListUrlState('search=%20socradar%20'), { search: 'socradar', page: 1 });
  assert.deepEqual(parseReportListUrlState(new URLSearchParams('page=5')), { search: '', page: 5 });
  assert.deepEqual(parseReportListUrlState(null), { search: '', page: 1 });
  assert.equal(buildReportListUrlSearchParams({ search: 'threat_report', page: 3 }).toString(), 'search=threat_report&page=3');
  assert.equal(buildReportListUrlSearchParams({ search: 'threat_report', page: 1 }).toString(), 'search=threat_report');
  assert.equal(buildReportListUrlSearchParams({ search: '', page: 2 }).toString(), 'page=2');
  assert.equal(buildReportListUrlSearchParams({ search: '', page: 1 }).toString(), '');
  const roundTrip = parseReportListUrlState(buildReportListUrlSearchParams({ search: 'cta-nk', page: 4 }));
  assert.deepEqual(roundTrip, { search: 'cta-nk', page: 4 });
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
  assert.equal(noMatch.hint, 'Try another title, source, or report type.');

  const empty = describeReportListEmptyState({ loading: false, itemCount: 0, total: 0, search: '', canWrite: true });
  assert.equal(empty.kind, 'empty');
  assert.equal(empty.message, 'No reports yet.');
  assert.equal(empty.hint, 'Use Import Intelligence to add the first one.');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 0, search: '', canWrite: false }).hint, '');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 0, search: '   ' }).kind, 'empty');
});
