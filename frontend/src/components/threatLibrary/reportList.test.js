import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_LIST_PAGE_SIZE,
  REPORT_LIST_SEARCH_DEBOUNCE_MS,
  REPORT_LIST_SEARCH_MAX_LENGTH,
  buildReportListQueryParams,
  buildReportListUrlSearchParams,
  describeReportListEmptyState,
  formatReportListShowingLabel,
  normalizeReportListSearch,
  parseReportListUrlState
} from './reportList.js';

test('debounce sits in the 250-350ms window and the page size is the pre-search value', () => {
  assert.ok(REPORT_LIST_SEARCH_DEBOUNCE_MS >= 250 && REPORT_LIST_SEARCH_DEBOUNCE_MS <= 350);
  assert.equal(REPORT_LIST_PAGE_SIZE, 100);
});

test('normalizeReportListSearch trims, bounds and rejects non-strings', () => {
  assert.equal(normalizeReportListSearch('  Iranian  '), 'Iranian');
  assert.equal(normalizeReportListSearch('   '), '');
  assert.equal(normalizeReportListSearch(null), '');
  assert.equal(normalizeReportListSearch(undefined), '');
  assert.equal(normalizeReportListSearch(['a']), '');
  assert.equal(normalizeReportListSearch('x'.repeat(REPORT_LIST_SEARCH_MAX_LENGTH + 50)).length, REPORT_LIST_SEARCH_MAX_LENGTH);
});

test('blank search produces exactly the pre-search request params', () => {
  assert.deepEqual(buildReportListQueryParams({}), { limit: 100, offset: 0 });
  assert.deepEqual(buildReportListQueryParams({ search: '' }), { limit: 100, offset: 0 });
  assert.deepEqual(buildReportListQueryParams({ search: '   ' }), { limit: 100, offset: 0 });
});

test('typing a term sends it as the `search` param (trimmed), alongside limit/offset', () => {
  assert.deepEqual(buildReportListQueryParams({ search: ' ncsc ' }), { limit: 100, offset: 0, search: 'ncsc' });
  // Pagination-ready: limit/offset are pass-through so adding paging later does not touch search.
  assert.deepEqual(buildReportListQueryParams({ search: 'iran', limit: 25, offset: 50 }), { limit: 25, offset: 50, search: 'iran' });
});

test('URL state round-trips `?search=` and stays empty when the field is cleared', () => {
  assert.deepEqual(parseReportListUrlState(new URLSearchParams('search=iranian')), { search: 'iranian' });
  assert.deepEqual(parseReportListUrlState('search=%20socradar%20'), { search: 'socradar' });
  assert.deepEqual(parseReportListUrlState(new URLSearchParams('')), { search: '' });
  assert.deepEqual(parseReportListUrlState(null), { search: '' });
  assert.equal(buildReportListUrlSearchParams({ search: 'threat_report' }).toString(), 'search=threat_report');
  assert.equal(buildReportListUrlSearchParams({ search: '' }).toString(), '');
  assert.equal(buildReportListUrlSearchParams({ search: '  ' }).toString(), '');
  const roundTrip = parseReportListUrlState(buildReportListUrlSearchParams({ search: 'cta-nk' }));
  assert.deepEqual(roundTrip, { search: 'cta-nk' });
});

test('empty-state: loading wins, then rows, then search-specific vs genuine-empty copy', () => {
  assert.equal(describeReportListEmptyState({ loading: true, itemCount: 0, search: 'x' }).kind, 'loading');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 3, search: 'x' }).kind, 'none');
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 3, search: '' }).kind, 'none');

  const noMatch = describeReportListEmptyState({ loading: false, itemCount: 0, search: 'zzz' });
  assert.equal(noMatch.kind, 'no_match');
  assert.equal(noMatch.message, 'No reports match your search.');
  assert.equal(noMatch.hint, 'Try another title, source, or report type.');
  assert.doesNotMatch(noMatch.message, /No reports yet/);

  const empty = describeReportListEmptyState({ loading: false, itemCount: 0, search: '', canWrite: true });
  assert.equal(empty.kind, 'empty');
  assert.equal(empty.message, 'No reports yet.');
  assert.equal(empty.hint, 'Use Import Intelligence to add the first one.');
  const emptyReadonly = describeReportListEmptyState({ loading: false, itemCount: 0, search: '', canWrite: false });
  assert.equal(emptyReadonly.hint, '');
  // Whitespace-only input is not a search: genuine empty copy is kept.
  assert.equal(describeReportListEmptyState({ loading: false, itemCount: 0, search: '   ' }).kind, 'empty');
});

test('showing label reflects the filtered total and singular/plural', () => {
  assert.equal(formatReportListShowingLabel({ shown: 7, total: 7 }), 'Showing 7 of 7 reports');
  assert.equal(formatReportListShowingLabel({ shown: 1, total: 1 }), 'Showing 1 of 1 report');
  assert.equal(formatReportListShowingLabel({ shown: 12, total: 12, search: 'iran' }), 'Showing 12 of 12 reports matching your search');
  assert.equal(formatReportListShowingLabel({ shown: 100, total: 153, search: '' }), 'Showing 100 of 153 reports');
});
