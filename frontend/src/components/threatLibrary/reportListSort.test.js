/**
 * Threat Library list sort state: DEFAULT → ASC → DESC → DEFAULT,
 * URL/query params, pagination reset, and header a11y helpers.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REPORT_LIST_SORTABLE_COLUMNS,
  buildReportListQueryParams,
  buildReportListUrlSearchParams,
  cycleReportListSort,
  parseReportListSortState,
  parseReportListUrlState,
  reportListAriaSort,
  reportListSortMarker
} from './reportList.js';
import { formatPublicationDate } from './publicationDate.js';

test('sortable columns match the list headers including TLP', () => {
  assert.deepEqual([...REPORT_LIST_SORTABLE_COLUMNS], [
    'report', 'source', 'tlp', 'entities', 'indicators', 'matched', 'status', 'published', 'imported'
  ]);
});

test('Published cycles DEFAULT → ASC → DESC → DEFAULT', () => {
  const first = cycleReportListSort('', '', 'published');
  assert.deepEqual(first, { sort: 'published', order: 'asc' });
  assert.equal(reportListSortMarker(first.sort, first.order, 'published'), ' ↑');
  assert.equal(reportListAriaSort(first.sort, first.order, 'published'), 'ascending');
  assert.equal(reportListAriaSort(first.sort, first.order, 'imported'), 'none');

  const second = cycleReportListSort(first.sort, first.order, 'published');
  assert.deepEqual(second, { sort: 'published', order: 'desc' });
  assert.equal(reportListSortMarker(second.sort, second.order, 'published'), ' ↓');
  assert.equal(reportListAriaSort(second.sort, second.order, 'published'), 'descending');

  const third = cycleReportListSort(second.sort, second.order, 'published');
  assert.deepEqual(third, { sort: '', order: '' });
  assert.equal(reportListSortMarker('', '', 'published'), '');
  assert.equal(reportListAriaSort('', '', 'published'), 'none');
  assert.equal(buildReportListUrlSearchParams({ ...third, search: '', page: 1 }).toString(), '');
  assert.deepEqual(buildReportListQueryParams({ ...third, page: 1 }), { limit: 25, offset: 0 });
});

test('clicking another sortable column replaces the previous sort at ASC', () => {
  const next = cycleReportListSort('published', 'desc', 'indicators');
  assert.deepEqual(next, { sort: 'indicators', order: 'asc' });
  assert.equal(reportListSortMarker(next.sort, next.order, 'published'), '');
  assert.equal(reportListAriaSort(next.sort, next.order, 'published'), 'none');
  assert.equal(reportListAriaSort(next.sort, next.order, 'indicators'), 'ascending');
});

test('sort change is requested at offset 0 (page 1); pagination later keeps sort', () => {
  const afterSort = buildReportListQueryParams({
    search: 'zscaler',
    page: 4,
    pageSize: 25,
    sort: 'published',
    order: 'desc'
  });
  assert.deepEqual(afterSort, {
    limit: 25,
    offset: 75,
    search: 'zscaler',
    sort: 'published',
    order: 'desc'
  });
  const reset = buildReportListQueryParams({
    search: 'zscaler',
    page: 1,
    sort: 'published',
    order: 'desc'
  });
  assert.equal(reset.offset, 0);
  assert.equal(reset.sort, 'published');
  const page2 = buildReportListQueryParams({
    search: 'zscaler',
    page: 2,
    pageSize: 50,
    sort: 'indicators',
    order: 'asc'
  });
  assert.deepEqual(page2, {
    limit: 50,
    offset: 50,
    search: 'zscaler',
    sort: 'indicators',
    order: 'asc'
  });
});

test('search composes with sort; default state writes no sort/order params', () => {
  const url = buildReportListUrlSearchParams({
    search: 'zscaler',
    page: 2,
    pageSize: 50,
    sort: 'published',
    order: 'desc'
  });
  assert.equal(url.toString(), 'search=zscaler&page=2&limit=50&sort=published&order=desc');
  assert.deepEqual(parseReportListUrlState(url), {
    search: 'zscaler',
    page: 2,
    pageSize: 50,
    sort: 'published',
    order: 'desc'
  });
  assert.equal(buildReportListUrlSearchParams({ search: '', page: 1 }).toString(), '');
  assert.equal(buildReportListUrlSearchParams({ sort: 'published', order: '' }).toString(), '');
  assert.equal(buildReportListUrlSearchParams({ sort: 'drop-table', order: 'desc' }).toString(), '');
  assert.deepEqual(parseReportListUrlState('sort=published'), {
    search: '', page: 1, pageSize: 25, sort: '', order: ''
  });
  assert.deepEqual(parseReportListUrlState('sort=published;drop&order=desc'), {
    search: '', page: 1, pageSize: 25, sort: '', order: ''
  });
  assert.deepEqual(parseReportListSortState('published', 'sideways'), { sort: '', order: '' });
});

test('Published NULL display remains a placeholder independent of Imported', () => {
  const missing = { published_at: null, published_date: null, created_at: '2026-09-16T00:30:21+03:00' };
  assert.equal(formatPublicationDate(missing), null);
  assert.equal(formatPublicationDate(missing) || '—', '—');
});

test('keyboard/button semantics: cycle helper is what the header button calls', () => {
  let state = { sort: '', order: '' };
  state = cycleReportListSort(state.sort, state.order, 'report');
  state = cycleReportListSort(state.sort, state.order, 'report');
  state = cycleReportListSort(state.sort, state.order, 'report');
  assert.deepEqual(state, { sort: '', order: '' });
});
