import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IOC_LIST_BROWSE_CAP,
  IOC_LIST_DEFAULT_PAGE_SIZE,
  IOC_LIST_ALLOWED_PAGE_SIZES,
  normalizeIocListPageSize,
  buildIocListPagination,
  formatIocListPaginationLabel,
  iocListPageCount
} from './iocListPagination.js';

test('normalizeIocListPageSize defaults to 25 and allows 25/50/100', () => {
  assert.equal(normalizeIocListPageSize(undefined), 25);
  assert.equal(normalizeIocListPageSize(5), 25);
  assert.equal(normalizeIocListPageSize(50), 50);
  assert.deepEqual(IOC_LIST_ALLOWED_PAGE_SIZES, [25, 50, 100]);
  assert.equal(IOC_LIST_DEFAULT_PAGE_SIZE, 25);
});

test('browse mode caps listed_items at 2000 and computes page_count from cap', () => {
  const p = buildIocListPagination({
    mode: 'browse',
    globalTotal: 1672730,
    page: 2,
    pageSize: 25,
    statusFilter: 'active'
  });
  assert.equal(IOC_LIST_BROWSE_CAP, 2000);
  assert.equal(p.listed_items, 2000);
  assert.equal(p.global_total, 1672730);
  assert.equal(p.is_capped, true);
  assert.equal(p.page_count, 80);
  assert.equal(p.total_pages, 80);
  assert.equal(p.mode, 'browse');
});

test('browse mode keeps global_total separate when under cap', () => {
  const p = buildIocListPagination({
    mode: 'browse',
    globalTotal: 842,
    page: 1,
    pageSize: 25,
    statusFilter: 'active'
  });
  assert.equal(p.listed_items, 842);
  assert.equal(p.global_total, 842);
  assert.equal(p.is_capped, false);
  assert.equal(p.page_count, 34);
});

test('search mode caps matches at 2000 without requiring global total', () => {
  const p = buildIocListPagination({
    mode: 'search',
    matchCount: 5000,
    page: 1,
    pageSize: 25
  });
  assert.equal(p.listed_items, 2000);
  assert.equal(p.is_capped, true);
  assert.equal(p.page_count, 80);
  assert.equal(p.global_total, null);
});

test('search mode shows exact match count when small', () => {
  const p = buildIocListPagination({
    mode: 'search',
    matchCount: 3,
    page: 1,
    pageSize: 25
  });
  assert.equal(p.listed_items, 3);
  assert.equal(p.is_capped, false);
  assert.equal(p.page_count, 1);
});

test('filter mode uses browse cap semantics', () => {
  const p = buildIocListPagination({
    mode: 'filter',
    globalTotal: 9000,
    page: 1,
    pageSize: 50,
    statusFilter: 'expired'
  });
  assert.equal(p.listed_items, 2000);
  assert.equal(p.is_capped, true);
  assert.equal(p.page_count, 40);
  assert.equal(p.status_filter, 'expired');
});

test('formatIocListPaginationLabel filter capped', () => {
  const label = formatIocListPaginationLabel(
    buildIocListPagination({ mode: 'filter', globalTotal: 9000, page: 1, pageSize: 25, statusFilter: 'expired' })
  );
  assert.match(label, /Showing latest 2,000 expired IOCs/);
});

test('formatIocListPaginationLabel browse capped', () => {
  const label = formatIocListPaginationLabel(
    buildIocListPagination({ mode: 'browse', globalTotal: 1672730, page: 2, pageSize: 25, statusFilter: 'active' }),
    { total: 1672730 }
  );
  assert.match(label, /Showing latest 2,000 of 1,672,730 active IOCs/);
  assert.match(label, /Page 2 \/ 80/);
});

test('formatIocListPaginationLabel search first matches', () => {
  const label = formatIocListPaginationLabel(
    buildIocListPagination({ mode: 'search', matchCount: 5000, page: 1, pageSize: 25 })
  );
  assert.match(label, /Showing first 2,000 matches/);
});

test('formatIocListPaginationLabel search exact small result', () => {
  const label = formatIocListPaginationLabel(
    buildIocListPagination({ mode: 'search', matchCount: 2, page: 1, pageSize: 25 }),
    {},
    'evil.example'
  );
  assert.match(label, /Showing 2 matching IOCs/);
});

test('iocListPageCount edge cases', () => {
  assert.equal(iocListPageCount(0, 25), 1);
  assert.equal(iocListPageCount(2000, 25), 80);
  assert.equal(iocListPageCount(2000, 100), 20);
});
