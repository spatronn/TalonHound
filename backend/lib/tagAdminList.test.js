import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TAG_ADMIN_DEFAULT_PAGE_SIZE,
  TAG_ADMIN_MAX_PAGE_SIZE,
  buildTagAdminCountQuery,
  buildTagAdminFilterClause,
  buildTagAdminPageQuery,
  buildTagAdminPagination,
  formatTagAdminShowingRange,
  parseTagAdminListQuery
} from './tagAdminList.js';

test('parseTagAdminListQuery defaults page 1 and page_size 25', () => {
  const q = parseTagAdminListQuery({});
  assert.equal(q.page, 1);
  assert.equal(q.page_size, TAG_ADMIN_DEFAULT_PAGE_SIZE);
  assert.equal(q.offset, 0);
  assert.equal(q.include_inactive, true);
  assert.equal(q.search, '');
});

test('parseTagAdminListQuery applies offset and caps page_size', () => {
  const q = parseTagAdminListQuery({ page: '2', page_size: '1000', include_inactive: 'false', search: '  MiRaI  ' });
  assert.equal(q.page, 2);
  assert.equal(q.page_size, TAG_ADMIN_MAX_PAGE_SIZE);
  assert.equal(q.offset, TAG_ADMIN_MAX_PAGE_SIZE);
  assert.equal(q.include_inactive, false);
  assert.equal(q.search, 'mirai');
});

test('parseTagAdminListQuery coerces invalid page/page_size', () => {
  const q = parseTagAdminListQuery({ page: '0', page_size: '-5' });
  assert.equal(q.page, 1);
  assert.equal(q.page_size, TAG_ADMIN_DEFAULT_PAGE_SIZE);
});

test('buildTagAdminPagination totals and flags', () => {
  const p = buildTagAdminPagination({ page: 1, page_size: 25, total_items: 1243 });
  assert.equal(p.total_pages, 50);
  assert.equal(p.has_previous, false);
  assert.equal(p.has_next, true);
  assert.equal(p.total_items, 1243);

  const last = buildTagAdminPagination({ page: 50, page_size: 25, total_items: 1243 });
  assert.equal(last.has_previous, true);
  assert.equal(last.has_next, false);

  const empty = buildTagAdminPagination({ page: 3, page_size: 25, total_items: 0 });
  assert.equal(empty.page, 1);
  assert.equal(empty.total_pages, 1);
  assert.equal(empty.has_next, false);
});

test('formatTagAdminShowingRange labels', () => {
  assert.equal(formatTagAdminShowingRange({ page: 1, page_size: 25, total_items: 1243 }).label, 'Showing 1–25 of 1243');
  assert.equal(formatTagAdminShowingRange({ page: 50, page_size: 25, total_items: 1243 }).label, 'Showing 1226–1243 of 1243');
  assert.equal(formatTagAdminShowingRange({ page: 1, page_size: 25, total_items: 0 }).label, 'Showing 0 of 0');
});

test('count and page queries share identical filters', () => {
  const opts = { include_inactive: false, search: 'elf', page_size: 25, offset: 25 };
  const filter = buildTagAdminFilterClause(opts, 1);
  const count = buildTagAdminCountQuery(opts);
  const page = buildTagAdminPageQuery(opts);

  assert.match(filter.sql, /t\.enabled = TRUE/);
  assert.match(filter.sql, /t\.name LIKE/);
  assert.match(filter.sql, /it_search\.source_name/);
  assert.equal(count.sql.includes(filter.sql), true);
  assert.deepEqual(count.params, ['elf']);

  assert.match(page.sql, /ORDER BY t\.name ASC, t\.id ASC/);
  assert.match(page.sql, /LIMIT \$2 OFFSET \$3/);
  assert.deepEqual(page.params, ['elf', 25, 25]);
  assert.equal(page.sql.includes(filter.sql), true);
});

test('empty search omits LIKE clause', () => {
  const filter = buildTagAdminFilterClause({ include_inactive: true, search: '' }, 1);
  assert.equal(filter.sql, '');
  assert.deepEqual(filter.params, []);
});
