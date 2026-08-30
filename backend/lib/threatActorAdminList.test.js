import test from 'node:test';
import assert from 'node:assert/strict';
import {
  THREAT_ACTOR_ADMIN_DEFAULT_PAGE_SIZE,
  THREAT_ACTOR_ADMIN_MAX_PAGE_SIZE,
  buildThreatActorAdminCountQuery,
  buildThreatActorAdminFilterClause,
  buildThreatActorAdminPageQuery,
  buildThreatActorAdminPagination,
  formatThreatActorAdminShowingRange,
  parseThreatActorAdminListQuery
} from './threatActorAdminList.js';

test('parseThreatActorAdminListQuery defaults page 1 and page_size 25', () => {
  const q = parseThreatActorAdminListQuery({});
  assert.equal(q.page, 1);
  assert.equal(q.page_size, THREAT_ACTOR_ADMIN_DEFAULT_PAGE_SIZE);
  assert.equal(q.offset, 0);
  assert.equal(q.include_inactive, true);
  assert.equal(q.search, '');
});

test('parseThreatActorAdminListQuery applies offset and caps page_size', () => {
  const q = parseThreatActorAdminListQuery({ page: '2', page_size: '1000', include_inactive: 'false', search: '  Fancy Bear  ' });
  assert.equal(q.page, 2);
  assert.equal(q.page_size, THREAT_ACTOR_ADMIN_MAX_PAGE_SIZE);
  assert.equal(q.offset, THREAT_ACTOR_ADMIN_MAX_PAGE_SIZE);
  assert.equal(q.include_inactive, false);
  assert.equal(q.search, 'Fancy Bear');
});

test('buildThreatActorAdminFilterClause searches name and aliases', () => {
  const filter = buildThreatActorAdminFilterClause({ include_inactive: true, search: 'sofacy' }, 1);
  assert.match(filter.sql, /lower\(ta\.name\) LIKE/);
  assert.match(filter.sql, /unnest\(COALESCE\(ta\.aliases/);
  assert.deepEqual(filter.params, ['sofacy']);
});

test('count and page queries share identical filters', () => {
  const opts = { include_inactive: false, search: 'apt29', page_size: 25, offset: 25 };
  const filter = buildThreatActorAdminFilterClause(opts, 1);
  const count = buildThreatActorAdminCountQuery(opts);
  const page = buildThreatActorAdminPageQuery(opts);

  assert.match(filter.sql, /ta\.active = TRUE/);
  assert.equal(count.sql.includes(filter.sql), true);
  assert.deepEqual(count.params, ['apt29']);
  assert.match(page.sql, /ORDER BY ta\.active DESC, ta\.name ASC, ta\.id ASC/);
  assert.match(page.sql, /LIMIT \$2 OFFSET \$3/);
  assert.deepEqual(page.params, ['apt29', 25, 25]);
});

test('buildThreatActorAdminPagination totals and flags', () => {
  const p = buildThreatActorAdminPagination({ page: 1, page_size: 25, total_items: 1043 });
  assert.equal(p.total_pages, 42);
  assert.equal(p.has_previous, false);
  assert.equal(p.has_next, true);
  assert.equal(formatThreatActorAdminShowingRange({ page: 42, page_size: 25, total_items: 1043 }).label, 'Showing 1026–1043 of 1043');
});
