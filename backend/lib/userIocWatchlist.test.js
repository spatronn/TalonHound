import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseWatchlistPublicId,
  normalizeUserId,
  parseWatchlistListParams,
  buildWatchlistPagination,
  iocRowToPageItem,
  annotateItemsWatchlisted,
  addToWatchlist,
  removeFromWatchlist,
  isWatchlisted
} from './userIocWatchlist.js';

test('parseWatchlistPublicId accepts valid uuid (lowercased), rejects junk', () => {
  assert.equal(
    parseWatchlistPublicId('A1B2C3D4-E5F6-7788-99AA-BBCCDDEEFF00'),
    'a1b2c3d4-e5f6-7788-99aa-bbccddeeff00'
  );
  assert.equal(parseWatchlistPublicId('not-a-uuid'), null);
  assert.equal(parseWatchlistPublicId(''), null);
  assert.equal(parseWatchlistPublicId(null), null);
  assert.equal(parseWatchlistPublicId('123'), null);
});

test('normalizeUserId only accepts positive integers', () => {
  assert.equal(normalizeUserId(5), 5);
  assert.equal(normalizeUserId('7'), 7);
  assert.equal(normalizeUserId(0), null);
  assert.equal(normalizeUserId(-3), null);
  assert.equal(normalizeUserId(null), null);
  assert.equal(normalizeUserId(1.5), null);
});

test('parseWatchlistListParams clamps page and normalizes page_size', () => {
  assert.deepEqual(parseWatchlistListParams({}), { page: 1, pageSize: 25, limit: 25, offset: 0 });
  assert.deepEqual(parseWatchlistListParams({ page: '3', page_size: '50' }), {
    page: 3, pageSize: 50, limit: 50, offset: 100
  });
  // Illegal page sizes fall back to the default 25.
  assert.equal(parseWatchlistListParams({ page_size: '999' }).pageSize, 25);
  assert.equal(parseWatchlistListParams({ page: '0' }).page, 1);
  assert.equal(parseWatchlistListParams({ page: '-4' }).page, 1);
});

test('buildWatchlistPagination reports exact totals and page counts', () => {
  const p = buildWatchlistPagination({ page: 2, pageSize: 25, total: 30 });
  assert.equal(p.total, 30);
  assert.equal(p.page_count, 2);
  assert.equal(p.mode, 'watchlist');
  const empty = buildWatchlistPagination({ page: 1, pageSize: 25, total: 0 });
  assert.equal(empty.page_count, 1);
  assert.equal(empty.total, 0);
});

test('iocRowToPageItem mirrors the IOC-list pageItem shape', () => {
  const item = iocRowToPageItem({
    id: 42, public_id: 'pid', observable: 'evil.com', observable_type: 'domain',
    source_name: 's', confidence: 'high', created_at: 't0', status: 'active'
  });
  assert.equal(item.id, 42);
  assert.equal(item.observable, 'evil.com');
  assert.equal(item.observable_type, 'domain');
  assert.equal(item.ip, 'evil.com');
  assert.deepEqual(item.source_names, []);
});

test('annotateItemsWatchlisted sets false for everything when no viewer', async () => {
  const items = [{ id: 1 }, { id: 2 }];
  const pool = { async query() { throw new Error('should not query without a viewer'); } };
  await annotateItemsWatchlisted(pool, null, items);
  assert.deepEqual(items.map((i) => i.watchlisted), [false, false]);
});

test('annotateItemsWatchlisted marks only the viewer-starred ids in one query', async () => {
  let calls = 0;
  const pool = {
    async query(sql, params) {
      calls += 1;
      assert.match(sql, /FROM user_ioc_watchlist/);
      assert.equal(params[0], 9); // viewer id
      // starred set for this user
      return { rows: [{ ioc_id: 2 }] };
    }
  };
  const items = [{ id: 1 }, { id: 2 }, { id: 3 }];
  await annotateItemsWatchlisted(pool, 9, items);
  assert.deepEqual(items.map((i) => i.watchlisted), [false, true, false]);
  assert.equal(calls, 1, 'exactly one batched membership query (no N+1)');
});

// Store helpers against a tiny fake pool: idempotency of add/remove.
function fakeWatchlistPool() {
  const rows = [];
  return {
    rows,
    async query(sql, params) {
      const s = String(sql);
      if (s.startsWith('INSERT INTO user_ioc_watchlist')) {
        const [user_id, observable_type, ioc_id] = params;
        if (rows.some((r) => r.user_id === user_id && r.observable_type === observable_type && r.ioc_id === ioc_id)) {
          return { rowCount: 0 };
        }
        rows.push({ user_id, observable_type, ioc_id });
        return { rowCount: 1 };
      }
      if (s.startsWith('DELETE FROM user_ioc_watchlist')) {
        const [user_id, observable_type, ioc_id] = params;
        const before = rows.length;
        for (let i = rows.length - 1; i >= 0; i -= 1) {
          const r = rows[i];
          if (r.user_id === user_id && r.observable_type === observable_type && r.ioc_id === ioc_id) rows.splice(i, 1);
        }
        return { rowCount: before - rows.length };
      }
      if (s.includes('SELECT 1 FROM user_ioc_watchlist')) {
        const [user_id, observable_type, ioc_id] = params;
        const hit = rows.some((r) => r.user_id === user_id && r.observable_type === observable_type && r.ioc_id === ioc_id);
        return { rowCount: hit ? 1 : 0, rows: hit ? [{ '?column?': 1 }] : [] };
      }
      throw new Error(`unexpected sql ${s}`);
    }
  };
}

test('add is idempotent; second add is a no-op', async () => {
  const pool = fakeWatchlistPool();
  const ref = { ioc_id: 100, observable_type: 'ip' };
  assert.deepEqual(await addToWatchlist(pool, 1, ref), { created: true });
  assert.deepEqual(await addToWatchlist(pool, 1, ref), { created: false });
  assert.equal(await isWatchlisted(pool, 1, ref), true);
  assert.equal(pool.rows.length, 1);
});

test('remove is idempotent; removing an absent row is a no-op', async () => {
  const pool = fakeWatchlistPool();
  const ref = { ioc_id: 100, observable_type: 'ip' };
  await addToWatchlist(pool, 1, ref);
  assert.deepEqual(await removeFromWatchlist(pool, 1, ref), { removed: true });
  assert.deepEqual(await removeFromWatchlist(pool, 1, ref), { removed: false });
  assert.equal(await isWatchlisted(pool, 1, ref), false);
});

test('watchlists are isolated per user', async () => {
  const pool = fakeWatchlistPool();
  const ref = { ioc_id: 100, observable_type: 'ip' };
  await addToWatchlist(pool, 1, ref);
  assert.equal(await isWatchlisted(pool, 1, ref), true);
  assert.equal(await isWatchlisted(pool, 2, ref), false, "user 2 must not see user 1's star");
});
