import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerUserWatchlistRoutes } from './userWatchlist.js';
import { annotateItemsWatchlisted } from '../lib/userIocWatchlist.js';

const IOC_A = { id: 100, public_id: '11111111-1111-1111-1111-111111111111', observable: 'evil.com', observable_type: 'domain' };
const IOC_B = { id: 200, public_id: '22222222-2222-2222-2222-222222222222', observable: '1.2.3.4', observable_type: 'ip' };
const IOCS = [IOC_A, IOC_B];

// In-memory model of the two tables the routes touch.
function makePool() {
  const watchlist = []; // { user_id, observable_type, ioc_id, created_at }
  let clock = 0;
  const pool = {
    watchlist,
    async query(sql, params = []) {
      const s = String(sql);

      if (s.includes('FROM ioc_items') && s.includes('WHERE public_id')) {
        const ioc = IOCS.find((i) => i.public_id === params[0]);
        return { rows: ioc ? [{ ioc_id: ioc.id, observable_type: ioc.observable_type }] : [] };
      }
      if (s.startsWith('INSERT INTO user_ioc_watchlist')) {
        const [user_id, observable_type, ioc_id] = params;
        if (watchlist.some((r) => r.user_id === user_id && r.observable_type === observable_type && r.ioc_id === ioc_id)) {
          return { rowCount: 0 };
        }
        watchlist.push({ user_id, observable_type, ioc_id, created_at: `t${clock++}` });
        return { rowCount: 1 };
      }
      if (s.startsWith('DELETE FROM user_ioc_watchlist')) {
        const [user_id, observable_type, ioc_id] = params;
        const before = watchlist.length;
        for (let i = watchlist.length - 1; i >= 0; i -= 1) {
          const r = watchlist[i];
          if (r.user_id === user_id && r.observable_type === observable_type && r.ioc_id === ioc_id) watchlist.splice(i, 1);
        }
        return { rowCount: before - watchlist.length };
      }
      if (s.includes('SELECT 1 FROM user_ioc_watchlist')) {
        const [user_id, observable_type, ioc_id] = params;
        const hit = watchlist.some((r) => r.user_id === user_id && r.observable_type === observable_type && r.ioc_id === ioc_id);
        return { rowCount: hit ? 1 : 0, rows: hit ? [{ '?column?': 1 }] : [] };
      }
      if (s.includes('count(*)') && s.includes('FROM user_ioc_watchlist')) {
        const [user_id] = params;
        return { rows: [{ n: watchlist.filter((r) => r.user_id === user_id).length }] };
      }
      if (s.includes('SELECT observable_type, ioc_id, created_at') && s.includes('FROM user_ioc_watchlist')) {
        const [user_id, limit, offset] = params;
        const mine = watchlist
          .filter((r) => r.user_id === user_id)
          .sort((a, b) => (a.created_at < b.created_at ? 1 : -1)) // created_at DESC
          .slice(offset, offset + limit);
        return { rows: mine.map((r) => ({ observable_type: r.observable_type, ioc_id: r.ioc_id, created_at: r.created_at })) };
      }
      if (s.includes('FROM ioc_items i') && s.includes('unnest')) {
        const [types, ids] = params;
        const rows = [];
        for (let i = 0; i < ids.length; i += 1) {
          const ioc = IOCS.find((x) => x.id === ids[i] && x.observable_type === types[i]);
          if (ioc) rows.push({ ...ioc, source_name: 'feed', confidence: 'high', category: null, note: null, created_at: 'c', first_seen_at: 'c', last_seen_at: 'c', status: 'active' });
        }
        return { rows };
      }
      if (s.includes('SELECT ioc_id FROM user_ioc_watchlist') && s.includes('ANY')) {
        const [user_id, ids] = params;
        const set = new Set(ids);
        return { rows: watchlist.filter((r) => r.user_id === user_id && set.has(r.ioc_id)).map((r) => ({ ioc_id: r.ioc_id })) };
      }
      throw new Error(`unexpected sql: ${s}`);
    }
  };
  return pool;
}

function withApp(pool, user) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { if (user) req.user = user; next(); });
  registerUserWatchlistRoutes(app, pool, {
    mapPageItems: async (p, items, viewerUserId) => {
      await annotateItemsWatchlisted(p, viewerUserId, items);
      return items;
    }
  });
  return app;
}

function call(app, method, path, body) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, {
          method,
          headers: { 'content-type': 'application/json' },
          body: body === undefined ? undefined : JSON.stringify(body)
        });
        const data = await res.json().catch(() => ({}));
        resolve({ status: res.status, body: data });
      } catch (err) {
        reject(err);
      } finally {
        server.close();
      }
    });
  });
}

const userA = { id: 1, email: 'a@x.com', role: 'analyst' };
const userB = { id: 2, email: 'b@x.com', role: 'readonly' };

test('PUT adds to the caller watchlist and is idempotent', async () => {
  const pool = makePool();
  const app = withApp(pool, userA);
  let res = await call(app, 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { watchlisted: true });
  res = await call(app, 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { watchlisted: true });
  assert.equal(pool.watchlist.filter((r) => r.user_id === 1).length, 1, 'no duplicate row');
});

test('DELETE removes and is idempotent', async () => {
  const pool = makePool();
  const app = withApp(pool, userA);
  await call(app, 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  let res = await call(app, 'DELETE', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.deepEqual(res.body, { watchlisted: false });
  res = await call(app, 'DELETE', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { watchlisted: false });
});

test('readonly user may manage their own watchlist (route layer)', async () => {
  const pool = makePool();
  const app = withApp(pool, userB); // readonly
  const res = await call(app, 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, { watchlisted: true });
});

test('unauthenticated (no user) is rejected', async () => {
  const pool = makePool();
  const app = withApp(pool, null);
  const res = await call(app, 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.equal(res.status, 403);
  assert.equal(pool.watchlist.length, 0);
});

test('machine principal (id null) cannot use the watchlist', async () => {
  const pool = makePool();
  const app = withApp(pool, { id: null, role: 'admin', email: 'api-ingest@internal' });
  const res = await call(app, 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.equal(res.status, 403);
});

test('invalid uuid → 400; nonexistent IOC → 404', async () => {
  const pool = makePool();
  const app = withApp(pool, userA);
  let res = await call(app, 'PUT', '/api/ioc/not-a-uuid/watchlist');
  assert.equal(res.status, 400);
  res = await call(app, 'PUT', '/api/ioc/33333333-3333-3333-3333-333333333333/watchlist');
  assert.equal(res.status, 404);
});

test('GET per-IOC status reflects only the caller', async () => {
  const pool = makePool();
  await call(withApp(pool, userA), 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  const aStatus = await call(withApp(pool, userA), 'GET', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.deepEqual(aStatus.body, { watchlisted: true });
  const bStatus = await call(withApp(pool, userB), 'GET', `/api/ioc/${IOC_A.public_id}/watchlist`);
  assert.deepEqual(bStatus.body, { watchlisted: false });
});

test('user isolation: A and B watchlists never overlap', async () => {
  const pool = makePool();
  await call(withApp(pool, userA), 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  await call(withApp(pool, userB), 'PUT', `/api/ioc/${IOC_B.public_id}/watchlist`);

  const aList = await call(withApp(pool, userA), 'GET', '/api/watchlist');
  const bList = await call(withApp(pool, userB), 'GET', '/api/watchlist');

  assert.deepEqual(aList.body.items.map((i) => i.public_id), [IOC_A.public_id]);
  assert.deepEqual(bList.body.items.map((i) => i.public_id), [IOC_B.public_id]);
  assert.equal(aList.body.items[0].watchlisted, true);
  assert.equal(aList.body.pagination.total, 1);
});

test('GET list body cannot choose another user via query/body', async () => {
  const pool = makePool();
  await call(withApp(pool, userA), 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  // User B tries to read user A's list by smuggling user_id — ignored; derived from session.
  const res = await call(withApp(pool, userB), 'GET', '/api/watchlist?user_id=1');
  assert.deepEqual(res.body.items, []);
  assert.equal(res.body.pagination.total, 0);
});

test('GET list is empty and paginates cleanly with no stars', async () => {
  const pool = makePool();
  const res = await call(withApp(pool, userA), 'GET', '/api/watchlist');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.items, []);
  assert.equal(res.body.pagination.total, 0);
  assert.equal(res.body.pagination.page_count, 1);
});

test('GET list paginates in SQL (LIMIT/OFFSET), newest star first', async () => {
  const pool = makePool();
  const app = withApp(pool, userA);
  await call(app, 'PUT', `/api/ioc/${IOC_A.public_id}/watchlist`);
  await call(app, 'PUT', `/api/ioc/${IOC_B.public_id}/watchlist`);
  const page1 = await call(app, 'GET', '/api/watchlist?page=1&page_size=25');
  // newest first → IOC_B (added last) then IOC_A
  assert.deepEqual(page1.body.items.map((i) => i.public_id), [IOC_B.public_id, IOC_A.public_id]);
  assert.equal(page1.body.pagination.total, 2);
});
