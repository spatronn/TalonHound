import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIocSavedSearchRoutes } from './iocSavedSearches.js';
import { rbacHttpPolicy } from '../lib/rbac.js';

const USER_A = { role: 'analyst', id: 11, email: 'a@example.com', username: 'a@example.com' };
const USER_B = { role: 'analyst', id: 22, email: 'b@example.com', username: 'b@example.com' };
const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com', username: 'admin@example.com' };
const READONLY = { role: 'readonly', id: 3, email: 'ro@example.com', username: 'ro@example.com' };

function createMockPool(store) {
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('INSERT INTO ioc_saved_searches')) {
        const name = params[0];
        const ownerId = params[5];
        const dup = [...store.values()].some(
          (r) => Number(r.owner_id) === Number(ownerId) && String(r.name).toLowerCase() === String(name).toLowerCase()
        );
        if (dup) {
          const err = new Error('duplicate');
          err.code = '23505';
          throw err;
        }
        const row = {
          id: crypto.randomUUID(),
          name,
          description: params[1],
          original_query: params[2],
          normalized_query: params[3],
          normalized_ast: params[4],
          owner_id: ownerId,
          owner_username: params[6],
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        store.set(row.id, row);
        return { rows: [row], rowCount: 1 };
      }
      if (s.includes('DELETE FROM ioc_saved_searches')) {
        const ok = store.delete(params[0]);
        return { rows: [], rowCount: ok ? 1 : 0 };
      }
      if (s.includes('FROM ioc_saved_searches') && s.includes('WHERE id = $1')) {
        const row = store.get(params[0]);
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      if (s.includes('FROM ioc_saved_searches') && s.includes('WHERE owner_id = $1')) {
        const rows = [...store.values()]
          .filter((r) => Number(r.owner_id) === Number(params[0]))
          .sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)));
        return { rows, rowCount: rows.length };
      }
      if (s.includes('UPDATE ioc_saved_searches')) {
        const id = params[params.length - 1];
        const row = store.get(id);
        if (!row) return { rows: [], rowCount: 0 };
        if (s.includes('name = $')) {
          const newName = params[0];
          const dup = [...store.values()].some(
            (r) => r.id !== id && Number(r.owner_id) === Number(row.owner_id)
              && String(r.name).toLowerCase() === String(newName).toLowerCase()
          );
          if (dup) {
            const err = new Error('duplicate');
            err.code = '23505';
            throw err;
          }
          row.name = newName;
        }
        if (s.includes('description =')) {
          const idx = [...s.matchAll(/description = \$(\d+)/g)][0];
          if (idx) row.description = params[Number(idx[1]) - 1];
        }
        if (s.includes('original_query =')) {
          const m = s.match(/original_query = \$(\d+)/);
          if (m) row.original_query = params[Number(m[1]) - 1];
        }
        if (s.includes('normalized_query =')) {
          const m = s.match(/normalized_query = \$(\d+)/);
          if (m) row.normalized_query = params[Number(m[1]) - 1];
        }
        row.updated_at = new Date().toISOString();
        return { rows: [row], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

function makeApp(store, { withRbac = false } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user'] ? JSON.parse(String(req.headers['x-test-user'])) : USER_A;
    next();
  });
  if (withRbac) app.use(rbacHttpPolicy);
  const auditEvents = [];
  registerIocSavedSearchRoutes(app, createMockPool(store), {
    auditSuccess: (e) => { auditEvents.push(e); }
  });
  app.__audit = auditEvents;
  return app;
}

async function withServer(fn, opts) {
  const store = new Map();
  const app = makeApp(store, opts);
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  app.__port = server.address().port;
  try {
    return await fn({ app, store });
  } finally {
    await new Promise((r) => server.close(r));
  }
}

async function req(app, method, pathName, { body, user } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${pathName}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* */ }
  return { status: res.status, data, text };
}

const VALID = { name: 'Mirai domains', query: 'type equals "domain"' };

test('create + list + get + run payload', async () => {
  await withServer(async ({ app }) => {
    const created = await req(app, 'POST', '/api/iocs/saved-searches', { user: USER_A, body: VALID });
    assert.equal(created.status, 201);
    assert.equal(created.data.saved_search.name, 'Mirai domains');
    assert.ok(created.data.saved_search.normalized_query);
    const id = created.data.saved_search.id;

    const list = await req(app, 'GET', '/api/iocs/saved-searches', { user: USER_A });
    assert.equal(list.status, 200);
    assert.equal(list.data.saved_searches.length, 1);
    assert.equal(list.data.saved_searches[0].id, id);

    const one = await req(app, 'GET', `/api/iocs/saved-searches/${id}`, { user: USER_A });
    assert.equal(one.status, 200);
    assert.equal(one.data.saved_search.original_query, VALID.query);
  });
});

test('invalid DSL is rejected on save', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'POST', '/api/iocs/saved-searches', {
      user: USER_A,
      body: { name: 'bad', query: 'severity equals "high"' }
    });
    assert.equal(res.status, 400);
    assert.equal(res.data.error?.code, 'unknown_field');
  });
});

test('duplicate name is 409 per owner; other users may reuse the name', async () => {
  await withServer(async ({ app }) => {
    const first = await req(app, 'POST', '/api/iocs/saved-searches', { user: USER_A, body: VALID });
    assert.equal(first.status, 201);
    const dup = await req(app, 'POST', '/api/iocs/saved-searches', {
      user: USER_A,
      body: { name: 'mirai domains', query: 'type equals "ip"' }
    });
    assert.equal(dup.status, 409);
    assert.equal(dup.data.code, 'SAVED_SEARCH_NAME_DUPLICATE');

    const other = await req(app, 'POST', '/api/iocs/saved-searches', { user: USER_B, body: VALID });
    assert.equal(other.status, 201);
  });
});

test('ownership: other analyst cannot get/update/delete; admin can get', async () => {
  await withServer(async ({ app }) => {
    const created = await req(app, 'POST', '/api/iocs/saved-searches', { user: USER_A, body: VALID });
    const id = created.data.saved_search.id;

    const bList = await req(app, 'GET', '/api/iocs/saved-searches', { user: USER_B });
    assert.equal(bList.data.saved_searches.length, 0);

    const bGet = await req(app, 'GET', `/api/iocs/saved-searches/${id}`, { user: USER_B });
    assert.equal(bGet.status, 403);

    const bPatch = await req(app, 'PATCH', `/api/iocs/saved-searches/${id}`, {
      user: USER_B,
      body: { name: 'hijack' }
    });
    assert.equal(bPatch.status, 403);

    const bDel = await req(app, 'DELETE', `/api/iocs/saved-searches/${id}`, { user: USER_B });
    assert.equal(bDel.status, 403);

    const adminGet = await req(app, 'GET', `/api/iocs/saved-searches/${id}`, { user: ADMIN });
    assert.equal(adminGet.status, 200);
  });
});

test('update rename and query; delete removes the row', async () => {
  await withServer(async ({ app }) => {
    const created = await req(app, 'POST', '/api/iocs/saved-searches', { user: USER_A, body: VALID });
    const id = created.data.saved_search.id;
    const renamed = await req(app, 'PATCH', `/api/iocs/saved-searches/${id}`, {
      user: USER_A,
      body: { name: 'Renamed', query: 'type equals "ip"' }
    });
    assert.equal(renamed.status, 200);
    assert.equal(renamed.data.saved_search.name, 'Renamed');
    assert.match(renamed.data.saved_search.normalized_query, /ip/i);

    const del = await req(app, 'DELETE', `/api/iocs/saved-searches/${id}`, { user: USER_A });
    assert.equal(del.status, 200);
    const missing = await req(app, 'GET', `/api/iocs/saved-searches/${id}`, { user: USER_A });
    assert.equal(missing.status, 404);
  });
});

test('readonly can list/get but cannot create', async () => {
  await withServer(async ({ app, store }) => {
    const created = await req(app, 'POST', '/api/iocs/saved-searches', { user: USER_A, body: VALID });
    const id = created.data.saved_search.id;
    store.get(id).owner_id = READONLY.id;

    const list = await req(app, 'GET', '/api/iocs/saved-searches', { user: READONLY });
    assert.equal(list.status, 200);
    assert.equal(list.data.saved_searches.length, 1);

    const post = await req(app, 'POST', '/api/iocs/saved-searches', { user: READONLY, body: VALID });
    assert.equal(post.status, 403);
  });
});

test('readonly POST is also blocked by rbacHttpPolicy', async () => {
  await withServer(async ({ app }) => {
    const post = await req(app, 'POST', '/api/iocs/saved-searches', { user: READONLY, body: VALID });
    assert.equal(post.status, 403);
  }, { withRbac: true });
});

test('create writes audit evidence', async () => {
  await withServer(async ({ app }) => {
    const created = await req(app, 'POST', '/api/iocs/saved-searches', { user: USER_A, body: VALID });
    assert.equal(created.status, 201);
    assert.equal(app.__audit.length, 1);
    assert.equal(app.__audit[0].action, 'ioc.saved_search.created');
  });
});
