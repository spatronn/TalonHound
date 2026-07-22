import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIocSearchExportRoutes } from './iocSearchExports.js';

const USER_A = { role: 'analyst', id: 11, email: 'a@example.com', username: 'a@example.com' };
const USER_B = { role: 'analyst', id: 22, email: 'b@example.com', username: 'b@example.com' };
const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com', username: 'admin@example.com' };

// In-memory export store backing the mock pool, keyed by id.
function createMockPool(store) {
  let seq = 1;
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('INSERT INTO ioc_search_exports')) {
        const id = `export-${seq++}`;
        const row = {
          id,
          original_query: params[0],
          normalized_query: params[1],
          normalized_ast: params[2],
          format: params[3],
          selected_columns: params[4],
          scope: params[5],
          requested_by_id: params[6],
          requested_by_email: params[7],
          status: 'queued',
          progress: 0,
          record_count: null,
          file_size: null,
          storage_path: null,
          expires_at: null,
          failure_reason: null,
          cancelled_at: null,
          retry_count: 0,
          created_at: new Date().toISOString()
        };
        store.set(id, row);
        return { rows: [row], rowCount: 1 };
      }
      if (s.includes('COUNT(*)::int AS n')) {
        const email = params[0];
        const n = [...store.values()].filter((r) => r.requested_by_email === email && ['queued', 'processing'].includes(r.status)).length;
        return { rows: [{ n }], rowCount: 1 };
      }
      if (s.includes('SET job_id')) return { rows: [], rowCount: 1 };
      if (s.includes('FROM ioc_search_exports') && s.includes('WHERE id = $1')) {
        const row = store.get(params[0]) || null;
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      if (s.includes('FROM ioc_search_exports')) {
        // listExports: params may include email filter as $1 when not includeAll.
        let rows = [...store.values()];
        if (s.includes('WHERE requested_by_email = $1')) {
          rows = rows.filter((r) => r.requested_by_email === params[0]);
        }
        return { rows, rowCount: rows.length };
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

function makeApp(store) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user'] ? JSON.parse(String(req.headers['x-test-user'])) : USER_A;
    next();
  });
  const pool = createMockPool(store);
  const exportQueue = { add: async () => ({ id: 'job-1' }) };
  const auditLogService = { auditSuccess: async () => {}, auditFailure: async () => {} };
  registerIocSearchExportRoutes(app, pool, { exportQueue, auditLogService });
  return app;
}

async function req(app, method, path, { body, user } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${path}`, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(fn) {
  const store = new Map();
  const app = makeApp(store);
  const server = app.listen(0);
  app.__port = server.address().port;
  try { await fn({ app, store }); } finally { await new Promise((r) => server.close(r)); }
}

test('User A creates an export; only A (and admin) can read it, B is forbidden', async () => {
  await withServer(async ({ app }) => {
    const created = await req(app, 'POST', '/api/iocs/search-exports', {
      user: USER_A,
      body: { query: 'ioc contains "example.com"', format: 'csv', scope: 'all' }
    });
    assert.equal(created.status, 201);
    const id = created.data.export_id;
    assert.ok(id);

    // A can read own export.
    const aRead = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: USER_A });
    assert.equal(aRead.status, 200);

    // B cannot read A's export.
    const bRead = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: USER_B });
    assert.equal(bRead.status, 403);

    // B cannot download A's export.
    const bDownload = await req(app, 'GET', `/api/iocs/search-exports/${id}/download`, { user: USER_B });
    assert.equal(bDownload.status, 403);

    // Admin can read any export.
    const adminRead = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: ADMIN });
    assert.equal(adminRead.status, 200);
  });
});

test("B's export list never includes A's exports", async () => {
  await withServer(async ({ app }) => {
    await req(app, 'POST', '/api/iocs/search-exports', { user: USER_A, body: { query: 'ioc contains "a"' } });
    const bList = await req(app, 'GET', '/api/iocs/search-exports', { user: USER_B });
    assert.equal(bList.status, 200);
    assert.equal(bList.data.items.length, 0);
    const aList = await req(app, 'GET', '/api/iocs/search-exports', { user: USER_A });
    assert.equal(aList.data.items.length, 1);
  });
});

test('download rejects non-ready, and expired exports', async () => {
  await withServer(async ({ app, store }) => {
    const created = await req(app, 'POST', '/api/iocs/search-exports', { user: USER_A, body: { query: 'ioc contains "a"' } });
    const id = created.data.export_id;

    // queued -> 409 not ready
    const notReady = await req(app, 'GET', `/api/iocs/search-exports/${id}/download`, { user: USER_A });
    assert.equal(notReady.status, 409);

    // ready but expired -> 410
    const row = store.get(id);
    row.status = 'ready';
    row.storage_path = `${id}.csv`;
    row.expires_at = new Date(Date.now() - 1000).toISOString();
    const expired = await req(app, 'GET', `/api/iocs/search-exports/${id}/download`, { user: USER_A });
    assert.equal(expired.status, 410);
  });
});

test('invalid DSL query is rejected at export creation', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'POST', '/api/iocs/search-exports', { user: USER_A, body: { query: 'example.com' } });
    assert.equal(res.status, 400);
  });
});

test('unknown export id is 404', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/search-exports/does-not-exist', { user: USER_A });
    assert.equal(res.status, 404);
  });
});
