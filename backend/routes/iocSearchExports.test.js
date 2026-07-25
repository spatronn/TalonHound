import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { registerIocSearchExportRoutes } from './iocSearchExports.js';

const USER_A = { role: 'analyst', id: 11, email: 'a@example.com', username: 'a@example.com' };
const USER_B = { role: 'analyst', id: 22, email: 'b@example.com', username: 'b@example.com' };
const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com', username: 'admin@example.com' };

function createMockPool(store, { storageDir } = {}) {
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
          requested_at: new Date().toISOString(),
          started_at: null,
          completed_at: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        store.set(id, row);
        return { rows: [row], rowCount: 1 };
      }

      if (s.includes('COUNT(*)::int AS n') && s.includes("status IN ('queued', 'processing')")) {
        const email = params[0];
        const n = [...store.values()].filter(
          (r) => r.requested_by_email === email && ['queued', 'processing'].includes(r.status)
        ).length;
        return { rows: [{ n }], rowCount: 1 };
      }

      if (s.includes('COUNT(*)::int AS n')) {
        let rows = [...store.values()];
        if (s.includes('requested_by_email = $1')) {
          rows = rows.filter((r) => r.requested_by_email === params[0]);
        }
        if (s.includes('status = ANY')) {
          const statuses = params.find((p) => Array.isArray(p)) || [];
          rows = rows.filter((r) => statuses.includes(r.status));
        } else if (s.includes("status = 'expired'")) {
          rows = rows.filter(
            (r) =>
              r.status === 'expired' ||
              (r.status === 'ready' && r.expires_at && new Date(r.expires_at) <= new Date())
          );
        } else if (s.includes("status = 'ready'")) {
          rows = rows.filter(
            (r) => r.status === 'ready' && (!r.expires_at || new Date(r.expires_at) > new Date())
          );
        }
        return { rows: [{ n: rows.length }], rowCount: 1 };
      }

      if (s.includes('SET job_id')) return { rows: [], rowCount: 1 };

      if (s.includes('SET status = \'expired\'')) {
        const row = store.get(params[0]);
        if (!row || !['ready', 'expired'].includes(row.status)) return { rows: [], rowCount: 0 };
        row.status = 'expired';
        row.storage_path = null;
        row.updated_at = new Date().toISOString();
        return { rows: [row], rowCount: 1 };
      }

      if (s.includes('FROM ioc_search_exports') && /WHERE id = \$1\b/.test(s)) {
        const row = store.get(params[0]) || null;
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }

      if (s.includes('FROM ioc_search_exports')) {
        let rows = [...store.values()];
        if (s.includes('requested_by_email = $1')) {
          rows = rows.filter((r) => r.requested_by_email === params[0]);
        }
        if (s.includes('status = ANY')) {
          const statuses = params.find((p) => Array.isArray(p)) || [];
          rows = rows.filter((r) => statuses.includes(r.status));
        } else if (s.includes("status = 'expired'")) {
          rows = rows.filter(
            (r) =>
              r.status === 'expired' ||
              (r.status === 'ready' && r.expires_at && new Date(r.expires_at) <= new Date())
          );
        } else if (s.includes("status = 'ready'")) {
          rows = rows.filter(
            (r) => r.status === 'ready' && (!r.expires_at || new Date(r.expires_at) > new Date())
          );
        }
        rows.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
        if (s.includes('LIMIT')) {
          const limit = params[params.length - 2];
          const offset = params[params.length - 1];
          rows = rows.slice(offset, offset + limit);
        }
        return { rows, rowCount: rows.length };
      }

      return { rows: [], rowCount: 0 };
    },
    __storageDir: storageDir
  };
}

function makeApp(store, { storageDir } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user'] ? JSON.parse(String(req.headers['x-test-user'])) : USER_A;
    next();
  });
  if (storageDir) process.env.IOC_EXPORT_STORAGE_DIR = storageDir;
  const pool = createMockPool(store, { storageDir });
  const exportQueue = { add: async () => ({ id: 'job-1' }) };
  const auditLogService = { auditSuccess: async () => {}, auditFailure: async () => {} };
  registerIocSearchExportRoutes(app, pool, { exportQueue, auditLogService });
  return app;
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
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return { status: res.status, data };
}

async function withServer(fn, { storageDir } = {}) {
  const store = new Map();
  const app = makeApp(store, { storageDir });
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await fn({ app, store });
  } finally {
    await new Promise((r) => server.close(r));
  }
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

    const aRead = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: USER_A });
    assert.equal(aRead.status, 200);
    assert.equal(aRead.data.task_type, 'ioc_search_export');

    const bRead = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: USER_B });
    assert.equal(bRead.status, 403);

    const bDownload = await req(app, 'GET', `/api/iocs/search-exports/${id}/download`, { user: USER_B });
    assert.equal(bDownload.status, 403);

    const adminRead = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: ADMIN });
    assert.equal(adminRead.status, 200);
  });
});

test("B's export list never includes A's exports", async () => {
  await withServer(async ({ app }) => {
    await req(app, 'POST', '/api/iocs/search-exports', {
      user: USER_A,
      body: { query: 'ioc contains "a"' }
    });
    const bList = await req(app, 'GET', '/api/iocs/search-exports', { user: USER_B });
    assert.equal(bList.status, 200);
    assert.equal(bList.data.items.length, 0);
    assert.equal(bList.data.total, 0);
    const aList = await req(app, 'GET', '/api/iocs/search-exports', { user: USER_A });
    assert.equal(aList.data.items.length, 1);
    assert.equal(aList.data.total, 1);
  });
});

test('list supports status filter and pagination metadata', async () => {
  await withServer(async ({ app, store }) => {
    const c1 = await req(app, 'POST', '/api/iocs/search-exports', {
      user: USER_A,
      body: { query: 'ioc contains "one"' }
    });
    const c2 = await req(app, 'POST', '/api/iocs/search-exports', {
      user: USER_A,
      body: { query: 'ioc contains "two"' }
    });
    store.get(c1.data.export_id).status = 'failed';
    store.get(c2.data.export_id).status = 'ready';
    store.get(c2.data.export_id).expires_at = new Date(Date.now() + 3600_000).toISOString();

    const failed = await req(app, 'GET', '/api/iocs/search-exports?status=failed&page=1&page_size=25', {
      user: USER_A
    });
    assert.equal(failed.status, 200);
    assert.equal(failed.data.total, 1);
    assert.equal(failed.data.items[0].status, 'failed');
    assert.equal(failed.data.page, 1);
    assert.equal(failed.data.page_size, 25);

    const bad = await req(app, 'GET', '/api/iocs/search-exports?status=nope', { user: USER_A });
    assert.equal(bad.status, 400);
  });
});

test('download rejects non-ready and expired exports (server-side)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ioc-export-'));
  try {
    await withServer(
      async ({ app, store }) => {
        const created = await req(app, 'POST', '/api/iocs/search-exports', {
          user: USER_A,
          body: { query: 'ioc contains "a"' }
        });
        const id = created.data.export_id;

        const notReady = await req(app, 'GET', `/api/iocs/search-exports/${id}/download`, { user: USER_A });
        assert.equal(notReady.status, 409);

        const row = store.get(id);
        row.status = 'ready';
        row.storage_path = `${id}.csv`;
        row.expires_at = new Date(Date.now() - 1000).toISOString();
        fs.writeFileSync(path.join(dir, `${id}.csv`), 'ioc\n');

        const expired = await req(app, 'GET', `/api/iocs/search-exports/${id}/download`, { user: USER_A });
        assert.equal(expired.status, 410);

        // Detail should also surface expired.
        const detail = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: USER_A });
        assert.equal(detail.status, 200);
        assert.equal(detail.data.status, 'expired');
      },
      { storageDir: dir }
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('valid ready download streams the file', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ioc-export-'));
  try {
    await withServer(
      async ({ app, store }) => {
        const created = await req(app, 'POST', '/api/iocs/search-exports', {
          user: USER_A,
          body: { query: 'ioc contains "a"' }
        });
        const id = created.data.export_id;
        const row = store.get(id);
        row.status = 'ready';
        row.storage_path = `${id}.csv`;
        row.expires_at = new Date(Date.now() + 3600_000).toISOString();
        row.completed_at = new Date().toISOString();
        fs.writeFileSync(path.join(dir, `${id}.csv`), 'ioc\nexample.com\n');

        const res = await fetch(`http://127.0.0.1:${app.__port}/api/iocs/search-exports/${id}/download`, {
          headers: { 'x-test-user': JSON.stringify(USER_A) }
        });
        assert.equal(res.status, 200);
        assert.match(res.headers.get('content-disposition') || '', /attachment/);
        const body = await res.text();
        assert.match(body, /example\.com/);
      },
      { storageDir: dir }
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('retry creates a new task and leaves the failed row unchanged', async () => {
  await withServer(async ({ app, store }) => {
    const created = await req(app, 'POST', '/api/iocs/search-exports', {
      user: USER_A,
      body: { query: 'ioc contains "retry-me"', format: 'csv_gz', scope: 'preview' }
    });
    const id = created.data.export_id;
    const failed = store.get(id);
    failed.status = 'failed';
    failed.failure_reason = 'boom at /data/ioc-search-exports/x.csv';

    const detail = await req(app, 'GET', `/api/iocs/search-exports/${id}`, { user: USER_A });
    assert.equal(detail.data.status, 'failed');
    assert.ok(!String(detail.data.failure_reason || '').includes('/data/'));

    const retried = await req(app, 'POST', `/api/iocs/search-exports/${id}/retry`, { user: USER_A });
    assert.equal(retried.status, 201);
    assert.notEqual(retried.data.id, id);
    assert.equal(retried.data.status, 'queued');
    assert.equal(store.get(id).status, 'failed');
    assert.equal(store.size, 2);
  });
});

test('create-again on expired creates a new task', async () => {
  await withServer(async ({ app, store }) => {
    const created = await req(app, 'POST', '/api/iocs/search-exports', {
      user: USER_A,
      body: { query: 'ioc contains "again"' }
    });
    const id = created.data.export_id;
    const row = store.get(id);
    row.status = 'expired';
    row.expires_at = new Date(Date.now() - 1000).toISOString();

    const again = await req(app, 'POST', `/api/iocs/search-exports/${id}/create-again`, { user: USER_A });
    assert.equal(again.status, 201);
    assert.notEqual(again.data.id, id);
    assert.equal(again.data.status, 'queued');
    assert.equal(store.get(id).status, 'expired');
  });
});

test('invalid DSL query is rejected at export creation', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'POST', '/api/iocs/search-exports', {
      user: USER_A,
      body: { query: 'example.com' }
    });
    assert.equal(res.status, 400);
  });
});

test('unknown export id is 404', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/search-exports/does-not-exist', { user: USER_A });
    assert.equal(res.status, 404);
  });
});

test('double create while at concurrency limit returns 429', async () => {
  const prev = process.env.IOC_EXPORT_MAX_CONCURRENT_PER_USER;
  process.env.IOC_EXPORT_MAX_CONCURRENT_PER_USER = '1';
  try {
    await withServer(async ({ app }) => {
      const first = await req(app, 'POST', '/api/iocs/search-exports', {
        user: USER_A,
        body: { query: 'ioc contains "one"' }
      });
      assert.equal(first.status, 201);
      const second = await req(app, 'POST', '/api/iocs/search-exports', {
        user: USER_A,
        body: { query: 'ioc contains "two"' }
      });
      assert.equal(second.status, 429);
    });
  } finally {
    if (prev == null) delete process.env.IOC_EXPORT_MAX_CONCURRENT_PER_USER;
    else process.env.IOC_EXPORT_MAX_CONCURRENT_PER_USER = prev;
  }
});
