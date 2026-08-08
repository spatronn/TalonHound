import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIocDeepSearchRoutes } from './iocDeepSearches.js';

const USER_A = { role: 'analyst', id: 11, email: 'a@example.com', username: 'a@example.com' };
const USER_B = { role: 'analyst', id: 22, email: 'b@example.com', username: 'b@example.com' };
const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com', username: 'admin@example.com' };

function baseRow(overrides = {}) {
  return {
    id: 'ds-1',
    original_query: 'source contains "USOM"',
    normalized_query: 'source contains "USOM"',
    normalized_ast: { type: 'condition' },
    query_fingerprint: 'fp-1',
    classification_reason: 'source_scan',
    origin: 'classified',
    status: 'completed',
    requested_by_id: 11,
    requested_by_email: 'a@example.com',
    match_count: 3,
    truncated: false,
    duration_ms: 1200,
    progress: 100,
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    failure_reason: null,
    cancel_requested: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides
  };
}

function createMockPool(store) {
  let seq = 1;
  const spool = store.__spool || (store.__spool = []);
  return {
    async query(sql, params = []) {
      const s = String(sql);

      if (s.includes('INSERT INTO ioc_deep_searches')) {
        const id = `ds-new-${seq++}`;
        const row = baseRow({
          id,
          original_query: params[0],
          normalized_query: params[1],
          query_fingerprint: params[3],
          classification_reason: params[4],
          origin: params[5],
          status: 'queued',
          requested_by_email: params[7],
          match_count: null
        });
        store.set(id, row);
        return { rows: [row], rowCount: 1 };
      }
      if (s.includes('SET job_id')) return { rows: [], rowCount: 1 };

      if (s.includes('COUNT(*)::int AS n') && s.includes("status IN ('queued', 'running')")) {
        return { rows: [{ n: 0 }], rowCount: 1 };
      }
      if (s.includes("status IN ('queued', 'running')") && s.includes('ORDER BY created_at DESC')) {
        // findActiveDuplicate — none active
        return { rows: [], rowCount: 0 };
      }
      if (s.includes('COUNT(*)::int AS n')) {
        let rows = [...store.values()];
        if (s.includes('requested_by_email = $1')) rows = rows.filter((r) => r.requested_by_email === params[0]);
        return { rows: [{ n: rows.length }], rowCount: 1 };
      }
      if (s.includes('FROM ioc_deep_searches') && s.includes('ORDER BY created_at DESC') && s.includes('LIMIT')) {
        let rows = [...store.values()];
        if (s.includes('requested_by_email = $1')) rows = rows.filter((r) => r.requested_by_email === params[0]);
        return { rows, rowCount: rows.length };
      }
      if (s.includes('FROM ioc_deep_searches WHERE id = $1')) {
        const row = store.get(params[0]);
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      if (s.includes("SET status = 'expired'")) {
        const row = store.get(params[0]);
        if (!row) return { rows: [], rowCount: 0 };
        row.status = 'expired';
        return { rows: [row], rowCount: 1 };
      }
      if (s.includes('SET cancel_requested = TRUE')) {
        const row = store.get(params[0]);
        if (!row || !['queued', 'running'].includes(row.status)) return { rows: [], rowCount: 0 };
        row.cancel_requested = true;
        if (row.status === 'queued') { row.status = 'cancelled'; row.cancelled_at = new Date().toISOString(); }
        return { rows: [row], rowCount: 1 };
      }
      if (s.includes('FROM ioc_deep_search_results')) {
        const dsId = params[0];
        const rows = spool.filter((r) => r.deep_search_id === dsId);
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
  const deepSearchQueue = { add: async () => ({ id: 'job-1' }) };
  const auditLogService = { auditSuccess: async () => {}, auditFailure: async () => {} };
  // Identity-ish mapper: proves the results route feeds spool rows through mapPageItems.
  const mapPageItems = async (_p, pageItems) => pageItems.map((it) => ({ ...it, mapped: true }));
  registerIocDeepSearchRoutes(app, pool, { deepSearchQueue, auditLogService, logger: null, mapPageItems });
  return app;
}

async function req(app, method, pathName, { user } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${pathName}`, { method, headers });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(fn, seed) {
  const store = new Map();
  if (seed) seed(store);
  const app = makeApp(store);
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await fn({ app, store });
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('GET results returns mapped IOC rows for a completed search', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/deep-searches/ds-1/results');
    assert.equal(res.status, 200);
    assert.equal(res.data.result_state, 'ready');
    assert.equal(res.data.items.length, 2);
    assert.ok(res.data.items.every((it) => it.mapped === true), 'rows passed through mapPageItems');
    assert.deepEqual(res.data.conditions.length > 0, true);
    assert.equal(res.data.match_count, 3);
  }, (store) => {
    store.set('ds-1', baseRow());
    store.__spool = [
      { deep_search_id: 'ds-1', position: 1, ioc_item_id: 100, ioc_observable_type: 'domain', public_id: 'p1', observable: 'a.com', status: 'active', created_at: new Date().toISOString(), first_seen_at: null, artifact_id: null },
      { deep_search_id: 'ds-1', position: 2, ioc_item_id: 101, ioc_observable_type: 'domain', public_id: 'p2', observable: 'b.com', status: 'active', created_at: new Date().toISOString(), first_seen_at: null, artifact_id: null }
    ];
  });
});

test('GET results on an expired set returns a clear non-error state (no re-run)', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/deep-searches/ds-1/results');
    assert.equal(res.status, 200);
    assert.equal(res.data.result_state, 'expired');
    assert.deepEqual(res.data.items, []);
  }, (store) => {
    store.set('ds-1', baseRow({ status: 'completed', expires_at: new Date(Date.now() - 1000).toISOString() }));
  });
});

test('GET results while still running returns a processing state', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/deep-searches/ds-1/results');
    assert.equal(res.status, 200);
    assert.equal(res.data.result_state, 'running');
    assert.deepEqual(res.data.items, []);
  }, (store) => {
    store.set('ds-1', baseRow({ status: 'running', match_count: null }));
  });
});

test('another user cannot read a private deep search', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/deep-searches/ds-1', { user: USER_B });
    assert.equal(res.status, 403);
  }, (store) => store.set('ds-1', baseRow()));
});

test('admin can read any deep search', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/deep-searches/ds-1', { user: ADMIN });
    assert.equal(res.status, 200);
    assert.equal(res.data.normalized_query, 'source contains "USOM"');
  }, (store) => store.set('ds-1', baseRow()));
});

test('cancel a completed search is rejected (409)', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'POST', '/api/iocs/deep-searches/ds-1/cancel');
    assert.equal(res.status, 409);
  }, (store) => store.set('ds-1', baseRow({ status: 'completed' })));
});

test('cancel a running search flips cancel_requested', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'POST', '/api/iocs/deep-searches/ds-1/cancel');
    assert.equal(res.status, 200);
  }, (store) => store.set('ds-1', baseRow({ status: 'running' })));
});

test('create-again on an expired search enqueues a fresh job', async () => {
  await withServer(async ({ app, store }) => {
    const res = await req(app, 'POST', '/api/iocs/deep-searches/ds-1/create-again');
    assert.equal(res.status, 201);
    assert.equal(res.data.status, 'queued');
    // A brand-new row was created; the source row is untouched.
    assert.ok([...store.keys()].some((k) => k.startsWith('ds-new-')));
    assert.equal(store.get('ds-1').status, 'expired');
  }, (store) => store.set('ds-1', baseRow({ status: 'expired' })));
});

test('list merges owner rows with a total', async () => {
  await withServer(async ({ app }) => {
    const res = await req(app, 'GET', '/api/iocs/deep-searches');
    assert.equal(res.status, 200);
    assert.equal(res.data.total, 1);
    assert.equal(res.data.items[0].task_type, 'ioc_deep_search');
  }, (store) => store.set('ds-1', baseRow()));
});
