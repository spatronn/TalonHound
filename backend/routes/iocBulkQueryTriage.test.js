import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIocBulkQueryTriageRoutes } from './iocBulkQueryTriage.js';
import { registerIocBulkTriageRoutes } from './iocBulkTriage.js';
import { AUDIT_ACTION } from '../lib/auditConstants.js';
import { compileQueryWideTarget } from '../lib/iocBulkQueryTriage.js';

const ADMIN = { role: 'admin', publicId: '11111111-1111-1111-1111-111111111111', username: 'admin', email: 'admin@t.local', id: 1 };
const ANALYST = { role: 'analyst', publicId: '22222222-2222-2222-2222-222222222222', username: 'analyst', email: 'analyst@t.local', id: 2 };
const READONLY = { role: 'readonly', publicId: '33333333-3333-3333-3333-333333333333', username: 'ro', email: 'ro@t.local', id: 3 };

const QUERY = 'tag contains "mirai"';

function makePool() {
  const job = {
    id: '11111111-1111-1111-1111-111111111111',
    action: 'tag',
    original_query: QUERY,
    normalized_query: 'tag contains "mirai"',
    normalized_ast: {},
    payload: {},
    status: 'queued',
    match_count: null,
    succeeded: 0,
    skipped: 0,
    failed: 0,
    progress: 0,
    error_sample: null,
    requested_by_id: 2,
    requested_by_email: 'analyst@t.local',
    requested_by_public_id: ANALYST.publicId,
    requested_by_role: 'analyst',
    requested_at: '2026-08-17T00:00:00.000Z',
    started_at: null,
    completed_at: null,
    snapshot_cutoff: null,
    expires_at: null,
    failure_reason: null,
    cancel_requested: false,
    cancelled_at: null,
    job_id: null,
    created_at: '2026-08-17T00:00:00.000Z',
    updated_at: '2026-08-17T00:00:00.000Z'
  };
  const inserts = [];
  return {
    inserts,
    query: async (sql, params = []) => {
      const norm = String(sql);
      if (norm.includes('FROM ioc_bulk_query_jobs') && norm.includes('COUNT(*)')) {
        return { rows: [{ n: 0 }], rowCount: 1 };
      }
      if (norm.includes('INSERT INTO ioc_bulk_query_jobs')) {
        inserts.push({ sql: norm, params });
        let payload = {};
        try { payload = JSON.parse(params[4] || '{}'); } catch { payload = {}; }
        return { rows: [{ ...job, payload }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    },
    connect: async () => ({ query: async () => ({ rows: [] }), release: () => {} })
  };
}

function createApp({ count = 47, executeOutcome = null, queue = null, resolve = null } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user']
      ? JSON.parse(String(req.headers['x-test-user']))
      : ADMIN;
    next();
  });
  const auditCalls = [];
  const executeCalls = [];
  const pool = makePool();
  registerIocBulkTriageRoutes(app, pool, {
    auditSuccess: async (p) => { auditCalls.push(p); }
  });
  registerIocBulkQueryTriageRoutes(app, pool, {
    bulkQueryQueue: queue,
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } },
    deps: {
      countMatchingIocs: async (_pool, compiled) => {
        if (compiled?.deepSearchId != null && compiled.matchCount != null) {
          return { ok: true, matchCount: compiled.matchCount };
        }
        return { ok: true, matchCount: count };
      },
      executeQueryWideBulk: async (_pool, args) => {
        executeCalls.push(args);
        return executeOutcome || {
          ok: true,
          matchCount: args.compiled?.matchCount ?? count,
          requested: args.compiled?.matchCount ?? count,
          succeeded: args.compiled?.matchCount ?? count,
          skipped: 0,
          failed: 0,
          results: []
        };
      },
      ...(resolve ? { resolveQueryWideTarget: resolve } : {})
    }
  });
  app.__auditCalls = auditCalls;
  app.__executeCalls = executeCalls;
  app.__pool = pool;
  return app;
}

async function request(app, path, { body, user, method = 'POST' } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${path}`, {
    method,
    headers,
    body: method === 'GET' ? undefined : JSON.stringify(body || {})
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(app, fn) {
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    return await fn(app);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('query-wide tag uses the query contract and ignores a fake frontend count', async () => {
  const app = createApp({ count: 47 });
  await withServer(app, async () => {
    const res = await request(app, '/api/iocs/bulk/query/tags', {
      body: {
        selection_mode: 'all_matching',
        query: QUERY,
        tag_id: 9,
        match_count: 1,
        ioc_ids: Array.from({ length: 2143 }, (_, i) => i + 1)
      },
      user: ANALYST
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.mode, 'sync');
    assert.equal(res.data.selection_mode, 'all_matching');
    assert.equal(res.data.match_count, 47);
    assert.equal(res.data.query, compileQueryWideTarget(QUERY).normalizedQuery);
    assert.equal(app.__executeCalls.length, 1);
    assert.equal(app.__executeCalls[0].compiled.normalizedQuery, compileQueryWideTarget(QUERY).normalizedQuery);
    assert.equal(Object.prototype.hasOwnProperty.call(app.__executeCalls[0].payload, 'ioc_ids'), false);
    const audit = app.__auditCalls.find((c) => c.action === AUDIT_ACTION.IOC_BULK_QUERY_COMPLETED);
    assert.ok(audit);
    assert.equal(audit.metadata.selection_mode, 'all_matching');
    assert.equal(audit.metadata.match_count, 47);
    assert.equal(audit.metadata.query, compileQueryWideTarget(QUERY).normalizedQuery);
  });
});

test('query-wide classification / suppress / expire bind query, count, and reason', async () => {
  const app = createApp({ count: 30 });
  await withServer(app, async () => {
    const classification = await request(app, '/api/iocs/bulk/query/classifications', {
      body: { selection_mode: 'all_matching', query: QUERY, classification_slug: 'malware' },
      user: ADMIN
    });
    assert.equal(classification.status, 200);
    assert.equal(app.__executeCalls.at(-1).payload.classification_slug, 'malware');

    const suppress = await request(app, '/api/iocs/bulk/query/suppress', {
      body: { selection_mode: 'all_matching', query: QUERY, reason: 'test dataset cleanup' },
      user: ADMIN
    });
    assert.equal(suppress.status, 200);
    assert.equal(app.__executeCalls.at(-1).payload.reason, 'test dataset cleanup');
    const suppressAudit = app.__auditCalls.find((c) => c.metadata?.bulk_action === 'suppress');
    assert.equal(suppressAudit.metadata.reason, 'test dataset cleanup');
    assert.equal(suppressAudit.metadata.match_count, 30);

    const expire = await request(app, '/api/iocs/bulk/query/expire', {
      body: { selection_mode: 'all_matching', query: QUERY, reason: 'expire test iocs' },
      user: ADMIN
    });
    assert.equal(expire.status, 200);
    assert.equal(app.__executeCalls.at(-1).payload.reason, 'expire test iocs');
  });
});

test('backend rejects empty, malformed, readonly, and invalid action', async () => {
  const app = createApp({ count: 10 });
  await withServer(app, async () => {
    const empty = await request(app, '/api/iocs/bulk/query/tags', {
      body: { selection_mode: 'all_matching', query: '', tag_id: 9 },
      user: ADMIN
    });
    assert.equal(empty.status, 400);
    assert.equal(empty.data.code, 'EMPTY_QUERY');

    const malformed = await request(app, '/api/iocs/bulk/query/tags', {
      body: { selection_mode: 'all_matching', query: 'tag contains', tag_id: 9 },
      user: ADMIN
    });
    assert.equal(malformed.status, 400);

    const readonly = await request(app, '/api/iocs/bulk/query/tags', {
      body: { selection_mode: 'all_matching', query: QUERY, tag_id: 9 },
      user: READONLY
    });
    assert.equal(readonly.status, 403);

    const expensive = await request(app, '/api/iocs/bulk/query/tags', {
      body: { selection_mode: 'all_matching', query: 'source contains "USOM"', tag_id: 9 },
      user: ADMIN
    });
    assert.equal(expensive.status, 409);
  });
});

test('large query is enqueued asynchronously instead of a long HTTP request', async () => {
  const enqueued = [];
  const queue = {
    add: async (name, data) => {
      enqueued.push({ name, data });
      return { id: 'bull-1' };
    }
  };
  const app = createApp({ count: 2143, queue });
  await withServer(app, async () => {
    const res = await request(app, '/api/iocs/bulk/query/tags', {
      body: { selection_mode: 'all_matching', query: QUERY, tag_id: 9 },
      user: ANALYST
    });
    assert.equal(res.status, 202);
    assert.equal(res.data.mode, 'async');
    assert.equal(res.data.match_count, 2143);
    assert.ok(res.data.job_id);
    assert.equal(app.__executeCalls.length, 0);
    assert.equal(enqueued.length, 1);
    const audit = app.__auditCalls.find((c) => c.action === AUDIT_ACTION.IOC_BULK_QUERY_ENQUEUED);
    assert.ok(audit);
    assert.equal(audit.metadata.match_count, 2143);
  });
});

test('explicit-ID page mode max 100 is unchanged', async () => {
  const app = createApp({ count: 10 });
  await withServer(app, async () => {
    const over = await request(app, '/api/iocs/bulk/expire', {
      body: { ioc_ids: Array.from({ length: 101 }, (_, i) => i + 1), reason: 'too many' },
      user: ADMIN
    });
    assert.equal(over.status, 400);
    assert.match(String(over.data.message), /100/);
  });
});

const DS_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

test('Deep Search query-wide bulk uses stored query and match_count, not 2,000 or client IDs', async () => {
  const resolve = async () => ({
    ok: true,
    originalQuery: 'ioc contains "a"',
    normalizedQuery: 'ioc contains "a"',
    ast: {},
    whereSql: 'TRUE',
    params: [],
    deepSearchId: DS_ID,
    matchCount: 2160030
  });
  const enqueued = [];
  const queue = {
    add: async (name, data) => {
      enqueued.push({ name, data });
      return { id: 'bull-ds-1' };
    }
  };
  const app = createApp({ count: 2000, queue, resolve });
  await withServer(app, async () => {
    const res = await request(app, '/api/iocs/bulk/query/tags', {
      body: {
        selection_mode: 'all_matching',
        deep_search_id: DS_ID,
        query: 'tag contains "tampered"',
        tag_id: 9,
        match_count: 2000,
        ioc_ids: Array.from({ length: 25 }, (_, i) => i + 1)
      },
      user: ANALYST
    });
    assert.equal(res.status, 202);
    assert.equal(res.data.mode, 'async');
    assert.equal(res.data.match_count, 2160030);
    assert.equal(res.data.query, 'ioc contains "a"');
    assert.equal(app.__executeCalls.length, 0);
    assert.equal(enqueued.length, 1);
    const audit = app.__auditCalls.find((c) => c.action === AUDIT_ACTION.IOC_BULK_QUERY_ENQUEUED);
    assert.ok(audit);
    assert.equal(audit.metadata.match_count, 2160030);
    assert.equal(audit.metadata.deep_search_id, DS_ID);
    assert.equal(audit.metadata.query, 'ioc contains "a"');
    assert.equal(app.__pool.inserts.length, 1);
    const stored = JSON.parse(app.__pool.inserts[0].params[4]);
    assert.equal(stored.deep_search_id, DS_ID);
    assert.equal(stored.expected_match_count, 2160030);
    assert.equal(Object.prototype.hasOwnProperty.call(stored, 'ioc_ids'), false);
  });
});

test('Deep Search query-wide bulk rejects stale or missing Deep Search context', async () => {
  const app = createApp({
    resolve: async () => ({
      ok: false,
      status: 409,
      code: 'DEEP_SEARCH_NOT_READY',
      message: 'Deep search results are not available for query-wide bulk'
    })
  });
  await withServer(app, async () => {
    const res = await request(app, '/api/iocs/bulk/query/tags', {
      body: { selection_mode: 'all_matching', deep_search_id: DS_ID, tag_id: 9 },
      user: ADMIN
    });
    assert.equal(res.status, 409);
    assert.equal(res.data.code, 'DEEP_SEARCH_NOT_READY');
  });
});

test('Deep Search query-wide bulk still requires triage role', async () => {
  const app = createApp({
    resolve: async () => ({ ok: true, normalizedQuery: 'ioc contains "a"', matchCount: 40, deepSearchId: DS_ID })
  });
  await withServer(app, async () => {
    const res = await request(app, '/api/iocs/bulk/query/tags', {
      body: { selection_mode: 'all_matching', deep_search_id: DS_ID, tag_id: 9 },
      user: READONLY
    });
    assert.equal(res.status, 403);
  });
});
