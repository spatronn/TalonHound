import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerAuditLogRoutes } from './auditLogs.js';
import { decodeAuditCursor, DEFAULT_AUDIT_LIMIT } from '../lib/auditLogQuery.js';

const ADMIN_USER = { role: 'admin', publicId: 'aaaa-admin', username: 'adminuser' };
const ANALYST_USER = { role: 'analyst', publicId: 'bbbb-analyst', username: 'analyst1' };
const READONLY_USER = { role: 'readonly', publicId: 'cccc-ro', username: 'rouser' };

// Build a descending run of audit rows: created_at descends, id descends.
function makeRows(count, { baseId = 1000, baseTime = Date.parse('2026-08-08T12:00:00.000Z') } = {}) {
  const rows = [];
  for (let n = 0; n < count; n += 1) {
    rows.push({
      id: baseId - n,
      created_at: new Date(baseTime - n * 1000),
      actor_user_id: null,
      actor_username: 'someone',
      action: 'ioc.created',
      entity_type: 'ioc',
      entity_id: String(baseId - n),
      severity: 'info',
      status: 'success'
    });
  }
  return rows;
}

function createMockPool(state) {
  return {
    async query(sql, params = []) {
      state.queries.push({ sql, params });
      if (typeof state.handler === 'function') return state.handler(sql, params, state);
      return { rows: [], rowCount: 0 };
    }
  };
}

function createApp(pool, opts = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    if (opts.authVia) req.authVia = opts.authVia;
    req.user = req.headers['x-test-user']
      ? JSON.parse(String(req.headers['x-test-user']))
      : ADMIN_USER;
    next();
  });
  registerAuditLogRoutes(app, pool);
  return app;
}

async function request(app, path, { user } = {}) {
  const headers = {};
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${path}`, { method: 'GET', headers });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(testFn, opts = {}) {
  const state = { queries: [], handler: null };
  const pool = createMockPool(state);
  const app = createApp(pool, opts);
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await testFn({ app, pool, state });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function listQuery(state) {
  return state.queries.find((q) => /FROM audit_logs/.test(q.sql) && /ORDER BY/.test(q.sql));
}

// ---------------------------------------------------------------------------
// Default range = Last 24 hours, enforced server-side
// ---------------------------------------------------------------------------

test('default request is constrained to Last 24 hours', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: makeRows(3), rowCount: 3 });
    const before = Date.now();
    const res = await request(app, '/api/audit-logs');
    const after = Date.now();

    assert.equal(res.status, 200);
    const q = listQuery(state);
    // Lower bound present as first param and ~24h before now.
    assert.match(q.sql, /created_at >= \$1::timestamptz/);
    const fromMs = Date.parse(q.params[0]);
    const dayMs = 24 * 60 * 60 * 1000;
    assert.ok(fromMs >= before - dayMs - 5000 && fromMs <= after - dayMs + 5000,
      'lower bound must be ~24h before now');
    // Response echoes the enforced window.
    assert.ok(res.data.range.from);
    assert.equal(res.data.range.to, null);
    assert.equal(res.data.limit, DEFAULT_AUDIT_LIMIT);
  });
});

test('missing range never issues an unbounded query (always a created_at lower bound)', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    await request(app, '/api/audit-logs');
    const q = listQuery(state);
    assert.match(q.sql, /created_at >= /);
  });
});

// ---------------------------------------------------------------------------
// No global COUNT(*)
// ---------------------------------------------------------------------------

test('no global/full-history COUNT(*) is executed on a normal request', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: makeRows(3), rowCount: 3 });
    await request(app, '/api/audit-logs');
    assert.ok(!state.queries.some((q) => /COUNT\(/i.test(q.sql)), 'must not run COUNT(*)');
  });
});

// ---------------------------------------------------------------------------
// Custom range + validation
// ---------------------------------------------------------------------------

test('custom from/to range is passed through as bounds', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    const res = await request(app, '/api/audit-logs?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z');
    assert.equal(res.status, 200);
    const q = listQuery(state);
    assert.equal(Date.parse(q.params[0]), Date.parse('2026-01-01T00:00:00Z'));
    assert.equal(Date.parse(q.params[1]), Date.parse('2026-02-01T00:00:00Z'));
    assert.match(q.sql, /created_at <= \$2::timestamptz/);
    assert.equal(Date.parse(res.data.range.to), Date.parse('2026-02-01T00:00:00Z'));
  });
});

test('invalid date is rejected with 400 (not silently substituted)', async () => {
  await withServer(async ({ app, state }) => {
    const res = await request(app, '/api/audit-logs?from=not-a-date');
    assert.equal(res.status, 400);
    assert.ok(!listQuery(state), 'no list query should run');
  });
});

test('from >= to is rejected with 400', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, '/api/audit-logs?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z');
    assert.equal(res.status, 400);
    assert.match(res.data.message, /must be before/i);
  });
});

test('legacy date_from/date_to aliases still work', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    const res = await request(app, '/api/audit-logs?date_from=2026-01-01T00:00:00Z&date_to=2026-02-01T00:00:00Z');
    assert.equal(res.status, 200);
    const q = listQuery(state);
    assert.equal(Date.parse(q.params[0]), Date.parse('2026-01-01T00:00:00Z'));
  });
});

// ---------------------------------------------------------------------------
// Limit enforcement + has_more via LIMIT+1
// ---------------------------------------------------------------------------

test('limit is enforced and query uses LIMIT+1 to detect more', async () => {
  await withServer(async ({ app, state }) => {
    // Return limit+1 rows so has_more is true.
    state.handler = (sql, params) => {
      const fetchLimit = params[params.length - 1];
      return { rows: makeRows(fetchLimit), rowCount: fetchLimit };
    };
    const res = await request(app, '/api/audit-logs?limit=10');
    assert.equal(res.status, 200);
    assert.equal(res.data.items.length, 10, 'extra probe row is trimmed');
    assert.equal(res.data.has_more, true);
    assert.ok(res.data.next_cursor, 'next_cursor present when has_more');
    const q = listQuery(state);
    assert.equal(q.params[q.params.length - 1], 11, 'LIMIT param is limit+1');
  });
});

test('limit is clamped to max 100', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    const res = await request(app, '/api/audit-logs?limit=99999');
    assert.equal(res.data.limit, 100);
    const q = listQuery(state);
    assert.equal(q.params[q.params.length - 1], 101);
  });
});

test('has_more is false and next_cursor null on final page', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: makeRows(3), rowCount: 3 }); // fewer than limit
    const res = await request(app, '/api/audit-logs?limit=50');
    assert.equal(res.data.has_more, false);
    assert.equal(res.data.next_cursor, null);
    assert.equal(res.data.items.length, 3);
  });
});

// ---------------------------------------------------------------------------
// Deterministic ordering + keyset cursor
// ---------------------------------------------------------------------------

test('ordering is created_at DESC, id DESC (stable tie-breaker)', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: makeRows(2), rowCount: 2 });
    await request(app, '/api/audit-logs');
    const q = listQuery(state);
    assert.match(q.sql, /ORDER BY created_at DESC, id DESC/);
  });
});

test('cursor pagination returns deterministic non-overlapping pages', async () => {
  await withServer(async ({ app, state }) => {
    // Page 1: probe returns 11 rows for limit=10.
    state.handler = (sql, params) => {
      const fetchLimit = params[params.length - 1];
      return { rows: makeRows(fetchLimit), rowCount: fetchLimit };
    };
    const page1 = await request(app, '/api/audit-logs?limit=10');
    const lastOfPage1 = page1.data.items[page1.data.items.length - 1];
    const cursor = page1.data.next_cursor;
    assert.ok(cursor);
    const decoded = decodeAuditCursor(cursor);
    assert.equal(decoded.id, String(lastOfPage1.id));

    // Page 2: cursor must add a strict row-value keyset predicate.
    state.queries.length = 0;
    state.handler = (sql, params) => {
      const fetchLimit = params[params.length - 1];
      // Continue the descending run below page 1's last id.
      return { rows: makeRows(fetchLimit, { baseId: lastOfPage1.id - 1, baseTime: Date.parse(lastOfPage1.created_at) - 1000 }), rowCount: fetchLimit };
    };
    const page2 = await request(app, `/api/audit-logs?limit=10&cursor=${encodeURIComponent(cursor)}`);
    assert.equal(page2.status, 200);
    const q2 = listQuery(state);
    assert.match(q2.sql, /\(created_at, id\) < \(\$\d+::timestamptz, \$\d+::bigint\)/);

    // No overlap between page 1 and page 2 ids.
    const ids1 = new Set(page1.data.items.map((r) => r.id));
    const overlap = page2.data.items.some((r) => ids1.has(r.id));
    assert.ok(!overlap, 'pages must not overlap');
  });
});

test('cursor params are bound (not interpolated) and reject SQL injection', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    const res = await request(app, '/api/audit-logs?cursor=%27%3B%20DROP%20TABLE%20audit_logs%3B--');
    assert.equal(res.status, 400, 'malformed cursor rejected before any query');
    assert.ok(!listQuery(state));
  });
});

// ---------------------------------------------------------------------------
// Filters combine with time range
// ---------------------------------------------------------------------------

test('filters are ANDed with the time range', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    await request(app, '/api/audit-logs?action=ioc.deleted&severity=critical&status=failed&entity_type=ioc');
    const q = listQuery(state);
    assert.match(q.sql, /created_at >= /);
    assert.match(q.sql, /action = \$/);
    assert.match(q.sql, /severity = \$/);
    assert.match(q.sql, /status = \$/);
    assert.match(q.sql, /entity_type = \$/);
    assert.ok(q.params.includes('ioc.deleted'));
    assert.ok(q.params.includes('critical'));
  });
});

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

test('analyst may read audit logs', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    const res = await request(app, '/api/audit-logs', { user: ANALYST_USER });
    assert.equal(res.status, 200);
  });
});

test('readonly user receives 403', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, '/api/audit-logs', { user: READONLY_USER });
    assert.equal(res.status, 403);
  });
});

test('ingest-authenticated caller receives 403', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, '/api/audit-logs', { user: ADMIN_USER });
    assert.equal(res.status, 200);
  }, {});

  await withServer(async ({ app }) => {
    const res = await request(app, '/api/audit-logs', { user: ADMIN_USER });
    assert.equal(res.status, 403);
  }, { authVia: 'ingest' });
});
