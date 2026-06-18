import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { requireRole, ROLES, rbacHttpPolicy } from '../lib/rbac.js';
import { registerAnalystIntelligenceRoutes } from './analystIntelligence.js';

function createMockPool(state) {
  return {
    async query(sql, params = []) {
      state.queries.push({ sql, params });
      if (typeof state.handler === 'function') return state.handler(sql, params, state);
      return { rows: [], rowCount: 0 };
    }
  };
}

function createApp(pool, auditCalls) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user']
      ? JSON.parse(String(req.headers['x-test-user']))
      : { role: 'analyst', publicId: '11111111-1111-1111-1111-111111111111', username: 'analyst1' };
    next();
  });
  app.use(rbacHttpPolicy);
  registerAnalystIntelligenceRoutes(app, pool, {
    auditSuccess: async (payload) => { auditCalls.push(payload); }
  });
  return app;
}

async function request(app, method, path, { body, user } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(testFn) {
  const auditCalls = [];
  const state = { queries: [], handler: null };
  const pool = createMockPool(state);
  const app = createApp(pool, auditCalls);
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await testFn({ app, pool, state, auditCalls });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('GET empty list returns []', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = (sql) => {
      if (sql.includes('FROM ioc_items')) {
        return { rows: [{ id: 42, public_id: 'abc', observable: '1.2.3.4', observable_type: 'ip' }], rowCount: 1 };
      }
      if (sql.includes('FROM ioc_analyst_intelligence')) {
        return { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    };
    const res = await request(app, 'GET', '/api/ioc/42/analyst-intelligence');
    assert.equal(res.status, 200);
    assert.deepEqual(res.data.items, []);
    assert.equal(res.data.summary.total_count, 0);
  });
});

test('readonly create returns 403', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, 'POST', '/api/ioc/42/analyst-intelligence', {
      user: { role: 'readonly', username: 'ro' },
      body: { title: 'Test' }
    });
    assert.equal(res.status, 403);
  });
});

test('invalid URL returns 400', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = (sql) => {
      if (sql.includes('FROM ioc_items')) {
        return { rows: [{ id: 42, public_id: 'abc', observable: '1.2.3.4', observable_type: 'ip' }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    };
    const res = await request(app, 'POST', '/api/ioc/42/analyst-intelligence', {
      body: { title: 'Bad URL', url: 'ftp://bad' }
    });
    assert.equal(res.status, 400);
  });
});

test('IOC not found returns 404', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    const res = await request(app, 'GET', '/api/ioc/99/analyst-intelligence');
    assert.equal(res.status, 404);
  });
});

test('analyst create writes audit log', async () => {
  await withServer(async ({ app, state, auditCalls }) => {
    state.handler = (sql) => {
      if (sql.includes('FROM ioc_items')) {
        return { rows: [{ id: 42, public_id: 'abc', observable: '1.2.3.4', observable_type: 'ip' }], rowCount: 1 };
      }
      if (sql.startsWith('INSERT INTO ioc_analyst_intelligence')) {
        return {
          rows: [{
            id: '22222222-2222-2222-2222-222222222222',
            ioc_id: 42,
            title: 'Vendor report',
            url: 'https://example.com/report',
            source_name: 'VendorX',
            reference_type: 'vendor_report',
            tlp: 'clear',
            confidence: 'high',
            assessment_impact: 'supports_malicious',
            note: null,
            created_by: '11111111-1111-1111-1111-111111111111',
            created_by_username: 'analyst1',
            created_at: new Date().toISOString(),
            updated_by: null,
            updated_by_username: null,
            updated_at: null
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    };
    const res = await request(app, 'POST', '/api/ioc/42/analyst-intelligence', {
      body: {
        title: 'Vendor report',
        url: 'https://example.com/report',
        source_name: 'VendorX',
        reference_type: 'vendor_report',
        confidence: 'high',
        assessment_impact: 'supports_malicious'
      }
    });
    assert.equal(res.status, 201);
    assert.equal(auditCalls.length, 1);
    assert.equal(auditCalls[0].action, 'ioc.analyst_intelligence.created');
  });
});

test('invalid reference id returns 400 on update', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, 'PUT', '/api/ioc/42/analyst-intelligence/not-a-uuid', {
      body: { title: 'Test', reference_type: 'other', tlp: 'clear', confidence: 'unknown', assessment_impact: 'context_only' }
    });
    assert.equal(res.status, 400);
  });
});

test('invalid enum returns 400', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = (sql) => {
      if (sql.includes('FROM ioc_items')) {
        return { rows: [{ id: 42, public_id: 'abc', observable: '1.2.3.4', observable_type: 'ip' }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    };
    const res = await request(app, 'POST', '/api/ioc/42/analyst-intelligence', {
      body: { title: 'Bad enum', assessment_impact: 'totally_bad' }
    });
    assert.equal(res.status, 400);
  });
});

test('delete soft-deletes and writes audit log', async () => {
  await withServer(async ({ app, state, auditCalls }) => {
    state.handler = (sql) => {
      if (sql.includes('FROM ioc_items')) {
        return { rows: [{ id: 42, public_id: 'abc', observable: '1.2.3.4', observable_type: 'ip' }], rowCount: 1 };
      }
      if (sql.includes('FROM ioc_analyst_intelligence') && sql.includes('SELECT')) {
        return {
          rows: [{
            id: '22222222-2222-2222-2222-222222222222',
            ioc_id: 42,
            title: 'To delete',
            url: null,
            source_name: null,
            reference_type: 'other',
            tlp: 'clear',
            confidence: 'unknown',
            assessment_impact: 'context_only',
            note: null
          }],
          rowCount: 1
        };
      }
      if (sql.includes('UPDATE ioc_analyst_intelligence') && sql.includes('deleted_at')) {
        return { rows: [], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    };
    const res = await request(app, 'DELETE', '/api/ioc/42/analyst-intelligence/22222222-2222-2222-2222-222222222222');
    assert.equal(res.status, 204);
    assert.equal(auditCalls.length, 1);
    assert.equal(auditCalls[0].action, 'ioc.analyst_intelligence.deleted');
  });
});

test('requireRole rejects readonly for write routes', () => {
  const handler = requireRole(ROLES.ADMIN, ROLES.ANALYST);
  const req = { user: { role: 'readonly' }, authVia: 'session' };
  let blocked = false;
  handler(req, { status: () => ({ json: () => { blocked = true; } }) }, () => {});
  assert.equal(blocked, true);
});
