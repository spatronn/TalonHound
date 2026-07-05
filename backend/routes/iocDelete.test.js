import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIocDeleteRoute } from './iocDelete.js';

const ADMIN_USER = { role: 'admin', publicId: 'aaaa-admin', username: 'adminuser' };
const ANALYST_USER = { role: 'analyst', publicId: 'bbbb-analyst', username: 'analyst1' };
const READONLY_USER = { role: 'readonly', publicId: 'cccc-ro', username: 'rouser' };

const IOC_PUBLIC_ID = '11111111-2222-3333-4444-555555555555';
const IOC_ROW = {
  id: 42,
  public_id: IOC_PUBLIC_ID,
  observable: '31.76.32.249',
  observable_type: 'ip',
  ioc_source_id: 7,
  match_event_count: '0',
  manual_membership_count: '1'
};

function createMockPool(state) {
  return {
    async query(sql, params = []) {
      state.queries.push({ sql, params });
      if (typeof state.handler === 'function') return state.handler(sql, params, state);
      return { rows: [], rowCount: 0 };
    }
  };
}

function makeSuccessHandler() {
  return (sql) => {
    if (sql.includes('FROM ioc_items')) return { rows: [IOC_ROW], rowCount: 1 };
    return { rows: [], rowCount: 0 };
  };
}

function createApp(pool, auditCalls, opts = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user']
      ? JSON.parse(String(req.headers['x-test-user']))
      : ADMIN_USER;
    next();
  });
  registerIocDeleteRoute(app, pool, {
    auditSuccess: async (payload) => { auditCalls.push(payload); }
  }, {
    invalidateDetailsCache: opts.invalidateDetailsCache || (() => {})
  });
  return app;
}

async function request(app, method, path, { body, user } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(testFn, opts = {}) {
  const auditCalls = [];
  const state = { queries: [], handler: null };
  const pool = createMockPool(state);
  const app = createApp(pool, auditCalls, opts);
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await testFn({ app, pool, state, auditCalls });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// ---------------------------------------------------------------------------
// Confirmation text variants
// ---------------------------------------------------------------------------

test('admin with lowercase "delete" confirmation deletes IOC and returns ok', async () => {
  await withServer(async ({ app, state, auditCalls }) => {
    state.handler = makeSuccessHandler();
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'delete' },
      user: ADMIN_USER
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.ok, true);
    assert.equal(res.data.deleted_public_id, IOC_PUBLIC_ID);
    assert.equal(auditCalls.length, 1);
  });
});

test('admin with uppercase "DELETE" confirmation is accepted (case-insensitive)', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = makeSuccessHandler();
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'DELETE' },
      user: ADMIN_USER
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.ok, true);
  });
});

test('admin with mixed-case "Delete" confirmation is accepted', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = makeSuccessHandler();
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'Delete' },
      user: ADMIN_USER
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.ok, true);
  });
});

test('admin with padded " delete " confirmation is accepted (whitespace trimmed)', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = makeSuccessHandler();
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: ' delete ' },
      user: ADMIN_USER
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.ok, true);
  });
});

// ---------------------------------------------------------------------------
// Invalid confirmation
// ---------------------------------------------------------------------------

test('wrong confirmation text returns 400', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'yes' },
      user: ADMIN_USER
    });
    assert.equal(res.status, 400);
    assert.match(res.data.message, /Confirmation text is invalid/);
  });
});

test('missing confirmation returns 400', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: {},
      user: ADMIN_USER
    });
    assert.equal(res.status, 400);
    assert.match(res.data.message, /Confirmation text is invalid/);
  });
});

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

test('readonly user receives 403 Forbidden', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'delete' },
      user: READONLY_USER
    });
    assert.equal(res.status, 403);
  });
});

test('analyst (non-admin) user receives 403 Forbidden', async () => {
  await withServer(async ({ app }) => {
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'delete' },
      user: ANALYST_USER
    });
    assert.equal(res.status, 403);
  });
});

// ---------------------------------------------------------------------------
// IOC not found
// ---------------------------------------------------------------------------

test('returns 404 when IOC public_id does not exist', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = (sql) => {
      if (sql.includes('FROM ioc_items')) return { rows: [], rowCount: 0 };
      return { rows: [], rowCount: 0 };
    };
    const res = await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'delete' },
      user: ADMIN_USER
    });
    assert.equal(res.status, 404);
    assert.match(res.data.message, /not found/i);
  });
});

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

test('successful delete records audit log with correct action and entity', async () => {
  await withServer(async ({ app, state, auditCalls }) => {
    state.handler = makeSuccessHandler();
    await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'delete' },
      user: ADMIN_USER
    });
    assert.equal(auditCalls.length, 1);
    assert.equal(auditCalls[0].action, 'ioc.deleted');
    assert.equal(auditCalls[0].entityType, 'ioc');
    assert.equal(auditCalls[0].entityId, IOC_PUBLIC_ID);
    assert.equal(auditCalls[0].metadata.ioc_value, '31.76.32.249');
    assert.equal(auditCalls[0].metadata.delete_mode, 'hard_delete');
  });
});

// ---------------------------------------------------------------------------
// Explicit deletes of non-CASCADE tables
// ---------------------------------------------------------------------------

test('deletes ioc_enrichments and ioc_manual_source_memberships before ioc_items', async () => {
  await withServer(async ({ app, state }) => {
    state.handler = makeSuccessHandler();
    await request(app, 'DELETE', `/api/ioc/${IOC_PUBLIC_ID}`, {
      body: { confirmation: 'delete' },
      user: ADMIN_USER
    });
    const deletedTables = state.queries
      .filter((q) => q.sql.trimStart().toUpperCase().startsWith('DELETE'))
      .map((q) => q.sql);
    assert.ok(
      deletedTables.some((s) => s.includes('ioc_enrichments')),
      'must DELETE FROM ioc_enrichments'
    );
    assert.ok(
      deletedTables.some((s) => s.includes('ioc_manual_source_memberships')),
      'must DELETE FROM ioc_manual_source_memberships'
    );
    assert.ok(
      deletedTables.some((s) => s.includes('ioc_items')),
      'must DELETE FROM ioc_items'
    );
    // ioc_enrichments and ioc_manual_source_memberships must come before ioc_items
    const enrichIdx = deletedTables.findIndex((s) => s.includes('ioc_enrichments'));
    const manualIdx = deletedTables.findIndex((s) => s.includes('ioc_manual_source_memberships'));
    const itemsIdx = deletedTables.findIndex((s) => s.includes('ioc_items'));
    assert.ok(enrichIdx < itemsIdx, 'ioc_enrichments must be deleted before ioc_items');
    assert.ok(manualIdx < itemsIdx, 'ioc_manual_source_memberships must be deleted before ioc_items');
  });
});
