import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerThreatClassificationRoutes } from './threatClassifications.js';
import { AUDIT_ACTION } from '../lib/auditConstants.js';
import { invalidateThreatClassificationRegistry } from '../lib/threatClassification.js';

const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com', username: 'admin@example.com' };
const ANALYST = { role: 'analyst', id: 2, email: 'analyst@example.com', username: 'analyst@example.com' };

const UNKNOWN_ID = '00000000-0000-4000-8000-000000000001';
const MALWARE_ID = '00000000-0000-4000-8000-000000000002';
const PHISHING_ID = '00000000-0000-4000-8000-000000000003';
const UNUSED_ID = '00000000-0000-4000-8000-000000000004';

function seedRows() {
  return [
    {
      id: UNKNOWN_ID,
      name: 'Unknown',
      slug: 'unknown',
      description: null,
      active: true,
      sort_order: 0,
      system_default: true,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
      created_by: null,
      updated_by: null
    },
    {
      id: MALWARE_ID,
      name: 'Malware',
      slug: 'malware',
      description: null,
      active: true,
      sort_order: 10,
      system_default: true,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
      created_by: null,
      updated_by: null
    },
    {
      id: PHISHING_ID,
      name: 'Phishing',
      slug: 'phishing',
      description: null,
      active: true,
      sort_order: 20,
      system_default: true,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
      created_by: null,
      updated_by: null
    },
    {
      id: UNUSED_ID,
      name: 'Unused',
      slug: 'unused',
      description: null,
      active: false,
      sort_order: 30,
      system_default: false,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
      created_by: null,
      updated_by: null
    }
  ];
}

function createMockPool(store, { failOnUpdate = false } = {}) {
  const listSql = (s) => s.includes('FROM threat_classifications') && s.includes('ORDER BY');
  const byIdSql = (s) => s.includes('WHERE id = $1::uuid') && !s.includes('UPDATE');

  async function query(sql, params = []) {
    const s = String(sql);

    if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') {
      return { rows: [], rowCount: 0 };
    }

    if (listSql(s) && s.includes('SELECT *')) {
      return { rows: store.map((r) => ({ ...r })), rowCount: store.length };
    }

    if (byIdSql(s) && s.trimStart().startsWith('SELECT')) {
      const row = store.find((r) => r.id === params[0]);
      return { rows: row ? [{ ...row }] : [], rowCount: row ? 1 : 0 };
    }

    if (s.includes('UPDATE threat_classifications AS tc') && s.includes('UNNEST')) {
      if (failOnUpdate) throw new Error('simulated update failure');
      const ids = params[0];
      const orders = params[1];
      const actor = params[2];
      for (let i = 0; i < ids.length; i++) {
        const row = store.find((r) => r.id === ids[i]);
        if (row) {
          row.sort_order = orders[i];
          row.updated_by = actor;
          row.updated_at = new Date().toISOString();
        }
      }
      return { rows: [], rowCount: ids.length };
    }

    if (s.includes('SELECT slug, name, active, system_default, sort_order') && s.includes('ORDER BY sort_order')) {
      const rows = [...store]
        .sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name))
        .map((r) => ({
          slug: r.slug,
          name: r.name,
          active: r.active,
          system_default: r.system_default,
          sort_order: r.sort_order
        }));
      return { rows, rowCount: rows.length };
    }

    throw new Error('unexpected SQL: ' + s.slice(0, 120));
  }

  return {
    query,
    async connect() {
      return {
        query,
        release() {}
      };
    }
  };
}

function makeApp(store, getUser, auditEvents, poolOpts) {
  invalidateThreatClassificationRegistry();
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = getUser();
    req.authVia = 'cookie';
    next();
  });
  const audit = { auditSuccess: (e) => { auditEvents?.push(e); } };
  registerThreatClassificationRoutes(app, createMockPool(store, poolOpts), audit);
  return app;
}

async function req(app, method, path, body) {
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: body ? { 'content-type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = text;
    }
    return { status: res.status, json };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('admin reorder succeeds with deterministic orders and audit metadata', async () => {
  const store = seedRows();
  const auditEvents = [];
  const app = makeApp(store, () => ADMIN, auditEvents);
  const res = await req(app, 'POST', '/api/admin/threat-classifications/reorder', {
    ordered_ids: [UNKNOWN_ID, PHISHING_ID, MALWARE_ID, UNUSED_ID]
  });
  assert.equal(res.status, 200);
  assert.equal(res.json.success, true);
  assert.deepEqual(
    store.map((r) => [r.slug, r.sort_order]),
    [
      ['unknown', 0],
      ['malware', 20],
      ['phishing', 10],
      ['unused', 30]
    ]
  );
  assert.equal(auditEvents.length, 1);
  assert.equal(auditEvents[0].action, AUDIT_ACTION.THREAT_CLASSIFICATION_REORDERED);
  assert.deepEqual(auditEvents[0].metadata.after_order.map((x) => x.sort_order), [0, 10, 20, 30]);
  assert.ok(Array.isArray(auditEvents[0].metadata.before_order));
});

test('reorder keeps Unknown first even when client sends it later', async () => {
  const store = seedRows();
  const app = makeApp(store, () => ADMIN, []);
  const res = await req(app, 'POST', '/api/admin/threat-classifications/reorder', {
    ordered_ids: [PHISHING_ID, MALWARE_ID, UNKNOWN_ID, UNUSED_ID]
  });
  assert.equal(res.status, 200);
  assert.equal(store.find((r) => r.slug === 'unknown').sort_order, 0);
  assert.equal(store.find((r) => r.slug === 'phishing').sort_order, 10);
  assert.equal(store.find((r) => r.slug === 'malware').sort_order, 20);
});

test('reorder rejects duplicate and missing ids', async () => {
  const store = seedRows();
  const app = makeApp(store, () => ADMIN, []);
  const dup = await req(app, 'POST', '/api/admin/threat-classifications/reorder', {
    ordered_ids: [UNKNOWN_ID, MALWARE_ID, MALWARE_ID, PHISHING_ID, UNUSED_ID]
  });
  assert.equal(dup.status, 400);
  assert.match(dup.json.error, /duplicate/i);

  const missing = await req(app, 'POST', '/api/admin/threat-classifications/reorder', {
    ordered_ids: [UNKNOWN_ID, MALWARE_ID]
  });
  assert.equal(missing.status, 400);
  assert.match(missing.json.error, /every classification/i);
});

test('reorder rejects non-admin users', async () => {
  const store = seedRows();
  const app = makeApp(store, () => ANALYST, []);
  const res = await req(app, 'POST', '/api/admin/threat-classifications/reorder', {
    ordered_ids: [UNKNOWN_ID, PHISHING_ID, MALWARE_ID, UNUSED_ID]
  });
  assert.equal(res.status, 403);
  assert.equal(store.find((r) => r.slug === 'malware').sort_order, 10);
});

test('reorder rolls back store updates when write fails', async () => {
  const store = seedRows();
  const before = store.map((r) => r.sort_order);
  const app = makeApp(store, () => ADMIN, [], { failOnUpdate: true });
  const res = await req(app, 'POST', '/api/admin/threat-classifications/reorder', {
    ordered_ids: [UNKNOWN_ID, PHISHING_ID, MALWARE_ID, UNUSED_ID]
  });
  assert.equal(res.status, 500);
  assert.deepEqual(store.map((r) => r.sort_order), before);
});
