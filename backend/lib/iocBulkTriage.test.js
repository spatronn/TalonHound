import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { invalidateThreatClassificationRegistry } from './threatClassification.js';
import {
  parseIocIdList,
  summarizeBulkResults,
  bulkAddTag,
  bulkAddClassification,
  bulkSuppress,
  bulkExpire,
  BULK_TRIAGE_MAX_ITEMS
} from './iocBulkTriage.js';
import { registerIocBulkTriageRoutes } from '../routes/iocBulkTriage.js';
import { AUDIT_ACTION } from './auditConstants.js';

const ADMIN = { role: 'admin', publicId: '11111111-1111-1111-1111-111111111111', username: 'admin', email: 'admin@t.local', id: 1 };
const ANALYST = { role: 'analyst', publicId: '22222222-2222-2222-2222-222222222222', username: 'analyst', email: 'analyst@t.local', id: 2 };
const READONLY = { role: 'readonly', publicId: '33333333-3333-3333-3333-333333333333', username: 'ro', email: 'ro@t.local', id: 3 };

function iocRow(id, extra = {}) {
  return {
    id,
    public_id: `pub-${id}`,
    observable: extra.observable || `10.0.0.${id}`,
    observable_type: extra.observable_type || 'ip',
    status: extra.status || 'active',
    manual_status_override: extra.manual_status_override || false,
    manual_status: extra.manual_status || null,
    manual_expires_at: extra.manual_expires_at || null
  };
}

function makePool(handlers = {}) {
  const queries = [];
  async function query(sql, params = []) {
    const norm = String(sql).replace(/\s+/g, ' ').trim();
    queries.push({ sql: norm, params: [...(params || [])] });
    for (const h of handlers.list || []) {
      if (h.match(norm, params)) return h.respond(norm, params);
    }
    if (norm.startsWith('BEGIN') || norm.startsWith('COMMIT') || norm.startsWith('ROLLBACK')) {
      return { rows: [], rowCount: 0 };
    }
    if (typeof handlers.fallback === 'function') return handlers.fallback(norm, params);
    throw new Error(`Unexpected query: ${norm.slice(0, 160)}`);
  }
  return {
    queries,
    query,
    connect: async () => ({ query, release: () => {} })
  };
}

function tagHandlers({ tag = { id: 9, name: 'malware', type: 'threat', category: 'malware' }, iocs = [], insertIds = null } = {}) {
  const inserted = new Set();
  return [
    {
      match: (sql) => sql.includes('FROM tags WHERE id'),
      respond: () => (tag ? { rows: [tag], rowCount: 1 } : { rows: [], rowCount: 0 })
    },
    {
      match: (sql) => sql.includes('FROM ioc_items') && sql.includes('id = ANY'),
      respond: (_sql, params) => {
        const want = new Set((params[0] || []).map(Number));
        const rows = iocs.filter((r) => want.has(Number(r.id)));
        return { rows, rowCount: rows.length };
      }
    },
    {
      match: (sql) => sql.includes('INSERT INTO ioc_tags'),
      respond: (_sql, params) => {
        const iocId = Number(params[0]);
        if (insertIds && !insertIds.includes(iocId)) return { rows: [], rowCount: 0 };
        if (inserted.has(iocId)) return { rows: [], rowCount: 0 };
        inserted.add(iocId);
        return { rows: [{ tag_id: 9 }], rowCount: 1 };
      }
    }
  ];
}

test('parseIocIdList rejects empty, non-array, over-max, and non-integers', () => {
  assert.equal(parseIocIdList(null).ok, false);
  assert.equal(parseIocIdList([]).ok, false);
  assert.equal(parseIocIdList([1, 0]).ok, false);
  assert.equal(parseIocIdList(['x']).ok, false);
  assert.equal(parseIocIdList(Array.from({ length: BULK_TRIAGE_MAX_ITEMS + 1 }, (_, i) => i + 1)).ok, false);
  const ok = parseIocIdList([3, 3, 1]);
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.ids, [3, 1]);
});

test('summarizeBulkResults counts ok / skipped / error', () => {
  const s = summarizeBulkResults([
    { id: 1, status: 'ok' },
    { id: 2, status: 'skipped' },
    { id: 3, status: 'error' }
  ]);
  assert.equal(s.requested, 3);
  assert.equal(s.succeeded, 1);
  assert.equal(s.skipped, 1);
  assert.equal(s.failed, 1);
});

test('bulkAddTag mixed valid/invalid IDs and repeated request is idempotent', async () => {
  const iocs = [iocRow(1), iocRow(2)];
  const pool = makePool({ list: tagHandlers({ iocs }) });
  const auditCalls = [];
  const first = await bulkAddTag(pool, {
    iocIds: [1, 2, 99],
    tagId: 9,
    user: ANALYST,
    req: {},
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  });
  assert.equal(first.ok, true);
  assert.equal(first.succeeded, 2);
  assert.equal(first.failed, 1);
  assert.equal(first.results.find((r) => r.id === 99).status, 'error');
  assert.equal(auditCalls.length, 2);
  assert.equal(auditCalls[0].action, AUDIT_ACTION.IOC_TAG_ADDED);
  assert.equal(auditCalls[0].metadata.bulk, true);

  const second = await bulkAddTag(pool, {
    iocIds: [1, 2],
    tagId: 9,
    user: ANALYST,
    req: {},
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  });
  assert.equal(second.succeeded, 0);
  assert.equal(second.skipped, 2);
  assert.equal(auditCalls.length, 2);
});

test('bulkAddTag rejects missing/disabled tag', async () => {
  const pool = makePool({ list: tagHandlers({ tag: null, iocs: [iocRow(1)] }) });
  const res = await bulkAddTag(pool, { iocIds: [1], tagId: 9, user: ADMIN });
  assert.equal(res.ok, false);
  assert.equal(res.status, 404);
});

test('bulkExpire skips already expired and audits new expires', async () => {
  const iocs = [
    iocRow(1, { status: 'active' }),
    iocRow(2, { status: 'expired' })
  ];
  const pool = makePool({
    list: [
      {
        match: (sql) => sql.includes('FROM ioc_items') && sql.includes('id = ANY'),
        respond: (_sql, params) => {
          const want = new Set((params[0] || []).map(Number));
          const rows = iocs.filter((r) => want.has(Number(r.id)));
          return { rows, rowCount: rows.length };
        }
      },
      {
        match: (sql) => sql.startsWith('UPDATE ioc_items'),
        respond: () => ({ rows: [], rowCount: 1 })
      }
    ]
  });
  const auditCalls = [];
  const recomputes = [];
  const res = await bulkExpire(pool, {
    iocIds: [1, 2, 77],
    reason: 'bulk expire smoke',
    user: ADMIN,
    req: {},
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  }, {
    recomputeIocGlobalStatus: async (_pool, id) => { recomputes.push(id); }
  });
  assert.equal(res.succeeded, 1);
  assert.equal(res.skipped, 1);
  assert.equal(res.failed, 1);
  assert.deepEqual(recomputes, [1]);
  assert.equal(auditCalls.length, 1);
  assert.equal(auditCalls[0].action, AUDIT_ACTION.IOC_EXPIRED);
  assert.equal(auditCalls[0].metadata.bulk, true);
});

test('bulkExpire rejects short reason before touching IOCs', async () => {
  const pool = makePool({ list: [] });
  const res = await bulkExpire(pool, { iocIds: [1], reason: 'no', user: ADMIN });
  assert.equal(res.ok, false);
  assert.equal(res.status, 400);
});

test('bulkSuppress skips already-suppressed IOCs', async () => {
  const iocs = [iocRow(1), iocRow(2)];
  let suppressLookups = 0;
  const pool = makePool({
    list: [
      {
        match: (sql) => sql.includes('FROM ioc_items') && sql.includes('id = ANY'),
        respond: (_sql, params) => {
          const want = new Set((params[0] || []).map(Number));
          return { rows: iocs.filter((r) => want.has(Number(r.id))), rowCount: 2 };
        }
      },
      {
        match: (sql) => sql.includes('SELECT id FROM ioc_suppressions'),
        respond: () => {
          suppressLookups += 1;
          return suppressLookups === 1
            ? { rows: [], rowCount: 0 }
            : { rows: [{ id: 1 }], rowCount: 1 };
        }
      },
      {
        match: (sql) => sql.includes('INSERT INTO ioc_suppressions'),
        respond: (_sql, params) => ({
          rows: [{
            id: 50,
            ioc_value: params[0],
            ioc_type: params[1],
            reason: params[2],
            expires_at: params[4],
            active: true
          }],
          rowCount: 1
        })
      },
      {
        match: (sql) => sql.includes('FROM ioc_items') && sql.includes('lower(observable)'),
        respond: () => ({ rows: [{ id: 1, observable_type: 'ip' }], rowCount: 1 })
      },
      {
        match: (sql) => sql.includes('FROM ioc_items') && sql.includes('observable_type = $2'),
        respond: () => ({
          rows: [{
            id: 1, observable: '10.0.0.1', observable_type: 'ip', status: 'active',
            manual_status_override: false, manual_status: null, manual_expires_at: null,
            expires_at: null, expired_at: null, expiration_reason: null
          }],
          rowCount: 1
        })
      },
      {
        match: (sql) => sql.includes('ioc_suppressions') && sql.includes('active = TRUE'),
        respond: () => ({ rows: [{ id: 1 }], rowCount: 1 })
      },
      {
        match: (sql) => sql.includes("SET status = 'suppressed'"),
        respond: () => ({ rows: [], rowCount: 1 })
      }
    ]
  });
  const auditCalls = [];
  const first = await bulkSuppress(pool, {
    iocIds: [1],
    reason: 'false positive lab',
    user: ANALYST,
    req: {},
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  });
  assert.equal(first.succeeded, 1);
  assert.equal(auditCalls.some((c) => c.action === AUDIT_ACTION.IOC_SUPPRESSION_CREATED), true);
  assert.equal(auditCalls.find((c) => c.action === AUDIT_ACTION.IOC_SUPPRESSION_CREATED).metadata.bulk, true);

  const second = await bulkSuppress(pool, {
    iocIds: [2],
    reason: 'false positive lab',
    user: ANALYST,
    req: {},
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  });
  assert.equal(second.skipped, 1);
  assert.equal(second.results[0].status, 'skipped');
});

test('bulkAddClassification adds once then skips on repeat', async () => {
  invalidateThreatClassificationRegistry();
  const iocs = [iocRow(5, { observable_type: 'domain', observable: 'evil.test' })];
  let overrideRows = [];
  const pool = makePool({
    list: [
      {
        match: (sql) => sql.includes('FROM threat_classifications'),
        respond: () => ({
          rows: [{ slug: 'malware', name: 'Malware', active: true, system_default: true, sort_order: 1 }],
          rowCount: 1
        })
      },
      {
        match: (sql) => sql.includes('FROM ioc_items') && sql.includes('id = ANY'),
        respond: () => ({ rows: iocs, rowCount: 1 })
      },
      {
        match: (sql) => sql.includes('FROM ioc_threat_classification_overrides'),
        respond: () => ({ rows: overrideRows, rowCount: overrideRows.length })
      },
      {
        match: (sql) => sql.includes('INSERT INTO ioc_threat_classification_overrides'),
        respond: (_sql, params) => {
          overrideRows = [{
            id: 'ov-1',
            ioc_id: params[0],
            ioc_observable_type: params[1],
            classification_slug: params[2],
            action: 'add',
            source_name: null
          }];
          return { rows: overrideRows, rowCount: 1 };
        }
      },
      {
        match: (sql) => sql.includes('DELETE FROM ioc_threat_classifications'),
        respond: () => ({ rows: [], rowCount: 0 })
      },
      {
        match: (sql) => sql.includes('INSERT INTO ioc_threat_classifications'),
        respond: () => ({ rows: [], rowCount: 1 })
      },
      {
        match: (sql) => sql.includes('SET threat_classification'),
        respond: () => ({ rows: [], rowCount: 1 })
      }
    ]
  });
  const auditCalls = [];
  const first = await bulkAddClassification(pool, {
    iocIds: [5],
    slug: 'malware',
    user: ANALYST,
    req: {},
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  });
  assert.equal(first.succeeded, 1);
  assert.equal(auditCalls[0].action, AUDIT_ACTION.IOC_THREAT_CLASSIFICATIONS_UPDATED);

  const second = await bulkAddClassification(pool, {
    iocIds: [5],
    slug: 'malware',
    user: ANALYST,
    req: {},
    audit: { auditSuccess: async (p) => { auditCalls.push(p); } }
  });
  assert.equal(second.skipped, 1);
});

function createApp(pool) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = req.headers['x-test-user']
      ? JSON.parse(String(req.headers['x-test-user']))
      : ADMIN;
    next();
  });
  const auditCalls = [];
  registerIocBulkTriageRoutes(app, pool, {
    auditSuccess: async (p) => { auditCalls.push(p); }
  });
  app.__auditCalls = auditCalls;
  return app;
}

async function request(app, path, { body, user } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (user) headers['x-test-user'] = JSON.stringify(user);
  const res = await fetch(`http://127.0.0.1:${app.__port}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body || {})
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function withServer(pool, fn) {
  const app = createApp(pool);
  const server = app.listen(0);
  app.__port = server.address().port;
  try {
    await fn(app);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('HTTP readonly is denied; analyst and admin can bulk tag', async () => {
  const pool = makePool({ list: tagHandlers({ iocs: [iocRow(1)] }) });
  await withServer(pool, async (app) => {
    const denied = await request(app, '/api/iocs/bulk/tags', {
      body: { ioc_ids: [1], tag_id: 9 },
      user: READONLY
    });
    assert.equal(denied.status, 403);

    const analyst = await request(app, '/api/iocs/bulk/tags', {
      body: { ioc_ids: [1], tag_id: 9 },
      user: ANALYST
    });
    assert.equal(analyst.status, 200);
    assert.equal(analyst.data.succeeded, 1);

    const admin = await request(app, '/api/iocs/bulk/tags', {
      body: { ioc_ids: [1], tag_id: 9 },
      user: ADMIN
    });
    assert.equal(admin.status, 200);
    assert.equal(admin.data.skipped, 1);
  });
});

test('HTTP batch limit and missing ioc_ids are 400', async () => {
  const pool = makePool({ list: [] });
  await withServer(pool, async (app) => {
    const empty = await request(app, '/api/iocs/bulk/expire', {
      body: { ioc_ids: [], reason: 'too many' },
      user: ADMIN
    });
    assert.equal(empty.status, 400);

    const over = await request(app, '/api/iocs/bulk/expire', {
      body: { ioc_ids: Array.from({ length: 101 }, (_, i) => i + 1), reason: 'too many' },
      user: ADMIN
    });
    assert.equal(over.status, 400);
    assert.match(String(over.data.message), /100/);

    const missing = await request(app, '/api/iocs/bulk/suppress', {
      body: { ioc_ids: [1] },
      user: ADMIN
    });
    assert.equal(missing.status, 400);
  });
});

test('HTTP mixed valid/invalid IDs returns per-item results', async () => {
  const pool = makePool({ list: tagHandlers({ iocs: [iocRow(1)] }) });
  await withServer(pool, async (app) => {
    const res = await request(app, '/api/iocs/bulk/tags', {
      body: { ioc_ids: [1, 404], tag_id: 9 },
      user: ANALYST
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.ok, false);
    assert.equal(res.data.succeeded, 1);
    assert.equal(res.data.failed, 1);
    assert.equal(res.data.results.find((r) => r.id === 404).status, 'error');
  });
});
