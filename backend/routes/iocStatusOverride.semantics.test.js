import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIocExpirationRoutes } from './iocExpiration.js';
import {
  isExplicitIocLifecycleOverride,
  isManualSourceLifecycleBookkeeping
} from '../lib/iocStatusOverrideGuards.js';

/**
 * Verification harness for the "manual source != manual override" fix.
 *
 * These tests drive the REAL status-override route (registerIocExpirationRoutes) and the
 * REAL recomputeIocGlobalStatus() through a small stateful in-memory Postgres substitute,
 * following this repo's existing route-test convention (mock pool + express). They prove the
 * persistence written by each explicit lifecycle action and how the canonical predicate
 * classifies it — no unit-only predicate stubs.
 */

const OBS = 'evil.reproduction.test';
const TYPE = 'domain';

/** Build a stateful pool holding a single observable's ioc_items rows + feed memberships. */
function makeStatefulPool({ rows, memberships = [] } = {}) {
  const store = { rows: rows.map((r) => ({ ...r })), memberships: memberships.map((m) => ({ ...m })) };
  const log = [];

  function rowById(id, type) {
    return store.rows.find((r) => Number(r.id) === Number(id) && r.observable_type === type);
  }

  async function query(sql, params = []) {
    const s = String(sql).replace(/\s+/g, ' ').trim();
    log.push({ s, params: [...(params || [])] });

    if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) {
      return { rows: [], rowCount: 0 };
    }

    // Suppression check (recompute) — never suppressed here.
    if (s.includes('FROM ioc_suppressions')) return { rows: [] };

    // --- fetchIocStatusRow / recompute row SELECT (single row by id) ---
    if (s.startsWith('SELECT') && s.includes('FROM ioc_items') && s.includes('WHERE id = $1 AND observable_type = $2')) {
      const r = rowById(params[0], params[1]);
      return { rows: r ? [{ ...r }] : [] };
    }

    // --- recompute: membership status list for the observable ---
    if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items i') && s.includes('m.status')) {
      return { rows: store.memberships.map((m) => ({ status: m.status, purged_at: m.purged_at || null })) };
    }
    // --- recompute: MIN(expires_at) across active memberships ---
    if (s.includes('MIN(m.expires_at)')) {
      const act = store.memberships.filter((m) => m.status === 'active' && !m.purged_at && m.expires_at);
      const min = act.length ? act.map((m) => m.expires_at).sort()[0] : null;
      return { rows: [{ min_exp: min }] };
    }

    // --- SET explicit override (Expire now / reactivate / custom expiry) ---
    if (s.includes('UPDATE ioc_items') && s.includes('SET manual_status_override = TRUE')) {
      const r = rowById(params[0], params[1]);
      if (r) {
        r.manual_status_override = true;
        r.manual_status = params[2];
        r.manual_expires_at = params[3];
        r.manual_override_reason = params[4];
        r.manual_override_by_user_id = params[5];
      }
      return { rowCount: r ? 1 : 0, rows: [] };
    }

    // --- CLEAR explicit override ---
    if (s.includes('UPDATE ioc_items') && s.includes('SET manual_status_override = FALSE')) {
      const r = rowById(params[0], params[1]);
      if (r) {
        r.manual_status_override = false;
        r.manual_status = null;
        r.manual_expires_at = null;
        r.manual_override_reason = params[2];
        r.manual_override_by_user_id = params[3];
      }
      return { rowCount: r ? 1 : 0, rows: [] };
    }

    // --- recompute override-branch write (single row, by id) ---
    if (s.includes('UPDATE ioc_items') && s.includes('SET status = $3, expires_at = $4, expired_at = $5, expiration_reason = $6')
        && s.includes('WHERE id = $1 AND observable_type = $2')) {
      const r = rowById(params[0], params[1]);
      if (r) {
        r.status = params[2];
        r.expires_at = params[3];
        r.expired_at = params[4];
        r.expiration_reason = params[5];
      }
      return { rowCount: r ? 1 : 0, rows: [] };
    }

    // --- recompute membership-branch write (all rows for observable) ---
    if (s.includes('UPDATE ioc_items') && s.includes('WHERE observable = $1 AND observable_type = $2')) {
      for (const r of store.rows) {
        if (r.observable === params[0] && r.observable_type === params[1]) {
          r.status = params[2];
          r.expires_at = params[3];
          r.expired_at = params[4];
          r.expiration_reason = params[5];
        }
      }
      return { rowCount: 1, rows: [] };
    }

    // Membership override-clear helper (feed membership route) — not exercised here.
    throw new Error(`Unexpected query: ${s.slice(0, 160)}`);
  }

  return {
    store,
    log,
    query,
    connect: async () => ({ query, release: () => {} })
  };
}

const auditStub = {
  auditLog: async () => {},
  auditSuccess: async () => {}
};

function makeApp(pool) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { publicId: '11111111-1111-4111-8111-111111111111', role: 'analyst' };
    next();
  });
  registerIocExpirationRoutes(app, pool, auditStub);
  return app;
}

async function patchOverride(app, id, body) {
  // Minimal supertest-free driver.
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/ioc/${id}/status-override`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
    const json = await res.json();
    return { status: res.status, json };
  } finally {
    server.close();
  }
}

function activeSourceRow(overrides = {}) {
  return {
    id: 1,
    observable: OBS,
    observable_type: TYPE,
    status: 'active',
    expires_at: null,
    expired_at: null,
    expiration_reason: null,
    manual_status_override: false,
    manual_status: null,
    manual_expires_at: null,
    manual_override_reason: null,
    manual_override_by_user_id: null,
    manual_override_at: null,
    ...overrides
  };
}

test('Set custom expiry on an existing IOC => genuine override, distinguishable from manual_custom_expire', async () => {
  // Feed IOC (active), analyst clicks "Set custom expiry" (custom_expire_ioc).
  const pool = makeStatefulPool({
    rows: [activeSourceRow()],
    memberships: [{ status: 'active', expires_at: null, purged_at: null }]
  });
  const app = makeApp(pool);

  const future = '2027-01-01T00:00:00.000Z';
  const { status, json } = await patchOverride(app, 1, {
    observable_type: TYPE,
    manual_status_override: true,
    manual_status: 'active',
    manual_expires_at: future,
    reason: 'watchlist pin per IR-9001'
  });

  assert.equal(status, 200);
  assert.equal(json.success, true);
  // Response surfaces a genuine override.
  assert.equal(json.ioc.manual_status_override, true);

  const row = pool.store.rows[0];
  // The persisted reason is the analyst's free text, NOT the source-bookkeeping sentinel.
  assert.equal(row.manual_override_reason, 'watchlist pin per IR-9001');
  assert.notEqual(row.manual_override_reason, 'manual_custom_expire');
  // Canonical predicate classifies it as an explicit override.
  assert.equal(isExplicitIocLifecycleOverride(row), true);
  assert.equal(isManualSourceLifecycleBookkeeping(row), false);
});

test('Set custom expiry rejects a reason that reuses a reserved source sentinel', async () => {
  const pool = makeStatefulPool({ rows: [activeSourceRow()] });
  const app = makeApp(pool);
  const { status, json } = await patchOverride(app, 1, {
    observable_type: TYPE,
    manual_status_override: true,
    manual_status: 'active',
    manual_expires_at: '2027-01-01T00:00:00.000Z',
    reason: 'manual_custom_expire'
  });
  assert.equal(status, 400);
  assert.match(json.error, /reserved/i);
});

test('Expire IOC now => genuine override (Manual Override = Yes)', async () => {
  const pool = makeStatefulPool({
    rows: [activeSourceRow()],
    memberships: [{ status: 'active', expires_at: null, purged_at: null }]
  });
  const app = makeApp(pool);
  const { status, json } = await patchOverride(app, 1, {
    observable_type: TYPE,
    manual_status_override: true,
    manual_status: 'expired',
    reason: 'confirmed benign, retire'
  });
  assert.equal(status, 200);
  assert.equal(json.ioc.manual_status_override, true);
  const row = pool.store.rows[0];
  assert.equal(row.status, 'expired');
  assert.equal(isExplicitIocLifecycleOverride(row), true);
});

test('Clear override on a genuine override clears the flag and recomputes source-derived state', async () => {
  // Start from a genuinely-overridden (expired) row that still has an active feed source.
  const pool = makeStatefulPool({
    rows: [activeSourceRow({
      status: 'expired',
      manual_status_override: true,
      manual_status: 'expired',
      manual_override_reason: 'confirmed benign, retire',
      expiration_reason: 'confirmed benign, retire'
    })],
    memberships: [{ status: 'active', expires_at: null, purged_at: null }]
  });
  const app = makeApp(pool);
  const { status, json } = await patchOverride(app, 1, {
    observable_type: TYPE,
    manual_status_override: false,
    reason: 'reopening'
  });
  assert.equal(status, 200);
  assert.equal(json.ioc.manual_status_override, false);
  const row = pool.store.rows[0];
  assert.equal(row.manual_status_override, false);
  // Recompute ran from sources: an active membership exists => IOC active again.
  assert.equal(row.status, 'active');
  assert.equal(isExplicitIocLifecycleOverride(row), false);
});

test('Clear override on a manual SOURCE bookkeeping row is a noop (lifecycle preserved)', async () => {
  // A manually-added source: flag TRUE for its own expiry bookkeeping, NOT an override.
  const pool = makeStatefulPool({
    rows: [activeSourceRow({
      status: 'active',
      expires_at: '2026-09-18T12:00:00.000Z',
      manual_status_override: true,
      manual_status: 'active',
      manual_expires_at: '2026-09-18T12:00:00.000Z',
      manual_override_reason: 'manual_custom_expire'
    })]
  });
  const app = makeApp(pool);
  const { status, json } = await patchOverride(app, 1, {
    observable_type: TYPE,
    manual_status_override: false,
    reason: 'oops'
  });
  assert.equal(status, 200);
  assert.equal(json.noop, true);
  assert.match(json.message, /no manual override/i);
  const row = pool.store.rows[0];
  // Untouched: the manual source keeps its bookkeeping flag and its own expiry.
  assert.equal(row.manual_status_override, true);
  assert.equal(row.manual_expires_at, '2026-09-18T12:00:00.000Z');
  assert.equal(isExplicitIocLifecycleOverride(row), false);
});
