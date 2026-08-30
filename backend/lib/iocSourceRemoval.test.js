import test from 'node:test';
import assert from 'node:assert/strict';
import { removeIocManualSource, isManualRemovableSource } from './iocSourceRemoval.js';

const OBSERVABLE = 'groeschelcompany.com';
const OBS_TYPE = 'domain';
const PUBLIC_ID = '11111111-1111-4111-8111-111111111111';
const FEED_PUBLIC_ID = '22222222-2222-4222-8222-222222222222';
const SECOND_MANUAL_PUBLIC_ID = '33333333-3333-4333-8333-333333333333';

const MANUAL_SOURCE = { id: 7, name: 'Threat-Hunting', source_type: 'manual' };

function auditCollector() {
  const events = [];
  return {
    events,
    auditSuccess: async (e) => { events.push(e); },
    auditLog: async (e) => { events.push({ ...e, __log: true }); }
  };
}

/**
 * Build a fake pg pool/client.
 * @param {{
 *   seed?: object|null,
 *   source?: object|null,
 *   target?: object|null,       // active manual membership row (or non-active)
 *   history?: boolean,          // whether a 'removed' history row exists
 *   survivor?: object|null,     // surviving sibling after delete
 *   recomputeRow?: object|null, // ioc_items row recompute fetches for survivor
 *   memberships?: Array<object>,// feed memberships for recompute non-override branch
 *   throwOnDelete?: boolean
 * }} cfg
 */
function makePool(cfg = {}) {
  const {
    seed = { observable: OBSERVABLE, observable_type: OBS_TYPE },
    source = MANUAL_SOURCE,
    target = null,
    history = false,
    survivor = null,
    recomputeRow = null,
    memberships = [],
    throwOnDelete = false
  } = cfg;

  const calls = [];
  const run = async (sql, params = []) => {
    const norm = String(sql).replace(/\s+/g, ' ').trim();
    calls.push({ sql: norm, params: [...params] });

    if (norm.startsWith('BEGIN') || norm.startsWith('COMMIT') || norm.startsWith('ROLLBACK')) {
      return { rows: [] };
    }
    if (norm.includes('FROM ioc_items WHERE public_id = $1::uuid LIMIT 1')) {
      return { rows: seed ? [seed] : [] };
    }
    if (norm.includes('SELECT id, name, source_type FROM ioc_sources WHERE id = $1')) {
      return { rows: source ? [source] : [] };
    }
    if (norm.includes('FROM ioc_items') && norm.includes('ioc_source_id = $3') && norm.includes('FOR UPDATE')) {
      return { rows: target ? [target] : [] };
    }
    if (norm.includes('FROM ioc_manual_source_memberships') && norm.includes("status = 'removed'")) {
      return { rows: history ? [{ '?column?': 1 }] : [] };
    }
    if (norm.includes('INSERT INTO ioc_manual_source_memberships')) {
      return { rows: [] };
    }
    if (norm.includes('DELETE FROM ioc_items WHERE id = $1 AND observable_type = $2')) {
      if (throwOnDelete) throw new Error('simulated delete failure');
      return { rows: [], rowCount: 1 };
    }
    if (norm.includes('FROM ioc_items') && norm.includes('ORDER BY (ioc_source_id IS NOT NULL) DESC')) {
      return { rows: survivor ? [survivor] : [] };
    }
    // ---- recomputeIocGlobalStatus queries ----
    if (norm.includes('FROM ioc_items') && norm.includes('manual_status_override, manual_status') && norm.includes('WHERE id = $1 AND observable_type = $2')) {
      return { rows: recomputeRow ? [recomputeRow] : [] };
    }
    if (norm.includes('FROM ioc_suppressions')) {
      return { rows: [] };
    }
    if (norm.includes('FROM ioc_feed_memberships m') && norm.includes('m.status, m.purged_at')) {
      return { rows: memberships };
    }
    if (norm.includes('MIN(m.expires_at)')) {
      return { rows: [{ min_exp: null }] };
    }
    if (norm.startsWith('UPDATE ioc_items')) {
      return { rows: [], rowCount: 1 };
    }
    throw new Error(`Unexpected query: ${norm.slice(0, 140)}`);
  };

  return {
    calls,
    query: run,
    connect: async () => ({ query: run, release: () => {} })
  };
}

test('isManualRemovableSource rejects feed and API system sources, accepts manual/custom', () => {
  assert.equal(isManualRemovableSource({ source_type: 'feed', name: 'ThreatFox' }), false);
  assert.equal(isManualRemovableSource({ source_type: 'manual', name: 'API' }), false);
  assert.equal(isManualRemovableSource({ source_type: 'manual', name: 'Threat-Hunting' }), true);
  assert.equal(isManualRemovableSource({ source_type: 'internal_hunting', name: 'Hunt' }), true);
  assert.equal(isManualRemovableSource(null), false);
});

test('Test 1: remove sole active manual source (feed expired) → 0 active sources, recalculated, audited', async () => {
  const audit = auditCollector();
  const pool = makePool({
    target: {
      id: 100, public_id: PUBLIC_ID, observable: OBSERVABLE, observable_type: OBS_TYPE,
      source_name: 'Threat-Hunting', status: 'active', confidence: 'high',
      confidence_source: 'ioc_source_default', confidence_source_name: 'Threat-Hunting',
      manual_expires_at: null, created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z'
    },
    // survivor = the feed's ioc_items row (no manual source)
    survivor: { id: 200, public_id: FEED_PUBLIC_ID },
    recomputeRow: {
      id: 200, observable: OBSERVABLE, observable_type: OBS_TYPE, status: 'active',
      manual_status_override: false, manual_status: null, manual_expires_at: null,
      expires_at: null, expired_at: null, expiration_reason: null
    },
    memberships: [{ status: 'expired', purged_at: null }] // all feed memberships expired
  });

  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit });

  assert.equal(res.status, 200);
  assert.equal(res.body.removed, true);
  assert.equal(res.body.canonical_public_id, FEED_PUBLIC_ID);
  assert.equal(res.body.status, 'expired', 'effective status recomputed to expired (0 active sources)');

  const sqls = pool.calls.map((c) => c.sql);
  assert.ok(sqls.some((s) => s.includes('INSERT INTO ioc_manual_source_memberships')), 'history tombstone written');
  const insert = pool.calls.find((c) => c.sql.includes('INSERT INTO ioc_manual_source_memberships'));
  assert.ok(insert.sql.includes("'removed'"), 'history row status is removed');
  assert.ok(sqls.some((s) => s.includes('DELETE FROM ioc_items WHERE id = $1')), 'membership row deleted');
  assert.ok(sqls.some((s) => s.includes('COMMIT')), 'transaction committed');

  const removedEvents = audit.events.filter((e) => e.action === 'ioc.source_removed');
  assert.equal(removedEvents.length, 1, 'exactly one removal audit event');
  assert.equal(removedEvents[0].metadata.source_id, 7);
  assert.equal(removedEvents[0].metadata.source_name, 'Threat-Hunting');
  assert.equal(removedEvents[0].subjectIocValue, OBSERVABLE);
});

test('Test 2: remove one of multiple active manual sources → other stays active', async () => {
  const audit = auditCollector();
  const pool = makePool({
    target: {
      id: 101, public_id: PUBLIC_ID, observable: OBSERVABLE, observable_type: OBS_TYPE,
      source_name: 'Threat-Hunting', status: 'active', confidence: 'high',
      confidence_source: null, confidence_source_name: null, manual_expires_at: null,
      created_at: '2026-01-01T00:00:00Z', last_seen_at: null
    },
    // survivor = the OTHER manual source row (override true, active)
    survivor: { id: 102, public_id: SECOND_MANUAL_PUBLIC_ID },
    recomputeRow: {
      id: 102, observable: OBSERVABLE, observable_type: OBS_TYPE, status: 'active',
      manual_status_override: true, manual_status: 'active', manual_expires_at: null,
      expires_at: null, expired_at: null, expiration_reason: null
    }
  });

  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit });

  assert.equal(res.status, 200);
  assert.equal(res.body.canonical_public_id, SECOND_MANUAL_PUBLIC_ID);
  assert.equal(res.body.status, 'active', 'remaining manual source keeps IOC active');
  // The surviving manual row is recomputed via the override branch; no blanket
  // observable-wide status UPDATE that could clobber it.
  const sqls = pool.calls.map((c) => c.sql);
  assert.ok(!sqls.some((s) => s.includes('WHERE observable = $1 AND observable_type = $2') && s.startsWith('UPDATE ioc_items')),
    'no blanket observable status update when a manual sibling survives');
});

test('Test 3: feed-managed source cannot be removed (no state mutation)', async () => {
  const audit = auditCollector();
  const pool = makePool({ source: { id: 9, name: 'ThreatFox abuse.ch', source_type: 'feed' } });

  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 9 }, { req: {}, user: {}, audit });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'feed_source_not_removable');
  assert.ok(!pool.calls.some((c) => c.sql.startsWith('BEGIN')), 'no transaction opened');
  assert.ok(!pool.calls.some((c) => c.sql.includes('DELETE FROM ioc_items')), 'no delete');
  assert.equal(audit.events.length, 0, 'no audit event');
});

test('Test 4a: already-removed association is idempotent (409, no audit, no mutation)', async () => {
  const audit = auditCollector();
  const pool = makePool({ target: null, history: true });

  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit });

  assert.equal(res.status, 409);
  assert.equal(res.body.error, 'source_already_removed');
  assert.ok(pool.calls.some((c) => c.sql.startsWith('ROLLBACK')), 'rolled back');
  assert.ok(!pool.calls.some((c) => c.sql.includes('DELETE FROM ioc_items')), 'no delete');
  assert.equal(audit.events.filter((e) => e.action === 'ioc.source_removed').length, 0);
});

test('Test 4b: association not found → 404', async () => {
  const audit = auditCollector();
  const pool = makePool({ target: null, history: false });
  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit });
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'association_not_found');
  assert.equal(audit.events.length, 0);
});

test('Non-active association cannot be removed again (409)', async () => {
  const audit = auditCollector();
  const pool = makePool({
    target: {
      id: 103, public_id: PUBLIC_ID, observable: OBSERVABLE, observable_type: OBS_TYPE,
      source_name: 'Threat-Hunting', status: 'expired', created_at: '2026-01-01T00:00:00Z'
    }
  });
  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit });
  assert.equal(res.status, 409);
  assert.equal(res.body.error, 'association_not_active');
  assert.ok(!pool.calls.some((c) => c.sql.includes('DELETE FROM ioc_items')));
});

test('Test 8: removal does not clear an IOC-level manual override', async () => {
  const audit = auditCollector();
  const pool = makePool({
    target: {
      id: 104, public_id: PUBLIC_ID, observable: OBSERVABLE, observable_type: OBS_TYPE,
      source_name: 'Threat-Hunting', status: 'active', created_at: '2026-01-01T00:00:00Z'
    },
    survivor: { id: 105, public_id: SECOND_MANUAL_PUBLIC_ID },
    recomputeRow: {
      id: 105, observable: OBSERVABLE, observable_type: OBS_TYPE, status: 'active',
      manual_status_override: true, manual_status: 'active', manual_expires_at: null,
      expires_at: null, expired_at: null, expiration_reason: null
    }
  });
  await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit });
  const clearsOverride = pool.calls.some((c) => /manual_status_override\s*=\s*FALSE/i.test(c.sql));
  assert.equal(clearsOverride, false, 'no query clears manual_status_override');
});

test('Test 9: delete failure rolls back and emits no audit (500)', async () => {
  const audit = auditCollector();
  const pool = makePool({
    target: {
      id: 106, public_id: PUBLIC_ID, observable: OBSERVABLE, observable_type: OBS_TYPE,
      source_name: 'Threat-Hunting', status: 'active', created_at: '2026-01-01T00:00:00Z'
    },
    throwOnDelete: true
  });
  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit });
  assert.equal(res.status, 500);
  assert.ok(pool.calls.some((c) => c.sql.startsWith('ROLLBACK')), 'rolled back');
  assert.ok(!pool.calls.some((c) => c.sql.startsWith('COMMIT')), 'never committed');
  assert.equal(audit.events.filter((e) => e.action === 'ioc.source_removed').length, 0, 'no audit on failure');
});

test('IOC not found → 404', async () => {
  const pool = makePool({ seed: null });
  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 7 }, { req: {}, user: {}, audit: auditCollector() });
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'ioc_not_found');
});

test('unknown source → 404', async () => {
  const pool = makePool({ source: null });
  const res = await removeIocManualSource(pool, { publicId: PUBLIC_ID, sourceId: 999 }, { req: {}, user: {}, audit: auditCollector() });
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'source_not_found');
});

test('invalid params rejected before any query', async () => {
  const pool = makePool({});
  const res = await removeIocManualSource(pool, { publicId: '', sourceId: 7 }, {});
  assert.equal(res.status, 400);
  assert.equal(pool.calls.length, 0);
});
