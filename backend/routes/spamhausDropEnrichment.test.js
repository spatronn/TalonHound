import test from 'node:test';
import assert from 'node:assert/strict';
import { registerSpamhausDropEnrichmentRoutes } from './spamhausDropEnrichment.js';

// ---------------------------------------------------------------------------
// Capture route handlers without express
// ---------------------------------------------------------------------------

function captureRoutes(pool, opts = {}) {
  const routes = {};
  const app = {
    get: (path, ...handlers) => { routes[`GET:${path}`] = handlers[handlers.length - 1]; },
    post: (path, ...handlers) => { routes[`POST:${path}`] = handlers[handlers.length - 1]; },
    put: (path, ...handlers) => { routes[`PUT:${path}`] = handlers[handlers.length - 1]; }
  };
  const audit = { auditSuccess: async () => {} };
  registerSpamhausDropEnrichmentRoutes(app, pool, audit, opts);
  return routes;
}

function mockRes() {
  const res = { _code: 200, _body: null };
  res.status = (code) => { res._code = code; return res; };
  res.json = (body) => { res._body = body; return res; };
  return res;
}

function makePool(queryFn) {
  return { query: queryFn };
}

function trackPool(queryFn) {
  const calls = [];
  const pool = makePool(async (sql, params) => {
    calls.push({ sql: String(sql), params });
    return queryFn(sql, params);
  });
  return { pool, calls };
}

function usageInserts(calls) {
  return calls.filter((c) => /INSERT INTO enrichment_usage_daily/i.test(c.sql));
}

function usageCounters(call) {
  const p = call.params;
  return {
    provider: p[0],
    iocType: p[1],
    request_count: p[2],
    external_call_count: p[3],
    cache_hit_count: p[4],
    success_count: p[5],
    failure_count: p[6],
    rate_limit_count: p[7],
    total_external_response_time_ms: p[8],
    external_response_count: p[9]
  };
}

function assertLocalLookupUsage(call, { iocType = 'ip', outcome }) {
  const c = usageCounters(call);
  assert.equal(c.provider, 'spamhaus_drop');
  assert.equal(c.iocType, iocType);
  assert.equal(c.request_count, 1);
  assert.equal(c.external_call_count, 0);
  assert.equal(c.cache_hit_count, 0);
  assert.equal(c.success_count, outcome === 'success' ? 1 : 0);
  assert.equal(c.failure_count, outcome === 'failure' ? 1 : 0);
  assert.equal(c.rate_limit_count, 0);
  assert.equal(c.total_external_response_time_ms, 0);
  assert.equal(c.external_response_count, 0);
}

// ---------------------------------------------------------------------------
// Shared DB fixtures
// ---------------------------------------------------------------------------

const CONFIG_ENABLED = [{ enabled: true, timeout_ms: 30000, config: { sync_interval_hours: 24 } }];
const CONFIG_DISABLED = [{ enabled: false, timeout_ms: 30000, config: {} }];
const SYNC_STATE_HEALTHY = [
  { list_type: 'drop_v4', status: 'healthy', last_success_at: new Date('2026-07-05T10:00:00Z'), entry_count: 100 },
  { list_type: 'drop_v6', status: 'healthy', last_success_at: new Date('2026-07-05T10:00:00Z'), entry_count: 50 }
];
const SYNC_STATE_NEVER = [
  { list_type: 'drop_v4', status: 'never_synced', last_success_at: null, entry_count: 0 },
  { list_type: 'drop_v6', status: 'never_synced', last_success_at: null, entry_count: 0 }
];

function defaultQuery(sql) {
  if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
  if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
  if (sql.includes('ioc_spamhaus_drop_enrichment') && /INSERT/i.test(sql)) {
    return {
      rows: [{
        lookup_ip: '1.2.3.4',
        provider_status: 'listed',
        listed: true,
        matched_cidr: '1.2.3.0/24',
        enriched_at: new Date()
      }]
    };
  }
  if (sql.includes('ioc_spamhaus_drop_enrichment')) return { rows: [] };
  return { rows: [] };
}

// ---------------------------------------------------------------------------
// GET /api/enrichment/spamhaus-drop/ioc
// ---------------------------------------------------------------------------

test('GET ioc returns not_run when no persisted enrichment exists', async () => {
  let cidrLookupCalled = false;
  const { pool } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_entries') || sql.includes('<< cidr')) {
      cidrLookupCalled = true;
      return { rows: [] };
    }
    if (sql.includes('ioc_spamhaus_drop_enrichment')) return { rows: [] };
    return { rows: [] };
  });

  const { ['GET:/api/enrichment/spamhaus-drop/ioc']: handler } = captureRoutes(pool);
  const req = { query: { ioc_value: '1.2.3.4', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._code, 200);
  assert.equal(res._body.status, 'not_run');
  assert.equal(res._body.provider, 'spamhaus_drop');
  assert.equal(res._body.listed, null);
  assert.equal(cidrLookupCalled, false, 'GET must not query spamhaus_drop_entries');
});

test('GET ioc returns persisted not_listed without CIDR re-lookup', async () => {
  let cidrLookupCalled = false;
  const { pool } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_entries') || sql.includes('<< cidr')) {
      cidrLookupCalled = true;
      return { rows: [] };
    }
    if (sql.includes('ioc_spamhaus_drop_enrichment')) {
      return {
        rows: [{
          lookup_ip: '39.80.61.25',
          provider_status: 'not_listed',
          listed: false,
          matched_cidr: null,
          dataset_status: 'healthy',
          last_sync_at: new Date('2026-07-15T10:00:00Z'),
          enriched_at: new Date('2026-07-15T12:00:00Z')
        }]
      };
    }
    return { rows: [] };
  });

  const { ['GET:/api/enrichment/spamhaus-drop/ioc']: handler } = captureRoutes(pool);
  const req = { query: { ioc_value: 'http://39.80.61.25:36540/bin.sh', ioc_type: 'url' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'not_listed');
  assert.equal(res._body.listed, false);
  assert.equal(res._body.target_ip, '39.80.61.25');
  assert.equal(cidrLookupCalled, false);
});

test('GET ioc returns persisted listed result', async () => {
  const { pool } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('ioc_spamhaus_drop_enrichment')) {
      return {
        rows: [{
          lookup_ip: '1.2.3.4',
          provider_status: 'listed',
          listed: true,
          matched_cidr: '1.2.3.0/24',
          sblid: 'SBL999',
          rir: 'ripencc',
          list_type: 'drop_v4',
          dataset_status: 'healthy',
          enriched_at: new Date()
        }]
      };
    }
    return { rows: [] };
  });

  const { ['GET:/api/enrichment/spamhaus-drop/ioc']: handler } = captureRoutes(pool);
  const req = { query: { ioc_value: '1.2.3.4', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'listed');
  assert.equal(res._body.matched_cidr, '1.2.3.0/24');
  assert.equal(res._body.sblid, 'SBL999');
});

test('GET ioc returns disabled when provider disabled (no lookup)', async () => {
  const pool = makePool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_DISABLED };
    return { rows: [] };
  });

  const { ['GET:/api/enrichment/spamhaus-drop/ioc']: handler } = captureRoutes(pool);
  const req = { query: { ioc_value: '8.8.8.8', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'disabled');
});

test('GET ioc returns not_applicable for url with domain host (no DNS)', async () => {
  const pool = makePool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    return { rows: [] };
  });

  const { ['GET:/api/enrichment/spamhaus-drop/ioc']: handler } = captureRoutes(pool);
  const req = { query: { ioc_value: 'https://example.com/path', ioc_type: 'url' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'not_applicable');
  assert.equal(res._body.listed, null);
});

// ---------------------------------------------------------------------------
// POST /api/enrichment/spamhaus-drop/ioc/refresh
// ---------------------------------------------------------------------------

test('POST refresh returns listed=true when IP matches a CIDR and persists', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    if (sql.includes('<< cidr')) {
      return { rows: [{ cidr: '1.2.3.0/24', sblid: 'SBL999', rir: 'ripencc', list_type: 'drop_v4', synced_at: new Date() }] };
    }
    return defaultQuery(sql);
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: '1.2.3.4', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'listed');
  assert.equal(res._body.listed, true);
  assert.equal(res._body.matched_cidr, '1.2.3.0/24');
  assert.equal(res._body.target_ip, '1.2.3.4');
  assert.ok(calls.some((c) => /INSERT INTO ioc_spamhaus_drop_enrichment/i.test(c.sql)));
  const usage = usageInserts(calls);
  assert.equal(usage.length, 1, 'exactly one usage event per lookup');
  assertLocalLookupUsage(usage[0], { outcome: 'success' });
});

test('POST refresh returns listed=false when IP is not in any CIDR and persists', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    if (sql.includes('<< cidr')) return { rows: [] };
    if (sql.includes('ioc_spamhaus_drop_enrichment') && /INSERT/i.test(sql)) {
      return { rows: [{ lookup_ip: '8.8.8.8', provider_status: 'not_listed', listed: false }] };
    }
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: '8.8.8.8', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'not_listed');
  assert.equal(res._body.listed, false);
  assert.equal(res._body.target_ip, '8.8.8.8');
  assert.ok(calls.some((c) => /INSERT INTO ioc_spamhaus_drop_enrichment/i.test(c.sql)));
  const usage = usageInserts(calls);
  assert.equal(usage.length, 1, 'no-match is still a successful lookup');
  assertLocalLookupUsage(usage[0], { outcome: 'success' });
});

test('POST refresh works for url with IP host', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    if (sql.includes('<< cidr')) return { rows: [] };
    if (sql.includes('ioc_spamhaus_drop_enrichment') && /INSERT/i.test(sql)) {
      return { rows: [{ lookup_ip: '222.138.182.107', provider_status: 'not_listed', listed: false }] };
    }
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: 'http://222.138.182.107:48022/bin.sh', ioc_type: 'url' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'not_listed');
  assert.equal(res._body.target_ip, '222.138.182.107');
  const usage = usageInserts(calls);
  assert.equal(usage.length, 1);
  assertLocalLookupUsage(usage[0], { iocType: 'url', outcome: 'success' });
});

test('POST refresh returns not_applicable for url with domain host (no DNS resolve)', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: 'https://malware.example.com/payload', ioc_type: 'url' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'not_applicable');
  assert.equal(res._body.listed, null);
  assert.equal(usageInserts(calls).length, 0, 'not_applicable is rejected before lookup');
});

test('POST refresh returns disabled when provider is disabled', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_DISABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_NEVER };
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: '1.2.3.4', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'disabled');
  assert.equal(res._body.listed, null);
  assert.equal(usageInserts(calls).length, 0, 'disabled provider is not a usage event');
});

test('POST refresh returns dataset_not_synced when dataset has never synced', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_NEVER };
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: '1.2.3.4', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'dataset_not_synced');
  assert.equal(res._body.listed, null);
  assert.equal(calls.some((c) => /INSERT INTO ioc_spamhaus_drop_enrichment/i.test(c.sql)), false);
  assert.equal(usageInserts(calls).length, 0, 'never-synced dataset is a precondition, not usage');
});

test('POST refresh called twice returns the latest dataset result each time', async () => {
  let callCount = 0;
  const pool = makePool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    if (sql.includes('<< cidr')) {
      callCount++;
      if (callCount === 1) return { rows: [] };
      return { rows: [{ cidr: '5.5.5.0/24', sblid: 'SBL1', rir: 'ripencc', list_type: 'drop_v4', synced_at: new Date() }] };
    }
    if (sql.includes('ioc_spamhaus_drop_enrichment') && /INSERT/i.test(sql)) {
      return { rows: [{ lookup_ip: '5.5.5.1', provider_status: callCount === 1 ? 'not_listed' : 'listed' }] };
    }
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);

  const req1 = { body: { ioc_value: '5.5.5.1', ioc_type: 'ip' } };
  const res1 = mockRes();
  await handler(req1, res1);
  assert.equal(res1._body.status, 'not_listed');

  const req2 = { body: { ioc_value: '5.5.5.1', ioc_type: 'ip' } };
  const res2 = mockRes();
  await handler(req2, res2);
  assert.equal(res2._body.status, 'listed');
  assert.equal(res2._body.matched_cidr, '5.5.5.0/24');
});

test('POST refresh records failure usage when the local CIDR query throws', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    if (sql.includes('<< cidr')) throw new Error('connection terminated');
    if (sql.includes('ioc_spamhaus_drop_enrichment') && /INSERT/i.test(sql)) {
      return { rows: [{ lookup_ip: '1.2.3.4', provider_status: 'failed' }] };
    }
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: '1.2.3.4', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._code, 500);
  const usage = usageInserts(calls);
  assert.equal(usage.length, 1, 'technical failure records exactly one usage event');
  assertLocalLookupUsage(usage[0], { outcome: 'failure' });
});

test('POST refresh does not record usage for invalid IP input', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    if (sql.includes('<< cidr')) {
      throw new Error('invalid input syntax for type inet: "not-an-ip"');
    }
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  const req = { body: { ioc_value: 'not-an-ip', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._code, 400);
  assert.equal(res._body.code, 'invalid_ip');
  assert.equal(usageInserts(calls).length, 0, 'validation rejection is not a usage event');
});

test('GET ioc hydrate does not record Enrichment Usage', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('ioc_spamhaus_drop_enrichment')) {
      return {
        rows: [{
          lookup_ip: '1.2.3.4',
          provider_status: 'listed',
          listed: true,
          matched_cidr: '1.2.3.0/24',
          enriched_at: new Date()
        }]
      };
    }
    return { rows: [] };
  });

  const { ['GET:/api/enrichment/spamhaus-drop/ioc']: handler } = captureRoutes(pool);
  const req = { query: { ioc_value: '1.2.3.4', ioc_type: 'ip' } };
  const res = mockRes();

  await handler(req, res);

  assert.equal(res._body.status, 'listed');
  assert.equal(usageInserts(calls).length, 0, 'GET hydrate is not a lookup usage event');
});

test('POST refresh twice records two usage events (no double-count per call)', async () => {
  const { pool, calls } = trackPool(async (sql) => {
    if (sql.includes('threat_intel_provider_configs')) return { rows: CONFIG_ENABLED };
    if (sql.includes('spamhaus_drop_sync_state')) return { rows: SYNC_STATE_HEALTHY };
    if (sql.includes('<< cidr')) return { rows: [] };
    if (sql.includes('ioc_spamhaus_drop_enrichment') && /INSERT/i.test(sql)) {
      return { rows: [{ lookup_ip: '8.8.8.8', provider_status: 'not_listed', listed: false }] };
    }
    return { rows: [] };
  });

  const { ['POST:/api/enrichment/spamhaus-drop/ioc/refresh']: handler } = captureRoutes(pool);
  await handler({ body: { ioc_value: '8.8.8.8', ioc_type: 'ip' } }, mockRes());
  await handler({ body: { ioc_value: '8.8.8.8', ioc_type: 'ip' } }, mockRes());

  const usage = usageInserts(calls);
  assert.equal(usage.length, 2);
  assertLocalLookupUsage(usage[0], { outcome: 'success' });
  assertLocalLookupUsage(usage[1], { outcome: 'success' });
});
