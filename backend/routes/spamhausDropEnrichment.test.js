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
});

test('POST refresh works for url with IP host', async () => {
  const pool = makePool(async (sql) => {
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
});

test('POST refresh returns not_applicable for url with domain host (no DNS resolve)', async () => {
  const pool = makePool(async (sql) => {
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
});

test('POST refresh returns disabled when provider is disabled', async () => {
  const pool = makePool(async (sql) => {
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
