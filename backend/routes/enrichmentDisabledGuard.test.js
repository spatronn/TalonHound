import test from 'node:test';
import assert from 'node:assert/strict';
import { registerIpEnrichmentRoutes } from './ipEnrichment.js';
import { registerAbuseIpdbEnrichmentRoutes } from './abuseipdbEnrichment.js';

// Capture Express handlers registered by a route module without a real server.
function captureRoutes(register, pool, audit) {
  const routes = {};
  const app = {
    get(path, ...handlers) { routes[`GET ${path}`] = handlers[handlers.length - 1]; },
    post(path, ...handlers) { routes[`POST ${path}`] = handlers[handlers.length - 1]; },
    put(path, ...handlers) { routes[`PUT ${path}`] = handlers[handlers.length - 1]; }
  };
  register(app, pool, audit);
  return routes;
}

// pg pool stub: returns a disabled config row for the given provider key.
function disabledPool(providerKey) {
  return {
    async query(_sql, params) {
      if (params?.[0] === providerKey) {
        return { rows: [{ provider: providerKey, enabled: false, api_key: 'stored-key', timeout_ms: 8000, config: null }] };
      }
      return { rows: [] };
    }
  };
}

function fakeRes() {
  return {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; }
  };
}

const noopAudit = { auditSuccess: async () => {}, auditFailure: async () => {} };

async function withFetchSpy(run) {
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = async (...args) => { called = true; throw new Error('external fetch must not happen for a disabled provider'); };
  try {
    await run();
  } finally {
    globalThis.fetch = original;
  }
  return called;
}

test('IPinfo refresh: disabled provider → 409 PROVIDER_DISABLED, external client not called', async () => {
  const routes = captureRoutes(registerIpEnrichmentRoutes, disabledPool('ipinfo_lite'), noopAudit);
  const handler = routes['POST /api/enrichment/ip/:ip/refresh'];
  assert.ok(handler, 'refresh route registered');

  const res = fakeRes();
  const fetchCalled = await withFetchSpy(async () => {
    await handler({ params: { ip: '8.8.8.8' }, query: {}, body: {}, user: { role: 'admin' } }, res);
  });

  assert.equal(res.statusCode, 409);
  assert.equal(res.body.error, 'PROVIDER_DISABLED');
  assert.equal(res.body.provider, 'ipinfo_lite');
  assert.equal(fetchCalled, false);
});

test('IPinfo bulk enrich: disabled provider → 409 PROVIDER_DISABLED, external client not called', async () => {
  const routes = captureRoutes(registerIpEnrichmentRoutes, disabledPool('ipinfo_lite'), noopAudit);
  const handler = routes['POST /api/enrichment/ips/enrich'];
  assert.ok(handler, 'bulk enrich route registered');

  const res = fakeRes();
  const fetchCalled = await withFetchSpy(async () => {
    await handler({ params: {}, query: {}, body: { ips: ['8.8.8.8', '1.1.1.1'] }, user: { role: 'admin' } }, res);
  });

  assert.equal(res.statusCode, 409);
  assert.equal(res.body.error, 'PROVIDER_DISABLED');
  assert.equal(res.body.provider, 'ipinfo_lite');
  assert.equal(fetchCalled, false);
});

test('AbuseIPDB refresh: disabled provider → 409 PROVIDER_DISABLED, external client not called', async () => {
  const routes = captureRoutes(registerAbuseIpdbEnrichmentRoutes, disabledPool('abuseipdb'), noopAudit);
  const handler = routes['POST /api/enrichment/abuseipdb/ip/:ip/refresh'];
  assert.ok(handler, 'refresh route registered');

  const res = fakeRes();
  const fetchCalled = await withFetchSpy(async () => {
    await handler({ params: { ip: '8.8.8.8' }, query: {}, body: {}, user: { role: 'admin' } }, res);
  });

  assert.equal(res.statusCode, 409);
  assert.equal(res.body.error, 'PROVIDER_DISABLED');
  assert.equal(res.body.provider, 'abuseipdb');
  assert.equal(fetchCalled, false);
});
