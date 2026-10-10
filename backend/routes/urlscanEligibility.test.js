// urlscan.io IOC-type eligibility, end to end on the backend: urlscan applies to
// domain and url observables only (whitelist). Every other type — IP, hashes,
// future types — must never reach the urlscan API from any entry point (IOC
// Details GET / refresh / force refresh, MCP enrich_ioc orchestration), and
// stored rows for such types must not be served (REST GET, MCP get_ioc_context).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { registerUrlscanEnrichmentRoutes } from './urlscanEnrichment.js';
import {
  URLSCAN_SUPPORTED_OBSERVABLE_TYPES,
  URLSCAN_UNSUPPORTED_TYPE_MESSAGE,
  isSupportedUrlscanIocType,
  buildUrlscanSearchQuery
} from '../lib/urlscanEnrichment.js';
import {
  getEnrichmentProvider,
  listEnrichmentProviders,
  registerEnrichmentExecutor,
  resetEnrichmentExecutorsForTests
} from '../lib/enrichmentProviderRegistry.js';
import { collectIocEnrichments } from '../lib/iocEnrichmentAggregator.js';
import { mcpEnrichIocs } from '../lib/mcpEnrichmentService.js';
import { scopesForAccessProfile } from '../lib/apiKeyProfiles.js';
import { createFakeEnrichmentPool, waitForFakeJob } from '../lib/fixtures/fakeEnrichmentPool.js';
import { resetEnrichmentProviderGuardForTests } from '../lib/enrichmentProviderGuard.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const SHA256 = '8588d11874ab52a1637953dc5538984647023d00b529f695fbd0e40cf8e5e852';
const IOCS = {
  1: { id: 1, ioc_value: '8.218.50.207', ioc_type: 'ip' },
  2: { id: 2, ioc_value: '2001:db8::1', ioc_type: 'ipv6' },
  3: { id: 3, ioc_value: SHA256, ioc_type: 'sha256' },
  4: { id: 4, ioc_value: 'example.org', ioc_type: 'domain' },
  5: { id: 5, ioc_value: 'https://example.org/login', ioc_type: 'url' }
};

// Enabled + configured urlscan; ioc_items answered from IOCS by id; an optional
// stored ioc_enrichments row (e.g. an IP row written under the old policy).
function routePool({ storedRow = null } = {}) {
  const writes = [];
  return {
    writes,
    async query(sql, params = []) {
      const s = String(sql);
      if (/FROM ioc_items/i.test(s)) {
        const row = IOCS[Number(params[0])];
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      if (/threat_intel_provider_configs/.test(s) && /SELECT/i.test(s)) {
        return {
          rows: [{
            provider: 'urlscan', enabled: true, api_key: 'test-key-12345', ttl_hours: 24, timeout_ms: 8000,
            config: { lookback_days: 30, search_size: 10, detail_limit: 2, no_result_ttl_hours: 6 }
          }]
        };
      }
      if (/FROM ioc_enrichments/.test(s) && /SELECT/i.test(s)) {
        return { rows: storedRow ? [storedRow] : [] };
      }
      if (/INSERT INTO ioc_enrichments/.test(s)) {
        const row = {
          ioc_id: params[0], ioc_value: params[1], ioc_type: params[2], provider: 'urlscan', status: params[4],
          normalized_summary: JSON.parse(params[5]), error_message: params[7], fetched_at: params[8], expires_at: params[9]
        };
        writes.push(row);
        return { rows: [row] };
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

function captureRoutes(pool) {
  const routes = {};
  const app = {
    get(p, ...h) { routes[`GET ${p}`] = h[h.length - 1]; },
    post(p, ...h) { routes[`POST ${p}`] = h[h.length - 1]; },
    put(p, ...h) { routes[`PUT ${p}`] = h[h.length - 1]; }
  };
  registerUrlscanEnrichmentRoutes(app, pool, { auditSuccess: async () => {}, auditFailure: async () => {} });
  return routes;
}

function fakeRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; }
  };
}

// Every outbound fetch is recorded; urlscan search answers "no hits".
async function withFetchRecorder(run) {
  const original = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (url) => {
    urls.push(String(url));
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      arrayBuffer: async () => Buffer.from(JSON.stringify({ total: 0, results: [], took: 1, has_more: false }))
    };
  };
  try {
    await run();
  } finally {
    globalThis.fetch = original;
  }
  return urls;
}

const admin = { role: 'admin', id: 1, username: 'admin' };

async function refresh(id, { force = false, body = {} } = {}) {
  const pool = routePool();
  const handler = captureRoutes(pool)['POST /api/ioc/:id/enrichments/urlscan/refresh'];
  const res = fakeRes();
  const urls = await withFetchRecorder(() => handler(
    { params: { id: String(id) }, query: force ? { force: 'true' } : {}, body, user: admin, headers: {} },
    res
  ));
  return { res, urls, writes: pool.writes };
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

test('urlscan supported observable types = domain + url (whitelist)', () => {
  assert.deepEqual([...URLSCAN_SUPPORTED_OBSERVABLE_TYPES], ['domain', 'url']);
  assert.equal(isSupportedUrlscanIocType('domain'), 'domain');
  assert.equal(isSupportedUrlscanIocType('hostname'), 'domain');
  assert.equal(isSupportedUrlscanIocType('URL'), 'url');
  for (const t of ['ip', 'ipv4', 'ipv6', 'ip6', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh',
    'hash', 'file_hash', 'email', 'cve', 'some_future_type', '', null, undefined]) {
    assert.equal(isSupportedUrlscanIocType(t), null, String(t));
  }
  // No query can be built for a non-applicable type.
  assert.deepEqual(buildUrlscanSearchQuery('ip', '8.218.50.207'), { ok: false, reason: 'unsupported_type' });
});

test('frontend URLSCAN_SUPPORTED_IOC_TYPES mirrors the backend list (drift guard)', () => {
  const src = readFileSync(path.join(here, '../../frontend/src/lib/iocProviderApplicability.js'), 'utf8');
  const m = src.match(/export const URLSCAN_SUPPORTED_IOC_TYPES = Object\.freeze\(\[([^\]]*)\]\)/);
  assert.ok(m, 'frontend declares URLSCAN_SUPPORTED_IOC_TYPES');
  const frontendTypes = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
  assert.deepEqual(frontendTypes.sort(), [...URLSCAN_SUPPORTED_OBSERVABLE_TYPES].sort());
});

// ---------------------------------------------------------------------------
// Refresh route (IOC Details Refresh / Force, and the MCP executor's function)
// ---------------------------------------------------------------------------

for (const [id, label] of [[1, 'IP 8.218.50.207'], [2, 'IPv6'], [3, 'SHA256']]) {
  test(`refresh for ${label} IOC → 422 unsupported, no upstream urlscan request, nothing stored`, async () => {
    for (const force of [false, true]) {
      const { res, urls, writes } = await refresh(id, { force });
      assert.equal(res.statusCode, 422, `force=${force}`);
      assert.equal(res.body.provider, 'urlscan');
      assert.equal(res.body.provider_status, 'unsupported');
      assert.equal(res.body.message, URLSCAN_UNSUPPORTED_TYPE_MESSAGE);
      assert.deepEqual(urls, [], `force=${force}`);
      assert.deepEqual(writes, []);
    }
  });
}

test('refresh ignores a client-supplied type: the stored IOC type decides', async () => {
  const { res, urls } = await refresh(1, { body: { iocType: 'domain', ioc_type: 'domain', observable_type: 'url' } });
  assert.equal(res.statusCode, 422);
  assert.deepEqual(urls, []);
});

for (const [id, label, needle] of [[4, 'domain', 'example.org'], [5, 'URL', 'example.org%2Flogin']]) {
  test(`refresh for ${label} IOC still queries urlscan and stores the result`, async () => {
    const { res, urls, writes } = await refresh(id);
    assert.equal(res.statusCode, 200, JSON.stringify(res.body));
    assert.equal(urls.length, 1);
    assert.match(urls[0], /^https:\/\/urlscan\.io\/api\/v1\/search\?/);
    assert.ok(urls[0].includes(needle), urls[0]);
    assert.equal(writes.length, 1);
    assert.equal(res.body.provider, 'urlscan');
  });
}

// ---------------------------------------------------------------------------
// GET (cached read used by the IOC Details card)
// ---------------------------------------------------------------------------

const staleIpRow = {
  ioc_id: 1, ioc_value: '8.218.50.207', ioc_type: 'ip', provider: 'urlscan', status: 'not_found',
  normalized_summary: { evidence_assessment: 'no_results' }, fetched_at: '2026-10-01T00:00:00.000Z',
  expires_at: '2026-10-02T00:00:00.000Z'
};

test('GET for an IP IOC never serves a stored urlscan row (422 unsupported, no upstream call)', async () => {
  const pool = routePool({ storedRow: staleIpRow });
  const handler = captureRoutes(pool)['GET /api/ioc/:id/enrichments/urlscan'];
  for (const id of [1, 3]) {
    const res = fakeRes();
    const urls = await withFetchRecorder(() => handler({ params: { id: String(id) }, user: admin }, res));
    assert.equal(res.statusCode, 422);
    assert.equal(res.body.provider_status, 'unsupported');
    assert.equal(res.body.summary, undefined);
    assert.deepEqual(urls, []);
  }
});

test('GET for domain / URL IOCs serves the cached row', async () => {
  for (const id of [4, 5]) {
    const row = { ...staleIpRow, ioc_id: id, ioc_value: IOCS[id].ioc_value, ioc_type: IOCS[id].ioc_type };
    const handler = captureRoutes(routePool({ storedRow: row }))['GET /api/ioc/:id/enrichments/urlscan'];
    const res = fakeRes();
    await handler({ params: { id: String(id) }, user: admin }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.cached, true);
    assert.equal(res.body.ioc_id, id);
  }
});

test('GET for an unknown IOC id → 404', async () => {
  const handler = captureRoutes(routePool())['GET /api/ioc/:id/enrichments/urlscan'];
  const res = fakeRes();
  await handler({ params: { id: '999' }, user: admin }, res);
  assert.equal(res.statusCode, 404);
});

// ---------------------------------------------------------------------------
// Registry capability + automated orchestration (MCP enrich_ioc)
// ---------------------------------------------------------------------------

test('registry: urlscan capability is domain + url; IP / hash IOCs are not applicable', () => {
  const urlscan = getEnrichmentProvider('urlscan');
  assert.deepEqual(urlscan.supportedObservableTypes, ['domain', 'url']);
  const applies = (observable, observable_type) => urlscan.resolveTarget({ observable, observable_type });
  for (const [v, t] of [['8.218.50.207', 'ip'], ['10.0.0.1', 'ip'], ['2001:db8::1', 'ipv6'], [SHA256, 'sha256'],
    ['d41d8cd98f00b204e9800998ecf8427e', 'md5'], ['x', 'some_future_type']]) {
    assert.deepEqual(applies(v, t), { applicable: false, reason: 'unsupported_type' }, `${t}`);
  }
  assert.deepEqual(applies('example.org', 'domain'),
    { applicable: true, scope: 'direct', target_type: 'domain', target_value: 'example.org' });
  assert.deepEqual(applies('https://example.org/login', 'url'),
    { applicable: true, scope: 'direct', target_type: 'url', target_value: 'https://example.org/login' });
});

async function runMcpEnrich(ioc, providers) {
  resetEnrichmentExecutorsForTests();
  resetEnrichmentProviderGuardForTests();
  const invoked = [];
  const saved = [];
  for (const p of listEnrichmentProviders()) {
    if (p.key.startsWith('t_')) continue;
    registerEnrichmentExecutor(p.key, async () => { invoked.push(p.key); return { status: 200, body: { status: 'success' } }; });
    saved.push([p, p.loadState, p.readFreshness]);
    p.loadState = async () => ({ enabled: true, configured: true });
    p.readFreshness = async () => ({ fresh: false, last_enriched_at: null });
  }
  const pool = createFakeEnrichmentPool({ iocs: [ioc] });
  const req = {
    user: { id: 3, username: 'analyst1', role: 'analyst' },
    mcpAuth: { scopes: scopesForAccessProfile('mcp_analyst'), ownerRole: 'analyst', apiKeyId: 42 },
    headers: {}
  };
  const audit = { auditSuccess: async () => {}, auditFailure: async () => {} };
  try {
    const out = await mcpEnrichIocs(pool, { ioc_id: ioc.public_id, ...(providers ? { providers } : {}) },
      { req, mcpAuth: req.mcpAuth, audit });
    if (out.body?.job_id) await waitForFakeJob(pool, out.body.job_id);
    await new Promise((r) => setTimeout(r, 20));
    return { out, invoked };
  } finally {
    for (const [p, load, fresh] of saved) { p.loadState = load; p.readFreshness = fresh; }
    resetEnrichmentExecutorsForTests();
  }
}

const IP_IOC = { id: 1, public_id: '11111111-1111-4111-8111-111111111111', observable: '8.218.50.207', observable_type: 'ip' };

test('orchestration: "all providers" for an IP IOC never schedules urlscan', async () => {
  const { out, invoked } = await runMcpEnrich(IP_IOC);
  assert.equal(invoked.includes('urlscan'), false);
  assert.ok(invoked.length > 0, 'applicable IP providers still run');
  assert.ok(out.body.not_applicable.some((n) => n.provider === 'urlscan' && n.reason === 'unsupported_type'));
  assert.equal((out.body.providers || []).some((p) => p.provider === 'urlscan'), false);
});

test('orchestration: explicitly requesting urlscan for an IP IOC → unsupported, executor not called', async () => {
  const { out, invoked } = await runMcpEnrich(IP_IOC, ['urlscan', 'spamhaus_drop']);
  assert.deepEqual(invoked, ['spamhaus_drop']);
  const item = out.body.providers.find((p) => p.provider === 'urlscan');
  assert.equal(item.status, 'unsupported');
  assert.equal(item.error_code, 'unsupported_observable');
});

test('orchestration: urlscan still runs for domain and URL IOCs', async () => {
  for (const [observable, observable_type] of [['example.org', 'domain'], ['https://example.org/login', 'url']]) {
    const ioc = { id: 4, public_id: '44444444-4444-4444-8444-444444444444', observable, observable_type };
    const { invoked } = await runMcpEnrich(ioc, ['urlscan']);
    assert.deepEqual(invoked, ['urlscan'], observable_type);
  }
});

// ---------------------------------------------------------------------------
// MCP get_ioc_context read path
// ---------------------------------------------------------------------------

function aggregatorPool(rows) {
  return {
    query: async (sql) => {
      if (String(sql).includes('FROM ioc_enrichments')) return { rows };
      throw Object.assign(new Error('relation does not exist'), { code: '42P01' });
    }
  };
}

const genericRows = [
  { provider: 'urlscan', status: 'not_found', ioc_type: 'ip', normalized_summary: null, fetched_at: '2026-10-01T00:00:00.000Z' },
  { provider: 'virustotal', status: 'success', ioc_type: 'ip', normalized_summary: {}, fetched_at: '2026-10-01T00:00:00.000Z' }
];

test('collectIocEnrichments drops stored urlscan rows for IP / hash IOCs, keeps other providers', async () => {
  for (const type of ['ip', 'ipv6', 'sha256']) {
    const entries = await collectIocEnrichments(aggregatorPool(genericRows), { iocId: 1, type, value: '8.218.50.207' });
    assert.deepEqual(entries.map((e) => e.provider), ['virustotal'], type);
  }
});

test('collectIocEnrichments keeps urlscan for domain / URL IOCs', async () => {
  for (const type of ['domain', 'url']) {
    const entries = await collectIocEnrichments(aggregatorPool(genericRows), { iocId: 1, type, value: 'example.org' });
    assert.deepEqual(entries.map((e) => e.provider), ['urlscan', 'virustotal'], type);
  }
});
