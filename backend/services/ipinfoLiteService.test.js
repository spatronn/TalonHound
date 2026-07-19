import test from 'node:test';
import assert from 'node:assert/strict';
import {
  enrichIpWithIpinfoLite,
  enrichIpsWithIpinfoLite,
  getEnrichmentByIp,
  getEnrichmentsByIps
} from './ipinfoLiteService.js';

function successRow(ip, overrides = {}) {
  return {
    ip,
    normalized_ip: ip,
    provider: 'ipinfo_lite',
    provider_status: 'success',
    asn: 'AS1',
    as_name: 'Cached Network',
    as_domain: 'cached.example',
    country_code: 'US',
    country: 'United States',
    continent_code: 'NA',
    continent: 'North America',
    derived_signals: {},
    raw_json: { ip },
    error_message: null,
    last_enriched_at: '2026-07-18T10:00:00.000Z',
    ...overrides
  };
}

function createPool(initialRows = []) {
  const rowsByIp = new Map(initialRows.map((row) => [row.normalized_ip || row.ip, { ...row }]));
  const calls = [];
  return {
    rowsByIp,
    calls,
    async query(sql, params = []) {
      const text = String(sql);
      calls.push({ sql: text, params });
      if (text.includes('FROM threat_intel_provider_configs')) {
        return {
          rows: [{
            provider: 'ipinfo_lite',
            enabled: true,
            api_key: 'test-token',
            timeout_ms: 6000,
            config: { base_url: 'https://ipinfo.test' }
          }]
        };
      }
      if (text.includes('normalized_ip = ANY')) {
        return { rows: params[0].map((ip) => rowsByIp.get(ip)).filter(Boolean) };
      }
      if (text.includes('FROM ioc_ip_enrichment')) {
        const row = rowsByIp.get(params[0]);
        return { rows: row ? [row] : [] };
      }
      if (text.includes('INSERT INTO ioc_ip_enrichment')) {
        const row = {
          ip: params[0],
          normalized_ip: params[0],
          provider: params[1],
          provider_status: params[2],
          asn: params[3],
          as_name: params[4],
          as_domain: params[5],
          country_code: params[6],
          country: params[7],
          continent_code: params[8],
          continent: params[9],
          derived_signals: JSON.parse(params[10]),
          raw_json: params[11] ? JSON.parse(params[11]) : null,
          error_message: params[12],
          last_enriched_at: params[13]
        };
        rowsByIp.set(row.normalized_ip, row);
        return { rows: [row] };
      }
      return { rows: [] };
    }
  };
}

function response(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    json: async () => body
  };
}

test('cached reads and normal enrich reuse one central row without provider calls', async () => {
  const pool = createPool([successRow('8.8.8.8')]);
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return response(200, { ip: '8.8.8.8', asn: 'AS2' });
  };
  try {
    const direct = await getEnrichmentByIp(pool, '8.8.8.8');
    const associatedForDomainA = await getEnrichmentsByIps(pool, ['8.8.8.8']);
    const associatedForDomainB = await getEnrichmentsByIps(pool, ['8.8.8.8']);
    const enriched = await enrichIpWithIpinfoLite(pool, '8.8.8.8');
    assert.equal(direct, associatedForDomainA.get('8.8.8.8'));
    assert.equal(associatedForDomainA.get('8.8.8.8'), associatedForDomainB.get('8.8.8.8'));
    assert.equal(enriched.state, 'cached');
    assert.equal(providerCalls, 0);
    assert.equal(pool.calls.some((call) => call.sql.includes('threat_intel_provider_configs')), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('force refresh bypasses cache, upserts the row, and subsequent reads see new data', async () => {
  const pool = createPool([successRow('8.8.8.8')]);
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return response(200, {
      ip: '8.8.8.8',
      asn: 'AS15169',
      as_name: 'Google LLC',
      as_domain: 'google.com',
      country: 'United States',
      continent: 'North America'
    });
  };
  try {
    const forced = await enrichIpWithIpinfoLite(pool, '8.8.8.8', { force: true });
    const reloaded = await getEnrichmentByIp(pool, '8.8.8.8');
    assert.equal(providerCalls, 1);
    assert.equal(forced.state, 'enriched');
    assert.equal(reloaded.asn, 'AS15169');
    assert.equal(reloaded.as_name, 'Google LLC');
    assert.ok(Date.parse(reloaded.last_enriched_at) > Date.parse('2026-07-18T10:00:00.000Z'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('provider failure preserves the last successful central row', async () => {
  const cached = successRow('8.8.8.8');
  const pool = createPool([cached]);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response(500, {});
  try {
    const result = await enrichIpWithIpinfoLite(pool, '8.8.8.8', { force: true });
    assert.equal(result.state, 'provider_error');
    assert.equal(result.stale_cached, true);
    assert.equal(result.row.as_name, 'Cached Network');
    assert.equal(pool.rowsByIp.get('8.8.8.8').provider_status, 'success');
    assert.equal(pool.calls.filter((call) => call.sql.includes('INSERT INTO ioc_ip_enrichment')).length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('bulk enrich persists independent successes and keeps partial failures isolated', async () => {
  const pool = createPool();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const ip = decodeURIComponent(new URL(url).pathname.slice(1));
    if (ip === '1.1.1.1') {
      return response(200, { ip, asn: 'AS13335', as_name: 'Cloudflare, Inc.' });
    }
    if (ip === '8.8.4.4') return response(500, {});
    return response(200, { ip, asn: 'AS15169', as_name: 'Google LLC' });
  };
  try {
    const results = await enrichIpsWithIpinfoLite(pool, ['1.1.1.1', '8.8.8.8', '8.8.4.4']);
    assert.deepEqual(results.map((item) => item.state), ['enriched', 'enriched', 'provider_error']);
    assert.equal(pool.rowsByIp.get('1.1.1.1').provider_status, 'success');
    assert.equal(pool.rowsByIp.get('8.8.8.8').provider_status, 'success');
    assert.equal(pool.rowsByIp.get('8.8.4.4').provider_status, 'failed');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('invalid IP is never sent to provider or persisted', async () => {
  const pool = createPool();
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return response(200, {});
  };
  try {
    const results = await enrichIpsWithIpinfoLite(pool, ['not-an-ip', '10.0.0.1']);
    assert.deepEqual(results.map((item) => item.state), ['invalid_ip', 'invalid_ip']);
    assert.equal(providerCalls, 0);
    assert.equal(pool.rowsByIp.size, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('equivalent IPv6 spellings deduplicate to one provider call and DB row', async () => {
  const pool = createPool();
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return response(200, {
      ip: '2606:4700:4700::1111',
      asn: 'AS13335',
      as_name: 'Cloudflare, Inc.'
    });
  };
  try {
    const results = await enrichIpsWithIpinfoLite(pool, [
      '2606:4700:4700:0:0:0:0:1111',
      '2606:4700:4700::1111'
    ]);
    assert.equal(results.length, 1);
    assert.equal(results[0].normalized_ip, '2606:4700:4700::1111');
    assert.equal(providerCalls, 1);
    assert.equal(pool.rowsByIp.size, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
