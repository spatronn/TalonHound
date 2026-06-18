import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isCacheFresh,
  enrichIpWithAbuseIpdb,
  fetchAbuseIpdbCheck,
  getAbuseIpdbConfig
} from './abuseipdbService.js';

function mockPool(rowsByQuery = []) {
  let call = 0;
  return {
    query: async (sql, params) => {
      if (rowsByQuery[call]) return rowsByQuery[call](sql, params);
      call += 1;
      if (/threat_intel_provider_configs/.test(sql)) {
        return {
          rows: [{
            provider: 'abuseipdb',
            enabled: true,
            api_key: 'test-key-12345',
            ttl_hours: 24,
            timeout_ms: 8000,
            config: { max_age_days: 90, verbose: false }
          }]
        };
      }
      if (/ioc_abuseipdb_enrichment/.test(sql) && /SELECT/.test(sql)) {
        return { rows: [] };
      }
      if (/INSERT INTO ioc_abuseipdb_enrichment/.test(sql)) {
        return {
          rows: [{
            ip: params[0],
            provider_status: params[1],
            max_age_days: params[2],
            verbose: params[3],
            normalized_summary: JSON.parse(params[4]),
            last_enriched_at: new Date().toISOString()
          }]
        };
      }
      return { rows: [] };
    }
  };
}

test('private IP does not call external fetch', async () => {
  let fetchCalled = false;
  const pool = mockPool();
  const result = await enrichIpWithAbuseIpdb(pool, '10.0.0.1', {
    fetchImpl: async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; }
  });
  assert.equal(result.skipped, true);
  assert.equal(result.provider_status, 'unsupported_private_ip');
  assert.equal(fetchCalled, false);
});

test('missing API key returns not_configured without fetch', async () => {
  let fetchCalled = false;
  const pool = {
    query: async (sql) => {
      if (/threat_intel_provider_configs/.test(sql)) {
        return { rows: [{ provider: 'abuseipdb', enabled: true, api_key: null, ttl_hours: 24, timeout_ms: 8000, config: {} }] };
      }
      return { rows: [] };
    }
  };
  const result = await enrichIpWithAbuseIpdb(pool, '8.8.8.8', {
    fetchImpl: async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; }
  });
  assert.equal(result.provider_status, 'not_configured');
  assert.equal(fetchCalled, false);
});

test('cache hit prevents external fetch', async () => {
  let fetchCalled = false;
  const freshRow = {
    ip: '8.8.8.8',
    provider_status: 'success',
    max_age_days: 90,
    verbose: false,
    normalized_summary: { abuseConfidenceScore: 0, provider_status: 'success' },
    last_enriched_at: new Date().toISOString()
  };
  const pool = {
    query: async (sql) => {
      if (/threat_intel_provider_configs/.test(sql)) {
        return { rows: [{ provider: 'abuseipdb', enabled: true, api_key: 'key', ttl_hours: 24, timeout_ms: 8000, config: { max_age_days: 90, verbose: false } }] };
      }
      if (/SELECT \* FROM ioc_abuseipdb_enrichment/.test(sql)) {
        return { rows: [freshRow] };
      }
      return { rows: [] };
    }
  };
  const config = await getAbuseIpdbConfig(pool);
  assert.equal(isCacheFresh(freshRow, config, { force: false }), true);

  const result = await enrichIpWithAbuseIpdb(pool, '8.8.8.8', {
    fetchImpl: async () => { fetchCalled = true; return { ok: true, json: async () => ({}) }; }
  });
  assert.equal(result.cached, true);
  assert.equal(fetchCalled, false);
});

test('refresh with force bypasses cache', async () => {
  let fetchCalled = false;
  const freshRow = {
    ip: '8.8.8.8',
    provider_status: 'success',
    max_age_days: 90,
    verbose: false,
    normalized_summary: { abuseConfidenceScore: 0, provider_status: 'success' },
    last_enriched_at: new Date().toISOString()
  };
  const pool = {
    query: async (sql) => {
      if (/threat_intel_provider_configs/.test(sql)) {
        return { rows: [{ provider: 'abuseipdb', enabled: true, api_key: 'key', ttl_hours: 24, timeout_ms: 8000, config: { max_age_days: 90, verbose: false } }] };
      }
      if (/SELECT \* FROM ioc_abuseipdb_enrichment/.test(sql)) {
        return { rows: [freshRow] };
      }
      if (/INSERT INTO ioc_abuseipdb_enrichment/.test(sql)) {
        return {
          rows: [{
            ip: '8.8.8.8',
            provider_status: 'success',
            normalized_summary: { abuseConfidenceScore: 5, provider_status: 'success' },
            last_enriched_at: new Date().toISOString()
          }]
        };
      }
      return { rows: [] };
    }
  };
  assert.equal(isCacheFresh(freshRow, { cache_ttl_hours: 24, max_age_days: 90, verbose: false }, { force: true }), false);

  const result = await enrichIpWithAbuseIpdb(pool, '8.8.8.8', {
    force: true,
    fetchImpl: async () => {
      fetchCalled = true;
      return {
        ok: true,
        json: async () => ({
          data: {
            ipAddress: '8.8.8.8',
            abuseConfidenceScore: 5,
            totalReports: 1,
            numDistinctUsers: 1
          }
        })
      };
    }
  });
  assert.equal(fetchCalled, true);
  assert.equal(result.cached, false);
});

test('fetchAbuseIpdbCheck maps 401/429/5xx errors', async () => {
  for (const [status, code] of [[401, 'auth'], [429, 'rate_limit'], [503, 'provider_error']]) {
    await assert.rejects(
      () => fetchAbuseIpdbCheck('8.8.8.8', {
        apiKey: 'key',
        timeout_ms: 5000,
        max_age_days: 90,
        verbose: false
      }, {
        fetchImpl: async () => ({
          ok: false,
          status,
          headers: { get: () => null }
        })
      }),
      (err) => err.code === code
    );
  }
});
