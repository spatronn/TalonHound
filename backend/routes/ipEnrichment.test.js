import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerIpEnrichmentRoutes } from './ipEnrichment.js';

function cachedRow(ip) {
  return {
    ip,
    normalized_ip: ip,
    provider: 'ipinfo_lite',
    provider_status: 'success',
    asn: 'AS15169',
    as_name: 'Google LLC',
    as_domain: 'google.com',
    country: 'United States',
    continent: 'North America',
    derived_signals: {},
    last_enriched_at: '2026-07-19T10:00:00.000Z'
  };
}

function createPool(initialRows = []) {
  const rowsByIp = new Map(initialRows.map((row) => [row.normalized_ip, row]));
  return {
    rowsByIp,
    async query(sql, params = []) {
      const text = String(sql);
      if (text.includes('FROM threat_intel_provider_configs')) {
        return { rows: [{ provider: 'ipinfo_lite', enabled: true, api_key: 'token', config: { base_url: 'https://ipinfo.test' }, timeout_ms: 6000 }] };
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
      if (text.includes('FROM ioc_items')) return { rows: [] };
      return { rows: [] };
    }
  };
}

async function withApp(pool, fn) {
  const auditCalls = [];
  const audit = {
    auditSuccess: async (entry) => { auditCalls.push({ kind: 'success', entry }); },
    auditFailure: async (entry) => { auditCalls.push({ kind: 'failure', entry }); }
  };
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: 1, email: 'admin@example.test', role: 'admin' };
    next();
  });
  registerIpEnrichmentRoutes(app, pool, audit);
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, () => resolve(listening));
  });
  try {
    await fn({ baseUrl: `http://127.0.0.1:${server.address().port}`, auditCalls });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('bulk cache endpoint returns explicit per-IP states without provider access', async () => {
  const pool = createPool([cachedRow('8.8.8.8')]);
  await withApp(pool, async ({ baseUrl, auditCalls }) => {
    const response = await fetch(`${baseUrl}/api/enrichment/ips?ips=8.8.8.8,invalid`);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.deepEqual(body.results.map((item) => item.state), ['invalid_ip', 'cached']);
    assert.equal(body.results[1].data.as_name, 'Google LLC');
    assert.equal(auditCalls.length, 0);

    const refreshResponse = await fetch(`${baseUrl}/api/enrichment/ips/enrich`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ips: ['8.8.8.8'] })
    });
    const refreshBody = await refreshResponse.json();
    assert.equal(refreshBody.results[0].state, 'cached');
    assert.equal(auditCalls.length, 0);

    const directRefresh = await fetch(`${baseUrl}/api/enrichment/ip/8.8.8.8/refresh`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
    const directBody = await directRefresh.json();
    assert.equal(directBody.cached, true);
    assert.equal(directBody.as_name, 'Google LLC');
    assert.equal(auditCalls.length, 0);
  });
});

test('bulk enrich isolates provider errors and records force audit metadata', async () => {
  const pool = createPool();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (String(url).startsWith('http://127.0.0.1:')) return originalFetch(url, options);
    const ip = decodeURIComponent(new URL(url).pathname.slice(1));
    if (ip === '8.8.4.4') {
      return { ok: false, status: 500, headers: { get: () => null }, json: async () => ({}) };
    }
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({ ip, asn: 'AS15169', as_name: 'Google LLC' })
    };
  };
  try {
    await withApp(pool, async ({ baseUrl, auditCalls }) => {
      const response = await fetch(`${baseUrl}/api/enrichment/ips/enrich`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ips: ['8.8.8.8', '8.8.4.4'], force: true })
      });
      const body = await response.json();
      assert.equal(response.status, 200);
      assert.deepEqual(body.results.map((item) => item.state), ['enriched', 'provider_error']);
      assert.equal(pool.rowsByIp.get('8.8.8.8').provider_status, 'success');
      assert.equal(auditCalls[0].entry.metadata.force, true);
      assert.deepEqual(auditCalls[0].entry.metadata.ips, ['8.8.8.8', '8.8.4.4']);
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
