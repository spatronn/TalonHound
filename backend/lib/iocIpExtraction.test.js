import test from 'node:test';
import assert from 'node:assert/strict';
import { extractIpLiteralFromIoc } from './iocIpExtraction.js';
import { collectDerivedInfrastructure, collectIocEnrichments } from './iocEnrichmentAggregator.js';

test('extractIpLiteralFromIoc: URL IPv4 host', () => {
  assert.equal(extractIpLiteralFromIoc('http://94.154.43.38/main_arm', 'url'), '94.154.43.38');
});

test('extractIpLiteralFromIoc: URL IPv4 with port', () => {
  assert.equal(extractIpLiteralFromIoc('http://94.154.43.38:8080/path', 'url'), '94.154.43.38');
});

test('extractIpLiteralFromIoc: domain URL returns null (no DNS)', () => {
  assert.equal(extractIpLiteralFromIoc('https://evil.example.com/x', 'url'), null);
});

test('extractIpLiteralFromIoc: IP IOC', () => {
  assert.equal(extractIpLiteralFromIoc('203.0.113.7', 'ip'), '203.0.113.7');
});

test('collectDerivedInfrastructure: returns null for non-URL', async () => {
  const pool = { query: async () => { throw new Error('should not query'); } };
  assert.equal(await collectDerivedInfrastructure(pool, { type: 'ip', value: '1.2.3.4' }), null);
  assert.equal(await collectDerivedInfrastructure(pool, { type: 'domain', value: 'a.com' }), null);
});

test('collectDerivedInfrastructure: URL IP host with partial providers', async () => {
  const pool = {
    query: async (sql, params = []) => {
      const q = String(sql);
      if (q.includes('FROM ioc_abuseipdb_enrichment')) {
        return {
          rows: [{
            ip: params[0],
            provider_status: 'success',
            normalized_summary: { abuseConfidenceScore: 90 },
            last_enriched_at: '2026-09-07T00:00:00.000Z',
            error_message: null
          }]
        };
      }
      if (q.includes('FROM ioc_ip_enrichment') || q.includes('FROM ioc_spamhaus_drop_enrichment')) {
        return { rows: [] };
      }
      throw new Error(`unexpected: ${q.slice(0, 80)}`);
    }
  };
  const out = await collectDerivedInfrastructure(pool, {
    type: 'url',
    value: 'http://94.154.43.38/main_arm'
  });
  assert.equal(out.extracted_host, '94.154.43.38');
  assert.equal(out.host_type, 'ip');
  assert.deepEqual(out.enrichments.map((e) => e.provider), ['abuseipdb']);
});

test('collectIocEnrichments: URL does not pull IP providers into direct enrichment', async () => {
  const seen = [];
  const pool = {
    query: async (sql) => {
      const q = String(sql);
      seen.push(q);
      if (q.includes('FROM ioc_enrichments')) {
        return {
          rows: [{
            provider: 'virustotal',
            status: 'success',
            ioc_type: 'url',
            normalized_summary: { ok: true },
            fetched_at: null,
            expires_at: null,
            error_message: null
          }]
        };
      }
      // Missing optional tables are tolerated via 42P01 — but AbuseIPDB/IPinfo
      // must not be queried for URL direct enrichment (type gate).
      throw Object.assign(new Error('relation does not exist'), { code: '42P01' });
    }
  };
  const entries = await collectIocEnrichments(pool, {
    iocId: 1,
    type: 'url',
    value: 'http://94.154.43.38/main_arm'
  });
  assert.deepEqual(entries.map((e) => e.provider), ['virustotal']);
  assert.ok(!seen.some((q) => q.includes('FROM ioc_abuseipdb_enrichment')));
  assert.ok(!seen.some((q) => q.includes('FROM ioc_ip_enrichment')));
  assert.ok(!seen.some((q) => q.includes('FROM ioc_spamhaus_drop_enrichment')));
});
