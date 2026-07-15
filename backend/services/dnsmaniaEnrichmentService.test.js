import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeDnsmaniaDomainResponse,
  normalizeDnsmaniaIpResponse,
  enrichIocWithDnsmania,
  rowToApiPayload
} from './dnsmaniaEnrichmentService.js';

test('domain success response maps to completed with relations', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'example.com',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    total_observations: 24,
    unique_ips: 2,
    records: [
      { ip: '1.2.3.4', record_type: 'A', first_seen: '2026-07-10T10:00:00Z', last_seen: '2026-07-15T14:00:00Z', count: 12 },
      { ip: null, record_type: 'NXDOMAIN', first_seen: '2026-07-11T00:00:00Z', last_seen: '2026-07-11T00:00:00Z', count: 1 }
    ],
    pagination: { limit: 50, offset: 0, returned: 2 }
  }, 'example.com');

  assert.equal(n.status, 'completed');
  assert.equal(n.known, true);
  assert.equal(n.summary.associated_ip_count, 2);
  assert.equal(n.summary.observation_count, 24);
  assert.equal(n.summary.nxdomain_observed, true);
  assert.equal(n.relations.length, 2);
  assert.equal(n.relations[0].value, '1.2.3.4');
});

test('domain never-seen response maps to no_data', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'missing.example',
    first_seen: null,
    last_seen: null,
    total_observations: 0,
    unique_ips: 0,
    records: [],
    pagination: { limit: 50, offset: 0, returned: 0 }
  }, 'missing.example');
  assert.equal(n.status, 'no_data');
  assert.equal(n.known, false);
});

test('ip success response maps associated domains', () => {
  const n = normalizeDnsmaniaIpResponse({
    ip: '1.2.3.4',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    total_observations: 54,
    unique_domains: 2,
    domains: [
      { domain: 'example.com', record_type: 'A', first_seen: '2026-07-10T10:00:00Z', last_seen: '2026-07-15T14:00:00Z', count: 12 }
    ],
    pagination: { limit: 50, offset: 0, returned: 1 }
  }, '1.2.3.4');
  assert.equal(n.status, 'completed');
  assert.equal(n.summary.associated_domain_count, 2);
  assert.equal(n.relations[0].domain, 'example.com');
});

test('enrich upserts success and overwrite on refresh (no duplicate)', async () => {
  const calls = [];
  const pool = {
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (String(sql).includes('INSERT INTO ioc_dnsmania_enrichment')) {
        return {
          rows: [{
            lookup_key: 'domain:example.com',
            lookup_type: 'domain',
            lookup_value: 'example.com',
            observable_value: 'example.com',
            ioc_type: 'domain',
            provider_status: 'completed',
            known: true,
            normalized_summary: { observation_count: 1 },
            relations_json: [{ value: '1.2.3.4' }],
            error_code: null,
            error_message: null,
            enriched_at: new Date().toISOString(),
            last_attempt_at: new Date().toISOString()
          }]
        };
      }
      return { rows: [] };
    }
  };

  const parsed = {
    lookup_key: 'domain:example.com',
    lookup_type: 'domain',
    lookup_value: 'example.com',
    observable_value: 'example.com',
    ioc_type: 'domain'
  };

  const lookupDomainFn = async () => ({
    domain: 'example.com',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    total_observations: 1,
    unique_ips: 1,
    records: [{ ip: '1.2.3.4', record_type: 'A', first_seen: '2026-07-10T10:00:00Z', last_seen: '2026-07-15T14:00:00Z', count: 1 }],
    pagination: { limit: 50, offset: 0, returned: 1 }
  });

  const first = await enrichIocWithDnsmania(pool, parsed, {
    config: { baseUrl: 'http://dnsmania.test', timeoutMs: 5000, enabled: true, configured: true, limit: 50 },
    lookupDomainFn
  });
  assert.equal(first.row.provider_status, 'completed');

  const second = await enrichIocWithDnsmania(pool, parsed, {
    config: { baseUrl: 'http://dnsmania.test', timeoutMs: 5000, enabled: true, configured: true, limit: 50 },
    lookupDomainFn
  });
  assert.equal(second.row.provider_status, 'completed');
  const inserts = calls.filter((c) => String(c.sql).includes('INSERT INTO ioc_dnsmania_enrichment'));
  assert.equal(inserts.length, 2);
  assert.match(inserts[0].sql, /ON CONFLICT \(lookup_key\) DO UPDATE/);
});

test('timeout maps to failed status', async () => {
  const pool = {
    query: async (sql) => {
      if (String(sql).includes('SELECT * FROM ioc_dnsmania_enrichment')) return { rows: [] };
      if (String(sql).includes('INSERT INTO')) {
        return {
          rows: [{
            lookup_key: 'domain:example.com',
            lookup_type: 'domain',
            lookup_value: 'example.com',
            observable_value: 'example.com',
            ioc_type: 'domain',
            provider_status: 'failed',
            known: false,
            normalized_summary: {},
            relations_json: [],
            error_code: 'timeout',
            error_message: 'DNSMania request timed out',
            last_attempt_at: new Date().toISOString()
          }]
        };
      }
      return { rows: [] };
    }
  };
  const err = new Error('DNSMania request timed out');
  err.code = 'timeout';
  const result = await enrichIocWithDnsmania(pool, {
    lookup_key: 'domain:example.com',
    lookup_type: 'domain',
    lookup_value: 'example.com',
    observable_value: 'example.com',
    ioc_type: 'domain'
  }, {
    config: { baseUrl: 'http://dnsmania.test', timeoutMs: 1000, enabled: true, configured: true, limit: 50 },
    lookupDomainFn: async () => { throw err; }
  });
  assert.equal(result.row.provider_status, 'failed');
  assert.equal(result.row.error_code, 'timeout');
});

test('disabled config fails with disabled code', async () => {
  await assert.rejects(
    () => enrichIocWithDnsmania({ query: async () => ({ rows: [] }) }, {
      lookup_key: 'domain:example.com',
      lookup_type: 'domain',
      lookup_value: 'example.com',
      observable_value: 'example.com',
      ioc_type: 'domain'
    }, {
      config: { baseUrl: 'http://dnsmania.test', timeoutMs: 1000, enabled: false, configured: true, limit: 50 }
    }),
    (e) => e.code === 'disabled'
  );
});

test('rowToApiPayload empty is not_run', () => {
  const p = rowToApiPayload(null, { lookup_type: 'domain', lookup_value: 'example.com' });
  assert.equal(p.status, 'not_run');
  assert.equal(p.enriched, false);
});
