import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeDnsmaniaDomainResponse,
  normalizeDnsmaniaIpResponse,
  deriveLatestDnsStatusFromRelations,
  buildDnsTimelineFromRelations,
  enrichIocWithDnsmania,
  lookupIp,
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
  assert.equal(n.summary.latest_dns_status, 'A');
  assert.equal(n.relations.length, 2);
  assert.equal(n.relations[0].value, '1.2.3.4');
});

test('A then later NXDOMAIN keeps Found and sets latest status NXDOMAIN', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'caudzzwo.coop-fresh.com',
    first_seen: '2026-07-17 14:44:30.978',
    last_seen: '2026-07-17 15:21:19.268',
    total_observations: 15,
    unique_ips: 2,
    records: [
      { ip: '188.114.96.3', record_type: 'A', first_seen: '2026-07-17 14:44:30.978', last_seen: '2026-07-17 14:44:31.022', count: 2 },
      { ip: '188.114.97.3', record_type: 'A', first_seen: '2026-07-17 14:44:30.978', last_seen: '2026-07-17 14:44:31.022', count: 2 },
      { ip: null, record_type: 'NXDOMAIN', first_seen: '2026-07-17 15:21:17.997', last_seen: '2026-07-17 15:21:19.268', count: 11 }
    ],
    pagination: { limit: 50, offset: 0, returned: 3 }
  }, 'caudzzwo.coop-fresh.com');

  assert.equal(n.status, 'completed');
  assert.equal(n.known, true);
  assert.equal(n.summary.latest_dns_status, 'NXDOMAIN');
  assert.equal(n.summary.nxdomain_observed, true);
  assert.equal(n.summary.associated_ip_count, 2);
  assert.match(n.summary.last_seen, /^2026-07-17T15:21:19/);
  assert.match(n.summary.last_successfully_resolved, /^2026-07-17T14:44:31/);
  assert.equal(n.relations.filter((r) => r.value).length, 2);
  assert.equal(n.relations.some((r) => r.record_type === 'NXDOMAIN'), true);
});

test('NXDOMAIN then later A sets latest status A', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'example.com',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    unique_ips: 1,
    records: [
      { ip: null, record_type: 'NXDOMAIN', first_seen: '2026-07-10T10:00:00Z', last_seen: '2026-07-11T00:00:00Z', count: 3 },
      { ip: '1.2.3.4', record_type: 'A', first_seen: '2026-07-15T14:00:00Z', last_seen: '2026-07-15T14:00:00Z', count: 1 }
    ]
  }, 'example.com');
  assert.equal(n.summary.latest_dns_status, 'A');
  assert.equal(n.summary.nxdomain_observed, true);
  assert.match(n.summary.last_successfully_resolved, /^2026-07-15T14:00:00/);
});

test('NXDOMAIN-only domain keeps Found with zero associated IPs', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'gone.example',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    unique_ips: 0,
    records: [
      { ip: null, record_type: 'NXDOMAIN', first_seen: '2026-07-10T10:00:00Z', last_seen: '2026-07-15T14:00:00Z', count: 4 }
    ]
  }, 'gone.example');
  assert.equal(n.status, 'completed');
  assert.equal(n.known, true);
  assert.equal(n.summary.latest_dns_status, 'NXDOMAIN');
  assert.equal(n.summary.associated_ip_count, 0);
  assert.equal(n.summary.last_successfully_resolved, null);
});

test('A-only domain sets latest status A', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'example.com',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    unique_ips: 1,
    records: [
      { ip: '1.2.3.4', record_type: 'A', first_seen: '2026-07-10T10:00:00Z', last_seen: '2026-07-15T14:00:00Z', count: 2 }
    ]
  }, 'example.com');
  assert.equal(n.summary.latest_dns_status, 'A');
  assert.equal(n.summary.nxdomain_observed, false);
  assert.match(n.summary.last_successfully_resolved, /^2026-07-15T14:00:00/);
});

test('sibling A records at same second do not lose to each other when NXDOMAIN is later', () => {
  const derived = deriveLatestDnsStatusFromRelations([
    { value: '188.114.96.3', record_type: 'A', first_seen: '2026-07-17T14:44:30.978Z', last_seen: '2026-07-17T14:44:31.022Z' },
    { value: '188.114.97.3', record_type: 'A', first_seen: '2026-07-17T14:44:30.978Z', last_seen: '2026-07-17T14:44:31.022Z' },
    { value: null, record_type: 'NXDOMAIN', first_seen: '2026-07-17T15:21:17.997Z', last_seen: '2026-07-17T15:21:19.268Z' }
  ]);
  assert.equal(derived.latest_dns_status, 'NXDOMAIN');
  assert.match(derived.last_successfully_resolved, /^2026-07-17T14:44:31/);
});

test('dns timeline groups sibling A rows and keeps NXDOMAIN as separate period', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'caudzzwo.coop-fresh.com',
    first_seen: '2026-07-17 14:44:30.978',
    last_seen: '2026-07-17 15:21:19.268',
    unique_ips: 2,
    records: [
      { ip: '188.114.96.3', record_type: 'A', first_seen: '2026-07-17 14:44:30.978', last_seen: '2026-07-17 14:44:31.022', count: 2 },
      { ip: '188.114.97.3', record_type: 'A', first_seen: '2026-07-17 14:44:30.978', last_seen: '2026-07-17 14:44:31.022', count: 2 },
      { ip: null, record_type: 'NXDOMAIN', first_seen: '2026-07-17 15:21:17.997', last_seen: '2026-07-17 15:21:19.268', count: 11 }
    ]
  }, 'caudzzwo.coop-fresh.com');

  assert.equal(n.summary.dns_timeline.length, 2);
  assert.equal(n.summary.dns_timeline[0].status, 'RESOLVED');
  assert.equal(n.summary.dns_timeline[0].record_type, 'A');
  assert.equal(n.summary.dns_timeline[0].observation_count, 4);
  assert.deepEqual(n.summary.dns_timeline[0].values, ['188.114.96.3', '188.114.97.3']);
  assert.equal(n.summary.dns_timeline[1].status, 'NXDOMAIN');
  assert.equal(n.summary.dns_timeline[1].observation_count, 11);
  assert.deepEqual(n.summary.dns_timeline[1].values, []);
});

test('dns timeline does not explode many NXDOMAIN observations into many rows', () => {
  const timeline = buildDnsTimelineFromRelations([
    { value: null, record_type: 'NXDOMAIN', first_seen: '2026-07-17T15:21:17.997Z', last_seen: '2026-07-17T15:21:19.268Z', count: 11 }
  ]);
  assert.equal(timeline.length, 1);
  assert.equal(timeline[0].status, 'NXDOMAIN');
  assert.equal(timeline[0].observation_count, 11);
});

test('A-only timeline has single RESOLVED period', () => {
  const n = normalizeDnsmaniaDomainResponse({
    domain: 'example.com',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    unique_ips: 1,
    records: [
      { ip: '1.2.3.4', record_type: 'A', first_seen: '2026-07-10T10:00:00Z', last_seen: '2026-07-15T14:00:00Z', count: 2 }
    ]
  }, 'example.com');
  assert.equal(n.summary.dns_timeline.length, 1);
  assert.equal(n.summary.dns_timeline[0].status, 'RESOLVED');
});

test('rowToApiPayload backfills dns_timeline for legacy summary', () => {
  const p = rowToApiPayload({
    provider_status: 'completed',
    known: true,
    lookup_type: 'domain',
    lookup_value: 'caudzzwo.coop-fresh.com',
    normalized_summary: {
      first_seen: '2026-07-17T14:44:30.978Z',
      last_seen: '2026-07-17T15:21:19.268Z',
      associated_ip_count: 2,
      nxdomain_observed: true
    },
    relations_json: [
      { value: '188.114.96.3', record_type: 'A', first_seen: '2026-07-17T14:44:30.978Z', last_seen: '2026-07-17T14:44:31.022Z', count: 2 },
      { value: '188.114.97.3', record_type: 'A', first_seen: '2026-07-17T14:44:30.978Z', last_seen: '2026-07-17T14:44:31.022Z', count: 2 },
      { value: null, record_type: 'NXDOMAIN', first_seen: '2026-07-17T15:21:17.997Z', last_seen: '2026-07-17T15:21:19.268Z', count: 11 }
    ]
  });
  assert.equal(p.summary.latest_dns_status, 'NXDOMAIN');
  assert.equal(p.summary.dns_timeline.length, 2);
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
  assert.equal(n.summary.latest_dns_status, null);
});

test('ip success response maps associated domains', () => {
  const n = normalizeDnsmaniaIpResponse({
    ip: '1.2.3.4',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    total_observations: 854685,
    unique_domains: 423710,
    domains: Array.from({ length: 5 }, (_, index) => ({
      domain: `example-${index}.com`,
      record_type: 'A',
      first_seen: '2026-07-10T10:00:00Z',
      last_seen: '2026-07-15T14:00:00Z',
      count: 12
    })),
    pagination: { limit: 5, offset: 0, returned: 5, total: 423710, has_more: true }
  }, '1.2.3.4');
  assert.equal(n.status, 'completed');
  assert.equal(n.summary.associated_domain_count, 423710);
  assert.equal(n.summary.associated_domain_count_is_exact, true);
  assert.equal(n.summary.associated_domains_returned, 5);
  assert.equal(n.relations.length, 5);
  assert.equal(n.relations[0].domain, 'example-0.com');
});

test('ip response does not treat null or invalid global counts as zero', () => {
  for (const uniqueDomains of [null, undefined, 'invalid']) {
    const n = normalizeDnsmaniaIpResponse({
      ip: '1.2.3.4',
      first_seen: '2026-07-10T10:00:00Z',
      last_seen: '2026-07-15T14:00:00Z',
      unique_domains: uniqueDomains,
      domains: [{ domain: 'example.com', record_type: 'A' }],
      pagination: { limit: 5, offset: 0, returned: 1 }
    }, '1.2.3.4');
    assert.equal(n.summary.associated_domain_count, null);
    assert.equal(n.summary.associated_domain_count_is_exact, false);
    assert.equal(n.summary.associated_domains_returned, 1);
  }
});

test('cached IP payload preserves exact count across page reload', () => {
  const p = rowToApiPayload({
    provider_status: 'completed',
    known: true,
    lookup_type: 'ip',
    lookup_value: '188.114.96.3',
    normalized_summary: {
      associated_domain_count: 423710,
      associated_domain_count_is_exact: true,
      associated_domains_returned: 5
    },
    relations_json: Array.from({ length: 5 }, (_, index) => ({ domain: `example-${index}.com` }))
  }, { cached: true, data_source: 'db' });
  assert.equal(p.summary.associated_domain_count, 423710);
  assert.equal(p.summary.associated_domain_count_is_exact, true);
  assert.equal(p.summary.associated_domains_returned, 5);
  assert.equal(p.relations.length, 5);
});

test('legacy cached IP payload exposes distinct persisted-domain fallback without claiming exactness', () => {
  const p = rowToApiPayload({
    provider_status: 'completed',
    known: true,
    lookup_type: 'ip',
    lookup_value: '188.114.96.3',
    normalized_summary: {},
    relations_json: [
      { domain: 'A.example' },
      { domain: 'a.example' },
      { domain: 'b.example' }
    ]
  });
  assert.equal(p.summary.associated_domain_count, undefined);
  assert.equal(p.summary.associated_domain_count_fallback, 2);
  assert.equal(p.summary.associated_domain_count_is_exact, false);
});

test('legacy cached IP payload preserves an existing valid associated-domain count', () => {
  const p = rowToApiPayload({
    provider_status: 'completed',
    known: true,
    lookup_type: 'ip',
    lookup_value: '188.114.96.3',
    normalized_summary: { associated_domain_count: 50 },
    relations_json: [{ domain: 'a.example' }]
  });
  assert.equal(p.summary.associated_domain_count, 50);
  assert.equal(p.summary.associated_domain_count_is_exact, false);
  assert.equal(p.summary.associated_domain_count_fallback, undefined);
});

test('lookupIp requests at most five relations by default', async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl = '';
  globalThis.fetch = async (url) => {
    requestedUrl = String(url);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ ip: '188.114.96.3', domains: [] })
    };
  };
  try {
    await lookupIp('188.114.96.3', {
      config: { baseUrl: 'http://dnsmania.test', timeoutMs: 1000, enabled: true, configured: true }
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(requestedUrl, 'http://dnsmania.test/api/v1/ip/188.114.96.3?limit=5&offset=0');
});

test('rowToApiPayload backfills latest_dns_status for legacy summary without the field', () => {
  const p = rowToApiPayload({
    provider_status: 'completed',
    known: true,
    lookup_type: 'domain',
    lookup_value: 'caudzzwo.coop-fresh.com',
    observable_value: 'caudzzwo.coop-fresh.com',
    ioc_type: 'domain',
    normalized_summary: {
      first_seen: '2026-07-17T14:44:30.978Z',
      last_seen: '2026-07-17T15:21:19.268Z',
      associated_ip_count: 2,
      nxdomain_observed: true
    },
    relations_json: [
      { value: '188.114.96.3', record_type: 'A', first_seen: '2026-07-17T14:44:30.978Z', last_seen: '2026-07-17T14:44:31.022Z' },
      { value: '188.114.97.3', record_type: 'A', first_seen: '2026-07-17T14:44:30.978Z', last_seen: '2026-07-17T14:44:31.022Z' },
      { value: null, record_type: 'NXDOMAIN', first_seen: '2026-07-17T15:21:17.997Z', last_seen: '2026-07-17T15:21:19.268Z' }
    ],
    enriched_at: '2026-07-17T15:22:00Z'
  });
  assert.equal(p.summary.latest_dns_status, 'NXDOMAIN');
  assert.match(p.summary.last_successfully_resolved, /^2026-07-17T14:44:31/);
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
  const summaryArg = JSON.parse(inserts[0].params[7]);
  assert.equal(summaryArg.latest_dns_status, 'A');
});

test('successful IP refresh persists exact total and only returned relations', async () => {
  let persistedSummary;
  let persistedRelations;
  const pool = {
    query: async (sql, params) => {
      if (String(sql).includes('INSERT INTO ioc_dnsmania_enrichment')) {
        persistedSummary = JSON.parse(params[7]);
        persistedRelations = JSON.parse(params[8]);
        return {
          rows: [{
            lookup_key: 'ip:188.114.96.3',
            lookup_type: 'ip',
            lookup_value: '188.114.96.3',
            provider_status: 'completed',
            known: true,
            normalized_summary: persistedSummary,
            relations_json: persistedRelations
          }]
        };
      }
      return { rows: [] };
    }
  };
  const domains = Array.from({ length: 5 }, (_, index) => ({
    domain: `example-${index}.com`,
    record_type: 'A',
    first_seen: '2026-07-10T10:00:00Z',
    last_seen: '2026-07-15T14:00:00Z',
    count: index + 1
  }));

  await enrichIocWithDnsmania(pool, {
    lookup_key: 'ip:188.114.96.3',
    lookup_type: 'ip',
    lookup_value: '188.114.96.3',
    observable_value: '188.114.96.3',
    ioc_type: 'ip'
  }, {
    config: { baseUrl: 'http://dnsmania.test', timeoutMs: 5000, enabled: true, configured: true, ipLimit: 5 },
    lookupIpFn: async () => ({
      ip: '188.114.96.3',
      first_seen: '2026-07-10T10:00:00Z',
      last_seen: '2026-07-15T14:00:00Z',
      total_observations: 854685,
      unique_domains: 423710,
      domains,
      pagination: { limit: 5, offset: 0, returned: 5, total: 423710, has_more: true }
    })
  });

  assert.equal(persistedSummary.associated_domain_count, 423710);
  assert.equal(persistedSummary.associated_domain_count_is_exact, true);
  assert.equal(persistedSummary.associated_domains_returned, 5);
  assert.equal(persistedRelations.length, 5);
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
