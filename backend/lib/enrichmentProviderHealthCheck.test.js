import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyProbeError,
  statusForFailure,
  resolveActiveProbeHealth,
  recordHealthProbeResult,
  runProviderHealthProbe,
  testRdapConnection,
  HEALTH_FAILURE_THRESHOLD,
  RDAP_HEALTH_PROBE_DOMAIN,
  ACTIVE_PROBE_PROVIDERS
} from './enrichmentProviderHealthCheck.js';

const HOUR = 60 * 60 * 1000;

/** Minimal fake pool that records queries and serves scripted rows. */
function fakePool({ rowsFor } = {}) {
  const queries = [];
  return {
    queries,
    async query(sql, params = []) {
      queries.push({ sql, params });
      const rows = rowsFor ? rowsFor(sql, params) : [];
      return { rows: rows || [], rowCount: (rows || []).length };
    }
  };
}

// A valid RDAP JSON document for example.com (trimmed to what the parser reads).
const RDAP_OK = {
  objectClassName: 'domain',
  ldhName: 'EXAMPLE.COM',
  status: ['client delete prohibited'],
  events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }],
  entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'RESERVED-Internet']]] }],
  nameservers: [{ ldhName: 'a.iana-servers.net' }]
};

test('classifyProbeError maps codes to sanitized categories', () => {
  assert.equal(classifyProbeError({ code: 'not_configured' }).category, 'not_configured');
  assert.equal(classifyProbeError({ code: 'auth' }).category, 'auth');
  assert.equal(classifyProbeError({ code: 'rate_limit' }).category, 'rate_limit');
  assert.equal(classifyProbeError({ code: 'timeout' }).category, 'timeout');
  assert.equal(classifyProbeError({ code: 'http_error' }).category, 'http');
  assert.equal(classifyProbeError({ code: 'anything else' }).category, 'network');
  // Evidence never leaks the raw provider message.
  const ev = classifyProbeError({ code: 'auth', message: 'key sk-SECRET-123 rejected' }).evidence;
  assert.ok(!/SECRET/.test(ev));
});

test('statusForFailure: auth is immediately unhealthy, rate limit stays degraded', () => {
  assert.equal(statusForFailure('auth', 1), 'unhealthy');
  assert.equal(statusForFailure('rate_limit', 5), 'degraded');
});

test('statusForFailure: transient degrades first, escalates at threshold', () => {
  assert.equal(statusForFailure('network', 1), 'degraded');
  assert.equal(statusForFailure('timeout', HEALTH_FAILURE_THRESHOLD - 1), 'degraded');
  assert.equal(statusForFailure('network', HEALTH_FAILURE_THRESHOLD), 'unhealthy');
});

test('resolveActiveProbeHealth: never checked -> unknown with explicit evidence', () => {
  const h = resolveActiveProbeHealth(null);
  assert.equal(h.status, 'unknown');
  assert.equal(h.reason, 'never_checked');
  assert.equal(h.evidence, 'No health check has been performed yet');
});

test('resolveActiveProbeHealth: recent healthy stays healthy', () => {
  const now = Date.now();
  const h = resolveActiveProbeHealth({
    status: 'healthy',
    last_check_at: new Date(now - HOUR).toISOString(),
    last_success_at: new Date(now - HOUR).toISOString(),
    evidence: 'Scheduled connection test succeeded'
  }, { now });
  assert.equal(h.status, 'healthy');
  assert.equal(h.evidence, 'Scheduled connection test succeeded');
});

test('resolveActiveProbeHealth: aged healthy evidence becomes overdue Degraded, never Unknown', () => {
  const now = Date.now();
  const h = resolveActiveProbeHealth({
    status: 'healthy',
    last_check_at: new Date(now - 40 * HOUR).toISOString(),
    last_success_at: new Date(now - 40 * HOUR).toISOString()
  }, { now });
  assert.equal(h.status, 'degraded');
  assert.equal(h.reason, 'overdue');
  assert.notEqual(h.status, 'unknown');
});

test('resolveActiveProbeHealth: unhealthy row passes through', () => {
  const now = Date.now();
  const h = resolveActiveProbeHealth({
    status: 'unhealthy',
    last_check_at: new Date(now - HOUR).toISOString(),
    error_category: 'auth',
    evidence: 'Authentication failed (invalid or revoked credentials)'
  }, { now });
  assert.equal(h.status, 'unhealthy');
});

test('recordHealthProbeResult success writes healthy and resets consecutive failures', async () => {
  const pool = fakePool();
  await recordHealthProbeResult(pool, { provider: 'virustotal', source: 'manual', outcome: 'success' });
  const insert = pool.queries.find((q) => /INSERT INTO enrichment_provider_health/.test(q.sql));
  assert.ok(insert);
  assert.match(insert.sql, /status = 'healthy'/);
  assert.match(insert.sql, /consecutive_failures = 0/);
  // source + evidence params are present and evidence is the manual message.
  assert.equal(insert.params[1], 'manual');
  assert.equal(insert.params[2], 'Manual connection test succeeded');
});

test('recordHealthProbeResult failure escalates degraded -> unhealthy across the threshold', async () => {
  // Existing row already has 2 consecutive network failures.
  const pool = fakePool({
    rowsFor: (sql) => (/SELECT \* FROM enrichment_provider_health/.test(sql)
      ? [{ provider: 'ipinfo_lite', consecutive_failures: HEALTH_FAILURE_THRESHOLD - 1 }]
      : [])
  });
  const res = await recordHealthProbeResult(pool, {
    provider: 'ipinfo_lite', source: 'scheduled', outcome: 'failure', category: 'network', evidence: 'net err'
  });
  assert.equal(res.consecutive_failures, HEALTH_FAILURE_THRESHOLD);
  assert.equal(res.status, 'unhealthy');
});

test('recordHealthProbeResult rate-limit does not accrue toward unhealthy', async () => {
  const pool = fakePool({
    rowsFor: (sql) => (/SELECT \* FROM enrichment_provider_health/.test(sql)
      ? [{ provider: 'abuseipdb', consecutive_failures: 4 }]
      : [])
  });
  const res = await recordHealthProbeResult(pool, {
    provider: 'abuseipdb', source: 'scheduled', outcome: 'failure', category: 'rate_limit', evidence: 'rl'
  });
  assert.equal(res.status, 'degraded');
  assert.equal(res.consecutive_failures, 4); // unchanged
});

test('testRdapConnection invokes the real client, bypasses cache, and parses the response', async () => {
  const calls = [];
  const pool = fakePool();
  const fetchFn = async (domain) => { calls.push(domain); return RDAP_OK; };
  const detail = await testRdapConnection(pool, { fetchFn });
  // Real lookup path exercised against the reserved probe domain.
  assert.deepEqual(calls, [RDAP_HEALTH_PROBE_DOMAIN]);
  assert.equal(detail.domain, RDAP_HEALTH_PROBE_DOMAIN);
  assert.ok(detail.registrar); // parsed from the RDAP entities
  // Cache bypass: the probe writes nothing to the domain enrichment cache.
  assert.equal(pool.queries.length, 0);
});

test('testRdapConnection surfaces timeout errors from the client', async () => {
  const fetchFn = async () => { const e = new Error('timed out'); e.code = 'timeout'; throw e; };
  await assert.rejects(() => testRdapConnection(fakePool(), { fetchFn }), /timed out/);
});

test('runProviderHealthProbe skips unsupported providers', async () => {
  const res = await runProviderHealthProbe(fakePool(), 'not-a-provider', { source: 'scheduled' });
  assert.equal(res.ran, false);
  assert.equal(res.reason, 'unsupported_provider');
});

test('runProviderHealthProbe does not probe a disabled provider', async () => {
  // VirusTotal registry state reads threat_intel_provider_configs (enabled/api_key).
  const pool = fakePool({
    rowsFor: (sql) => (/threat_intel_provider_configs/.test(sql)
      ? [{ enabled: false, api_key: 'present' }]
      : [])
  });
  const res = await runProviderHealthProbe(pool, 'virustotal', { source: 'scheduled' });
  assert.equal(res.ran, false);
  assert.equal(res.reason, 'disabled');
  // No health row was written for a skipped provider.
  assert.ok(!pool.queries.some((q) => /INSERT INTO enrichment_provider_health/.test(q.sql)));
});

test('runProviderHealthProbe does not probe a provider missing required credentials', async () => {
  const saved = process.env.VIRUSTOTAL_API_KEY;
  delete process.env.VIRUSTOTAL_API_KEY;
  try {
    const pool = fakePool({
      rowsFor: (sql) => (/threat_intel_provider_configs/.test(sql)
        ? [{ enabled: true, api_key: null }]
        : [])
    });
    const res = await runProviderHealthProbe(pool, 'virustotal', { source: 'scheduled' });
    assert.equal(res.ran, false);
    assert.equal(res.reason, 'not_configured');
  } finally {
    if (saved !== undefined) process.env.VIRUSTOTAL_API_KEY = saved;
  }
});

test('ACTIVE_PROBE_PROVIDERS excludes the scheduled-operation provider (spamhaus)', () => {
  assert.ok(ACTIVE_PROBE_PROVIDERS.includes('rdap'));
  assert.ok(ACTIVE_PROBE_PROVIDERS.includes('virustotal'));
  assert.ok(!ACTIVE_PROBE_PROVIDERS.includes('spamhaus_drop'));
});
