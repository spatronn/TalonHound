import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveRange,
  resolveProviderFilter,
  resolveIocTypeFilter,
  parseUsageQuery,
  daysBetween,
  MAX_RANGE_DAYS,
  buildProviderBreakdownQuery,
  buildSeriesQuery,
  buildTypeBreakdownQuery,
  buildCollectionStartQuery,
  deriveMetrics,
  summarizeProviderRows,
  shapeProviderBreakdown,
  shapeTypeBreakdown,
  shapeSeries,
  normalizeProviderQuota
} from './enrichmentUsageQuery.js';

// Canonical "today" is always supplied by the caller (route: SELECT CURRENT_DATE,
// i.e. today in the System Timezone). Tests pass it explicitly as a date string.
const TODAY = '2026-08-12';

test('resolveRange defaults to last 30 days (inclusive)', () => {
  const r = resolveRange({}, TODAY);
  assert.equal(r.ok, true);
  assert.equal(r.preset, 'last_30_days');
  assert.equal(r.to, '2026-08-12');
  assert.equal(r.from, '2026-07-14');
  assert.equal(daysBetween(r.from, r.to), 30);
});

test('resolveRange today / last_7_days presets', () => {
  assert.deepEqual(resolveRange({ range: 'today' }, TODAY), { ok: true, from: '2026-08-12', to: '2026-08-12', preset: 'today' });
  const seven = resolveRange({ range: 'last_7_days' }, TODAY);
  assert.equal(seven.from, '2026-08-06');
  assert.equal(daysBetween(seven.from, seven.to), 7);
});

test('resolveRange custom validates presence, format, order and max span', () => {
  assert.equal(resolveRange({ range: 'custom' }, TODAY).ok, false);
  assert.equal(resolveRange({ range: 'custom', from: '2026-13-01', to: '2026-08-01' }, TODAY).ok, false);
  assert.equal(resolveRange({ range: 'custom', from: '2026-08-10', to: '2026-08-01' }, TODAY).ok, false);
  const tooWide = resolveRange({ range: 'custom', from: '2024-01-01', to: '2026-08-01' }, TODAY);
  assert.equal(tooWide.ok, false);
  assert.match(tooWide.error, new RegExp(String(MAX_RANGE_DAYS)));
  const good = resolveRange({ range: 'custom', from: '2026-08-01', to: '2026-08-10' }, TODAY);
  assert.deepEqual(good, { ok: true, from: '2026-08-01', to: '2026-08-10', preset: 'custom' });
});

test('resolveRange rejects unknown preset', () => {
  assert.equal(resolveRange({ range: 'last_year' }, TODAY).ok, false);
});

test('resolveProviderFilter: all/empty pass through, unknown rejected', () => {
  assert.deepEqual(resolveProviderFilter('', ['virustotal']), { ok: true, provider: null });
  assert.deepEqual(resolveProviderFilter('all', ['virustotal']), { ok: true, provider: null });
  assert.deepEqual(resolveProviderFilter('VirusTotal', ['virustotal']), { ok: true, provider: 'virustotal' });
  assert.equal(resolveProviderFilter('nope', ['virustotal']).ok, false);
});

test('resolveIocTypeFilter validates against the bounded set', () => {
  assert.deepEqual(resolveIocTypeFilter('all'), { ok: true, iocType: null });
  assert.deepEqual(resolveIocTypeFilter('IP'), { ok: true, iocType: 'ip' });
  assert.equal(resolveIocTypeFilter('emofile').ok, false);
});

test('parseUsageQuery composes filters and reports the first error with a 400', () => {
  const ok = parseUsageQuery({ range: 'today', provider: 'virustotal', iocType: 'domain' }, { knownProviders: ['virustotal'], today: TODAY });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.params, { from: '2026-08-12', to: '2026-08-12', preset: 'today', provider: 'virustotal', iocType: 'domain' });

  const bad = parseUsageQuery({ provider: 'ghost' }, { knownProviders: ['virustotal'], today: TODAY });
  assert.equal(bad.ok, false);
  assert.equal(bad.status, 400);

  const badRange = parseUsageQuery({ range: 'custom', from: 'x', to: 'y' }, { knownProviders: [], today: TODAY });
  assert.equal(badRange.ok, false);
  assert.equal(badRange.status, 400);
});

test('parseUsageQuery accepts snake_case ioc_type alias', () => {
  const r = parseUsageQuery({ ioc_type: 'hash' }, { knownProviders: [], today: TODAY });
  assert.equal(r.ok, true);
  assert.equal(r.params.iocType, 'hash');
});

test('SQL builders parameterize the range and optional filters', () => {
  const prov = buildProviderBreakdownQuery({ from: '2026-08-01', to: '2026-08-10', iocType: 'ip' });
  assert.match(prov.sql, /GROUP BY provider_key/);
  assert.match(prov.sql, /bucket_date BETWEEN \$1 AND \$2/);
  assert.match(prov.sql, /ioc_type = \$3/);
  assert.deepEqual(prov.params, ['2026-08-01', '2026-08-10', 'ip']);
  // provider breakdown must NOT filter by provider (it groups all of them)
  assert.doesNotMatch(prov.sql, /provider_key = \$/);

  const series = buildSeriesQuery({ from: '2026-08-01', to: '2026-08-10', provider: 'virustotal' });
  assert.match(series.sql, /GROUP BY bucket_date/);
  assert.match(series.sql, /ORDER BY bucket_date ASC/);
  assert.match(series.sql, /provider_key = \$3/);
  assert.deepEqual(series.params, ['2026-08-01', '2026-08-10', 'virustotal']);

  const types = buildTypeBreakdownQuery({ from: '2026-08-01', to: '2026-08-10', provider: 'virustotal' });
  assert.match(types.sql, /GROUP BY ioc_type/);
  assert.deepEqual(types.params, ['2026-08-01', '2026-08-10', 'virustotal']);

  assert.match(buildCollectionStartQuery().sql, /MIN\(bucket_date\)/);
});

test('deriveMetrics computes rates and avg latency defensively', () => {
  const m = deriveMetrics({
    request_count: 10, external_call_count: 6, cache_hit_count: 4,
    success_count: 8, failure_count: 2, rate_limit_count: 1,
    total_external_response_time_ms: 600, external_response_count: 6
  });
  assert.equal(m.cache_hit_rate, 40);
  assert.equal(m.success_rate, 80);
  assert.equal(m.avg_external_response_time_ms, 100);

  const zero = deriveMetrics({});
  assert.equal(zero.cache_hit_rate, null);
  assert.equal(zero.success_rate, null);
  assert.equal(zero.avg_external_response_time_ms, null);
});

test('summarizeProviderRows sums across providers', () => {
  const s = summarizeProviderRows([
    { request_count: 5, external_call_count: 3, cache_hit_count: 2, success_count: 4, failure_count: 1, rate_limit_count: 0, total_external_response_time_ms: 300, external_response_count: 3 },
    { request_count: 5, external_call_count: 5, cache_hit_count: 0, success_count: 5, failure_count: 0, rate_limit_count: 2, total_external_response_time_ms: 500, external_response_count: 5 }
  ]);
  assert.equal(s.request_count, 10);
  assert.equal(s.external_call_count, 8);
  assert.equal(s.rate_limit_count, 2);
  assert.equal(s.avg_external_response_time_ms, 100);
});

test('shapeProviderBreakdown merges registry, surfaces zero-usage and unknown providers, sorts by external desc', () => {
  const rows = [
    { provider_key: 'virustotal', request_count: 10, external_call_count: 7, cache_hit_count: 3, success_count: 9, failure_count: 1, rate_limit_count: 1, total_external_response_time_ms: 700, external_response_count: 7 },
    { provider_key: 'legacy_gone', request_count: 2, external_call_count: 2, cache_hit_count: 0, success_count: 2, failure_count: 0, rate_limit_count: 0, total_external_response_time_ms: 0, external_response_count: 0 }
  ];
  const registry = [
    { key: 'virustotal', displayName: 'VirusTotal', enabled: true, configured: true },
    { key: 'abuseipdb', displayName: 'AbuseIPDB', enabled: false, configured: false }
  ];
  const out = shapeProviderBreakdown(rows, registry);
  assert.equal(out[0].provider_key, 'virustotal'); // most external calls first
  const abuse = out.find((p) => p.provider_key === 'abuseipdb');
  assert.equal(abuse.request_count, 0);       // zero-usage known provider still present
  assert.equal(abuse.enabled, false);
  const legacy = out.find((p) => p.provider_key === 'legacy_gone');
  assert.equal(legacy.known, false);          // recorded but not in registry (renamed/removed)
  assert.equal(legacy.display_name, 'legacy_gone');
});

test('shapeTypeBreakdown returns bounded types in stable order', () => {
  const out = shapeTypeBreakdown([
    { ioc_type: 'hash', request_count: 3, external_call_count: 3, cache_hit_count: 0, success_count: 3, failure_count: 0, rate_limit_count: 0, total_external_response_time_ms: 0, external_response_count: 0 },
    { ioc_type: 'ip', request_count: 5, external_call_count: 2, cache_hit_count: 3, success_count: 5, failure_count: 0, rate_limit_count: 0, total_external_response_time_ms: 0, external_response_count: 0 }
  ]);
  assert.deepEqual(out.map((t) => t.ioc_type), ['ip', 'hash']); // USAGE_IOC_TYPES order
});

test('normalizeProviderQuota returns null unless a reliable limit is configured', () => {
  assert.equal(normalizeProviderQuota(null), null);
  assert.equal(normalizeProviderQuota({}), null);
  assert.equal(normalizeProviderQuota({ used: 100 }), null); // used without limit is not a quota
  assert.equal(normalizeProviderQuota({ limit: 0 }), null);
  assert.deepEqual(normalizeProviderQuota({ limit: 5000 }), {
    limit: 5000, used: null, used_pct: null, window: null, source: 'configured'
  });
  assert.deepEqual(normalizeProviderQuota({ limit: 5000, used: 1240, window: 'monthly', source: 'api' }), {
    limit: 5000, used: 1240, used_pct: 24.8, window: 'monthly', source: 'api'
  });
});

test('shapeSeries normalizes rows to plain counter objects', () => {
  const out = shapeSeries([{ date: '2026-08-01', request_count: '4', external_call_count: '2', cache_hit_count: '2', success_count: '4', failure_count: '0', rate_limit_count: '0' }]);
  assert.deepEqual(out, [{ date: '2026-08-01', request_count: 4, external_call_count: 2, cache_hit_count: 2, success_count: 4, failure_count: 0, rate_limit_count: 0 }]);
});
