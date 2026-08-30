import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_RANGE,
  RANGE_OPTIONS,
  IOC_TYPE_OPTIONS,
  TREND_SERIES,
  formatNumber,
  formatPercent,
  formatMs,
  formatDateLabel,
  buildDailyBuckets,
  mergeSeries,
  computeChartGeometry,
  summaryCards,
  hasAnyUsage,
  sortProviderRows,
  quotaView,
  providerFilterOptions,
  todayInTimeZone,
  daysAgoInTimeZone
} from './enrichmentUsage.js';

test('defaults: Last 30 Days is the default range', () => {
  assert.equal(DEFAULT_RANGE, 'last_30_days');
  assert.ok(RANGE_OPTIONS.find((o) => o.value === 'last_30_days' && o.label === 'Last 30 Days'));
  assert.equal(IOC_TYPE_OPTIONS[0].value, '');
  assert.deepEqual(TREND_SERIES.map((s) => s.key), ['request_count', 'external_call_count', 'cache_hit_count']);
});

test('formatters handle null/large values', () => {
  assert.equal(formatNumber(1240), '1,240');
  assert.equal(formatNumber(null), '—');
  assert.equal(formatPercent(24.8), '24.8%');
  assert.equal(formatPercent(null), '—');
  assert.equal(formatMs(420), '420 ms');
  assert.equal(formatMs(1500), '1.50 s');
  assert.equal(formatMs(null), '—');
  assert.equal(formatDateLabel('2026-08-12'), 'Aug 12');
  assert.equal(formatDateLabel('bad'), 'bad');
});

test('todayInTimeZone resolves the date in the given System Timezone (not UTC/local)', () => {
  // 22:30 UTC on Aug 12 is already Aug 13 in Istanbul (UTC+3) -> canonical "today" differs from UTC.
  const instant = new Date('2026-08-12T22:30:00.000Z');
  assert.equal(todayInTimeZone('UTC', instant), '2026-08-12');
  assert.equal(todayInTimeZone('Europe/Istanbul', instant), '2026-08-13');
  // Honolulu (UTC-10) is still Aug 12 at that instant
  assert.equal(todayInTimeZone('Pacific/Honolulu', instant), '2026-08-12');
  // invalid tz falls back to UTC rather than throwing
  assert.equal(todayInTimeZone('Not/AZone', instant), '2026-08-12');
});

test('daysAgoInTimeZone does calendar arithmetic from the System-Timezone today', () => {
  const instant = new Date('2026-08-12T22:30:00.000Z');
  assert.equal(daysAgoInTimeZone('Europe/Istanbul', 29, instant), '2026-07-15'); // from Aug 13
  assert.equal(daysAgoInTimeZone('UTC', 29, instant), '2026-07-14');             // from Aug 12
});

test('buildDailyBuckets produces an inclusive, bounded date span', () => {
  assert.deepEqual(buildDailyBuckets('2026-08-10', '2026-08-12'), ['2026-08-10', '2026-08-11', '2026-08-12']);
  assert.equal(buildDailyBuckets('2026-08-12', '2026-08-12').length, 1);
  assert.deepEqual(buildDailyBuckets('bad', 'x'), []);
});

test('mergeSeries zero-fills missing days and flags pre-collection days', () => {
  const merged = mergeSeries('2026-08-01', '2026-08-03', [
    { date: '2026-08-02', request_count: 5, external_call_count: 3, cache_hit_count: 2 }
  ], { collectionStartedOn: '2026-08-02' });
  assert.equal(merged.length, 3);
  assert.equal(merged[0].request_count, 0);
  assert.equal(merged[0].collected, false); // before collection start
  assert.equal(merged[1].request_count, 5);
  assert.equal(merged[1].collected, true);
  assert.equal(merged[2].collected, true); // on/after start, zero usage but collected
});

test('computeChartGeometry: transform maps counts to coordinates with a nice max', () => {
  const buckets = mergeSeries('2026-08-01', '2026-08-02', [
    { date: '2026-08-01', request_count: 0, external_call_count: 0, cache_hit_count: 0 },
    { date: '2026-08-02', request_count: 8, external_call_count: 5, cache_hit_count: 3 }
  ]);
  const geo = computeChartGeometry(buckets, TREND_SERIES, { width: 700, height: 300, padding: { top: 10, right: 10, bottom: 30, left: 40 } });
  assert.equal(geo.isEmpty, false);
  assert.equal(geo.maxY, 10); // niceMax(8) -> 10
  assert.equal(geo.lines.length, 3);
  const requests = geo.lines.find((l) => l.key === 'request_count');
  // first bucket value 0 sits on the baseline (bottom); second (8) sits higher (smaller y)
  assert.ok(requests.points[0].y > requests.points[1].y);
  // baseline y for value 0 == top + innerH
  const innerH = 300 - 10 - 30;
  assert.ok(Math.abs(requests.points[0].y - (10 + innerH)) < 0.5);
  assert.ok(geo.xTicks.length >= 1);
  assert.equal(geo.yTicks[0].value, 0);
});

test('computeChartGeometry: all-zero data is flagged empty with a non-zero axis', () => {
  const buckets = mergeSeries('2026-08-01', '2026-08-02', []);
  const geo = computeChartGeometry(buckets);
  assert.equal(geo.isEmpty, true);
  assert.equal(geo.maxY, 1); // avoids divide-by-zero
});

test('summaryCards renders the six required metrics in order', () => {
  const cards = summaryCards({
    request_count: 100, external_call_count: 60, cache_hit_count: 40,
    success_rate: 95, failure_count: 5, rate_limit_count: 2,
    cache_hit_rate: 40, avg_external_response_time_ms: 320
  });
  const primary = cards.filter((c) => !c.secondary).map((c) => c.label);
  assert.deepEqual(primary, ['Total Requests', 'External API Calls', 'Cache Hits', 'Success Rate', 'Failed Requests', 'Rate Limit Events']);
  assert.equal(cards.find((c) => c.key === 'external_call_count').value, '60');
  assert.equal(cards.find((c) => c.key === 'rate_limit_count').tone, 'warn');
  // secondary metrics present but flagged
  assert.ok(cards.find((c) => c.key === 'avg_external_response_time_ms').secondary);
});

test('summaryCards shows dashes (not fake zeros) when rates are unknown', () => {
  const cards = summaryCards({ request_count: 0, external_call_count: 0, cache_hit_count: 0, success_rate: null, failure_count: 0, rate_limit_count: 0, cache_hit_rate: null, avg_external_response_time_ms: null });
  assert.equal(cards.find((c) => c.key === 'success_rate').value, '—');
  assert.equal(cards.find((c) => c.key === 'avg_external_response_time_ms').value, '—');
  assert.equal(hasAnyUsage({ request_count: 0 }), false);
  assert.equal(hasAnyUsage({ request_count: 3 }), true);
});

test('sortProviderRows defaults to external calls descending', () => {
  const rows = [
    { provider_key: 'a', display_name: 'A', external_call_count: 2, request_count: 10 },
    { provider_key: 'b', display_name: 'B', external_call_count: 9, request_count: 9 }
  ];
  assert.deepEqual(sortProviderRows(rows).map((r) => r.provider_key), ['b', 'a']);
  assert.deepEqual(sortProviderRows(rows, 'request_count', 'desc').map((r) => r.provider_key), ['a', 'b']);
  assert.deepEqual(sortProviderRows(rows, 'display_name', 'asc').map((r) => r.provider_key), ['a', 'b']);
});

test('quotaView never invents data and formats a configured quota', () => {
  assert.deepEqual(quotaView(null), { state: 'unavailable', label: 'Quota unavailable' });
  assert.deepEqual(quotaView({ limit: 0 }), { state: 'unavailable', label: 'Quota unavailable' });
  const limitOnly = quotaView({ limit: 5000 });
  assert.equal(limitOnly.state, 'available');
  assert.equal(limitOnly.label, 'Limit 5,000');
  assert.equal(limitOnly.pct, null);
  const full = quotaView({ limit: 5000, used: 1240, used_pct: 24.8, window: 'monthly' });
  assert.equal(full.label, '1,240 / 5,000');
  assert.equal(full.pct, 24.8);
  assert.equal(full.barPct, 24.8);
  assert.equal(full.window, 'monthly');
});

test('providerFilterOptions prepends All Providers', () => {
  const opts = providerFilterOptions([{ provider_key: 'virustotal', display_name: 'VirusTotal' }]);
  assert.deepEqual(opts, [
    { value: '', label: 'All Providers' },
    { value: 'virustotal', label: 'VirusTotal' }
  ]);
});
