import test from 'node:test';
import assert from 'node:assert/strict';
import {
  USAGE_IOC_TYPES,
  normalizeUsageIocType,
  emptyUsageDelta,
  buildUsageDelta,
  sumUsageDeltas,
  usageDeltaHasData,
  buildUsageUpsert,
  writeEnrichmentUsage,
  recordEnrichmentUsage
} from './enrichmentUsageTelemetry.js';

test('normalizeUsageIocType collapses to the bounded set', () => {
  assert.equal(normalizeUsageIocType('ip'), 'ip');
  assert.equal(normalizeUsageIocType('IPv6'), 'ip');
  assert.equal(normalizeUsageIocType('ipv4'), 'ip');
  assert.equal(normalizeUsageIocType('domain'), 'domain');
  assert.equal(normalizeUsageIocType('hostname'), 'domain');
  assert.equal(normalizeUsageIocType('URL'), 'url');
  assert.equal(normalizeUsageIocType('sha256'), 'hash');
  assert.equal(normalizeUsageIocType('file_hash'), 'hash');
  assert.equal(normalizeUsageIocType('md5'), 'hash');
  assert.equal(normalizeUsageIocType(''), 'other');
  assert.equal(normalizeUsageIocType('weird'), 'other');
  for (const t of ['ip', 'domain', 'url', 'hash', 'other']) {
    assert.ok(USAGE_IOC_TYPES.includes(t));
  }
});

test('buildUsageDelta: successful external call counts request+external+success and latency', () => {
  const d = buildUsageDelta({ outcome: 'success', external: true, responseTimeMs: 123.6 });
  assert.equal(d.request_count, 1);
  assert.equal(d.external_call_count, 1);
  assert.equal(d.cache_hit_count, 0);
  assert.equal(d.success_count, 1);
  assert.equal(d.failure_count, 0);
  assert.equal(d.rate_limit_count, 0);
  assert.equal(d.total_external_response_time_ms, 124);
  assert.equal(d.external_response_count, 1);
});

test('buildUsageDelta: cache hit records no external call and no latency', () => {
  const d = buildUsageDelta({ outcome: 'success', external: false, cacheHit: true, responseTimeMs: 999 });
  assert.equal(d.request_count, 1);
  assert.equal(d.external_call_count, 0);
  assert.equal(d.cache_hit_count, 1);
  assert.equal(d.success_count, 1);
  // latency is external-only; a cache hit must never contribute provider latency
  assert.equal(d.total_external_response_time_ms, 0);
  assert.equal(d.external_response_count, 0);
});

test('buildUsageDelta: rate-limited external call is a failure + rate limit', () => {
  const d = buildUsageDelta({ outcome: 'failure', external: true, rateLimited: true, responseTimeMs: 50 });
  assert.equal(d.external_call_count, 1);
  assert.equal(d.failure_count, 1);
  assert.equal(d.rate_limit_count, 1);
  assert.equal(d.success_count, 0);
  assert.equal(d.external_response_count, 1);
});

test('buildUsageDelta: count>1 scales counters (bulk semantics)', () => {
  const d = buildUsageDelta({ outcome: 'success', external: true, count: 4, responseTimeMs: 10 });
  assert.equal(d.request_count, 4);
  assert.equal(d.external_call_count, 4);
  assert.equal(d.success_count, 4);
  assert.equal(d.external_response_count, 4);
});

test('buildUsageDelta: explicit count 0 yields an all-zero delta (bulk category with no items)', () => {
  const d = buildUsageDelta({ outcome: 'success', cacheHit: true, count: 0 });
  assert.equal(d.request_count, 0);
  assert.equal(d.cache_hit_count, 0);
  assert.equal(usageDeltaHasData(d), false);
});

test('sumUsageDeltas folds a mixed bulk into one delta', () => {
  const total = sumUsageDeltas([
    buildUsageDelta({ outcome: 'success', external: true, responseTimeMs: 100 }),
    buildUsageDelta({ outcome: 'success', cacheHit: true }),
    buildUsageDelta({ outcome: 'failure', external: true, rateLimited: true, responseTimeMs: 20 })
  ]);
  assert.equal(total.request_count, 3);
  assert.equal(total.external_call_count, 2);
  assert.equal(total.cache_hit_count, 1);
  assert.equal(total.success_count, 2);
  assert.equal(total.failure_count, 1);
  assert.equal(total.rate_limit_count, 1);
  assert.equal(total.external_response_count, 2);
  assert.equal(total.total_external_response_time_ms, 120);
});

test('usageDeltaHasData distinguishes empty from non-empty', () => {
  assert.equal(usageDeltaHasData(emptyUsageDelta()), false);
  assert.equal(usageDeltaHasData(null), false);
  assert.equal(usageDeltaHasData(buildUsageDelta({ outcome: 'success', external: true })), true);
});

test('buildUsageUpsert emits an additive ON CONFLICT upsert with ordered params', () => {
  const delta = buildUsageDelta({ outcome: 'success', external: true, responseTimeMs: 42 });
  const { sql, params } = buildUsageUpsert('virustotal', 'domain', delta);
  assert.match(sql, /INSERT INTO enrichment_usage_daily/);
  assert.match(sql, /ON CONFLICT \(bucket_date, provider_key, ioc_type\) DO UPDATE/);
  assert.match(sql, /request_count = enrichment_usage_daily\.request_count \+ EXCLUDED\.request_count/);
  // Buckets are dated in the canonical System Timezone (session tz) via CURRENT_DATE,
  // matching the read range + frontend "today".
  assert.match(sql, /VALUES \(CURRENT_DATE/);
  assert.equal(params[0], 'virustotal');
  assert.equal(params[1], 'domain');
  assert.equal(params[2], 1); // request_count
  assert.equal(params[3], 1); // external_call_count
});

test('writeEnrichmentUsage issues one upsert and normalizes the ioc type', async () => {
  const calls = [];
  const pool = { query: async (sql, params) => { calls.push({ sql, params }); return { rowCount: 1 }; } };
  const ok = await writeEnrichmentUsage(pool, {
    provider: 'virustotal',
    iocType: 'SHA256',
    delta: buildUsageDelta({ outcome: 'success', external: true, responseTimeMs: 10 })
  });
  assert.equal(ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].params[1], 'hash'); // normalized
});

test('writeEnrichmentUsage skips empty deltas without querying', async () => {
  let queried = false;
  const pool = { query: async () => { queried = true; return {}; } };
  const ok = await writeEnrichmentUsage(pool, { provider: 'virustotal', iocType: 'ip', delta: emptyUsageDelta() });
  assert.equal(ok, false);
  assert.equal(queried, false);
});

test('writeEnrichmentUsage never throws when the DB write fails', async () => {
  const pool = { query: async () => { throw new Error('db down'); } };
  const captured = [];
  const logger = { warn: (msg, fields) => captured.push({ msg, fields }) };
  const ok = await writeEnrichmentUsage(pool, {
    provider: 'virustotal',
    iocType: 'ip',
    delta: buildUsageDelta({ outcome: 'success', external: true }),
    logger
  });
  assert.equal(ok, false);
  assert.equal(captured.length, 1);
  assert.match(captured[0].fields.error, /db down/);
});

test('recordEnrichmentUsage is a thin wrapper over buildUsageDelta + write', async () => {
  const calls = [];
  const pool = { query: async (sql, params) => { calls.push(params); return {}; } };
  await recordEnrichmentUsage(pool, {
    provider: 'ipinfo_lite',
    iocType: 'ip',
    outcome: 'success',
    cacheHit: true
  });
  assert.equal(calls.length, 1);
  // cache hit => external_call_count param (index 3) is 0, cache_hit_count (index 4) is 1
  assert.equal(calls[0][3], 0);
  assert.equal(calls[0][4], 1);
});

test('recordEnrichmentUsage tolerates a missing pool', async () => {
  const ok = await recordEnrichmentUsage(null, { provider: 'x', iocType: 'ip', outcome: 'success' });
  assert.equal(ok, false);
});
