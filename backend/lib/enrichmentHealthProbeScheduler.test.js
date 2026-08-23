import test from 'node:test';
import assert from 'node:assert/strict';
import {
  nextProbeDelayMs,
  isProbeDue,
  healthProbeIntervalMs,
  runDueEnrichmentHealthProbes
} from './enrichmentHealthProbeScheduler.js';
import { healthRetryDelaysMs } from './enrichmentProviderHealthCheck.js';

const MIN = 60 * 1000;

test('never-checked providers are due immediately', () => {
  assert.equal(nextProbeDelayMs(null), 0);
  assert.equal(isProbeDue(null), true);
  assert.equal(isProbeDue({ status: 'healthy' /* no last_check_at */ }), true);
});

test('healthy providers re-probe on the 24h interval, not sooner', () => {
  const now = Date.now();
  const healthyRow = { status: 'healthy', last_check_at: new Date(now - 60 * MIN).toISOString() };
  assert.equal(nextProbeDelayMs(healthyRow), healthProbeIntervalMs());
  assert.equal(isProbeDue(healthyRow, now), false);

  const oldRow = { status: 'healthy', last_check_at: new Date(now - 25 * 60 * MIN).toISOString() };
  assert.equal(isProbeDue(oldRow, now), true);
});

test('transient failures follow the 5m then 30m retry ladder', () => {
  const [first, second] = healthRetryDelaysMs();
  const base = { status: 'degraded', error_category: 'network' };
  assert.equal(nextProbeDelayMs({ ...base, consecutive_failures: 1 }), first);
  assert.equal(nextProbeDelayMs({ ...base, consecutive_failures: 2 }), second);

  const now = Date.now();
  // 1 failure, checked 6 minutes ago -> past the 5m retry -> due.
  assert.equal(isProbeDue({ ...base, consecutive_failures: 1, last_check_at: new Date(now - 6 * MIN).toISOString() }, now), true);
  // 1 failure, checked 2 minutes ago -> not yet due.
  assert.equal(isProbeDue({ ...base, consecutive_failures: 1, last_check_at: new Date(now - 2 * MIN).toISOString() }, now), false);
});

test('auth failures and Unhealthy states fall back to the 24h cadence (no hammering)', () => {
  // Auth failure -> unhealthy, non-transient -> 24h.
  assert.equal(nextProbeDelayMs({ status: 'unhealthy', error_category: 'auth', consecutive_failures: 1 }), healthProbeIntervalMs());
  // Persistent transient failure that already escalated to unhealthy -> 24h.
  assert.equal(nextProbeDelayMs({ status: 'unhealthy', error_category: 'network', consecutive_failures: 3 }), healthProbeIntervalMs());
});

test('runDueEnrichmentHealthProbes yields to the advisory lock (no double-probe)', async () => {
  // Lock is held elsewhere: pg_try_advisory_lock returns false -> run is a no-op.
  const queries = [];
  const pool = {
    async connect() {
      return {
        async query(sql, params) {
          queries.push(sql);
          if (/pg_try_advisory_lock/.test(sql)) return { rows: [{ acquired: false }] };
          return { rows: [] };
        },
        release() {}
      };
    },
    async query() { return { rows: [] }; }
  };
  const res = await runDueEnrichmentHealthProbes(pool, { logger: { warn() {} } });
  assert.equal(res.locked, false);
  assert.deepEqual(res.probed, []);
  // It must not have read provider rows or run any probe while lock was denied.
  assert.ok(!queries.some((s) => /enrichment_provider_health/.test(s)));
});
