import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deleteFinishedIntegrationRunsBatch,
  deleteTerminalQueueJobsBatch,
  deleteStaleIpGeoCacheBatch,
  runOperationalHistoryRetentionCleanup,
  resolveOperationalRetentionDays,
  INTEGRATION_RUN_RETENTION_DEFAULT_DAYS,
  IOC_IP_GEO_CACHE_TTL_DEFAULT_DAYS
} from './operationalHistoryRetention.js';

test('resolveOperationalRetentionDays defaults', () => {
  const prev = {
    INTEGRATION_RUN_RETENTION_DAYS: process.env.INTEGRATION_RUN_RETENTION_DAYS,
    INTEGRATION_QUEUE_JOB_RETENTION_DAYS: process.env.INTEGRATION_QUEUE_JOB_RETENTION_DAYS,
    IOC_IP_GEO_CACHE_TTL_DAYS: process.env.IOC_IP_GEO_CACHE_TTL_DAYS
  };
  try {
    delete process.env.INTEGRATION_RUN_RETENTION_DAYS;
    delete process.env.INTEGRATION_QUEUE_JOB_RETENTION_DAYS;
    delete process.env.IOC_IP_GEO_CACHE_TTL_DAYS;
    const d = resolveOperationalRetentionDays();
    assert.equal(d.runDays, INTEGRATION_RUN_RETENTION_DEFAULT_DAYS);
    assert.equal(d.queueDays, INTEGRATION_RUN_RETENTION_DEFAULT_DAYS);
    assert.equal(d.geoDays, IOC_IP_GEO_CACHE_TTL_DEFAULT_DAYS);
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});

test('deleteFinishedIntegrationRunsBatch uses strict older-than cutoff params', async () => {
  let captured = null;
  const db = {
    async query(sql, params) {
      captured = { sql: String(sql), params };
      return { rowCount: 3 };
    }
  };
  const n = await deleteFinishedIntegrationRunsBatch(db, { days: 90, batchSize: 500 });
  assert.equal(n, 3);
  assert.match(captured.sql, /integration_runs/);
  assert.match(captured.sql, /status <> 'running'/);
  assert.match(captured.sql, /make_interval\(days => \$1::int\)/);
  assert.deepEqual(captured.params, [90, 500]);
});

test('deleteTerminalQueueJobsBatch targets terminal statuses only', async () => {
  let captured = null;
  const db = {
    async query(sql, params) {
      captured = { sql: String(sql), params };
      return { rowCount: 1 };
    }
  };
  await deleteTerminalQueueJobsBatch(db, { days: 90, batchSize: 100 });
  assert.match(captured.sql, /status IN \('success', 'failed', 'skipped'\)/);
  assert.deepEqual(captured.params, [90, 100]);
});

test('deleteStaleIpGeoCacheBatch filters on updated_at', async () => {
  let captured = null;
  const db = {
    async query(sql, params) {
      captured = { sql: String(sql), params };
      return { rowCount: 4 };
    }
  };
  const n = await deleteStaleIpGeoCacheBatch(db, { days: 30, batchSize: 200 });
  assert.equal(n, 4);
  assert.match(captured.sql, /ioc_ip_geo_cache/);
  assert.match(captured.sql, /updated_at </);
  assert.deepEqual(captured.params, [30, 200]);
});

/**
 * Fake pool: each table is an array of ageDays. Deletes remove rows with age > days
 * (strictly older), up to batchSize per call.
 */
function fakeOpsPool({ runs = [], jobs = [], geo = [], lockAcquired = true } = {}) {
  const store = { runs: [...runs], jobs: [...jobs], geo: [...geo] };
  const calls = { runBatches: 0, jobBatches: 0, geoBatches: 0, unlocked: false };

  async function query(sql, params = []) {
    const s = String(sql);
    if (s.includes('pg_try_advisory_lock')) return { rows: [{ ok: lockAcquired }] };
    if (s.includes('pg_advisory_unlock')) {
      calls.unlocked = true;
      return { rows: [{}] };
    }
    if (s.includes('DELETE FROM integration_runs')) {
      const days = Number(params[0]);
      const batchSize = Number(params[1]);
      const doomed = [];
      for (let i = 0; i < store.runs.length && doomed.length < batchSize; i += 1) {
        if (store.runs[i] > days) doomed.push(i);
      }
      const set = new Set(doomed);
      store.runs = store.runs.filter((_, i) => !set.has(i));
      calls.runBatches += 1;
      return { rowCount: doomed.length };
    }
    if (s.includes('DELETE FROM integration_queue_jobs')) {
      const days = Number(params[0]);
      const batchSize = Number(params[1]);
      const doomed = [];
      for (let i = 0; i < store.jobs.length && doomed.length < batchSize; i += 1) {
        if (store.jobs[i] > days) doomed.push(i);
      }
      const set = new Set(doomed);
      store.jobs = store.jobs.filter((_, i) => !set.has(i));
      calls.jobBatches += 1;
      return { rowCount: doomed.length };
    }
    if (s.includes('DELETE FROM ioc_ip_geo_cache')) {
      const days = Number(params[0]);
      const batchSize = Number(params[1]);
      const doomed = [];
      for (let i = 0; i < store.geo.length && doomed.length < batchSize; i += 1) {
        if (store.geo[i] > days) doomed.push(i);
      }
      const set = new Set(doomed);
      store.geo = store.geo.filter((_, i) => !set.has(i));
      calls.geoBatches += 1;
      return { rowCount: doomed.length };
    }
    throw new Error(`unexpected sql: ${s}`);
  }

  return {
    store,
    calls,
    async connect() {
      return { query, release() {} };
    },
    query
  };
}

const silentLogger = { info() {}, log() {}, warn() {}, error() {} };

test('ops retention drains multiple batches and keeps boundary-age rows', async () => {
  // age === retentionDays must survive (strictly older only); age 91 deleted.
  const pool = fakeOpsPool({
    runs: [91, 91, 91, 90, 10],
    jobs: [100, 90],
    geo: [40, 30, 5]
  });

  const prevRun = process.env.INTEGRATION_RUN_RETENTION_DAYS;
  const prevQueue = process.env.INTEGRATION_QUEUE_JOB_RETENTION_DAYS;
  const prevGeo = process.env.IOC_IP_GEO_CACHE_TTL_DAYS;
  try {
    process.env.INTEGRATION_RUN_RETENTION_DAYS = '90';
    process.env.INTEGRATION_QUEUE_JOB_RETENTION_DAYS = '90';
    process.env.IOC_IP_GEO_CACHE_TTL_DAYS = '30';

    const res = await runOperationalHistoryRetentionCleanup(pool, {
      batchSize: 2,
      minIntervalMs: 0,
      logger: silentLogger
    });

    assert.equal(res.skipped, false);
    assert.equal(res.runs.deleted, 3);
    assert.equal(res.runs.batches, 2); // 2 + 1
    assert.deepEqual(pool.store.runs, [90, 10]);
    assert.equal(res.jobs.deleted, 1);
    assert.deepEqual(pool.store.jobs, [90]);
    assert.equal(res.geo.deleted, 1);
    assert.deepEqual(pool.store.geo, [30, 5]);
    assert.equal(pool.calls.unlocked, true);
  } finally {
    if (prevRun === undefined) delete process.env.INTEGRATION_RUN_RETENTION_DAYS;
    else process.env.INTEGRATION_RUN_RETENTION_DAYS = prevRun;
    if (prevQueue === undefined) delete process.env.INTEGRATION_QUEUE_JOB_RETENTION_DAYS;
    else process.env.INTEGRATION_QUEUE_JOB_RETENTION_DAYS = prevQueue;
    if (prevGeo === undefined) delete process.env.IOC_IP_GEO_CACHE_TTL_DAYS;
    else process.env.IOC_IP_GEO_CACHE_TTL_DAYS = prevGeo;
  }
});

test('ops retention skips when advisory lock is held', async () => {
  const pool = fakeOpsPool({ runs: [999], lockAcquired: false });
  const res = await runOperationalHistoryRetentionCleanup(pool, {
    batchSize: 10,
    minIntervalMs: 0,
    logger: silentLogger
  });
  assert.equal(res.skipped, true);
  assert.equal(res.reason, 'locked');
  assert.equal(pool.calls.runBatches, 0);
});

test('ops retention not_due gate respects lastRunAtMs', async () => {
  const pool = fakeOpsPool({ runs: [999] });
  const res = await runOperationalHistoryRetentionCleanup(pool, {
    batchSize: 10,
    minIntervalMs: 24 * 3600 * 1000,
    lastRunAtMs: Date.now(),
    logger: silentLogger
  });
  assert.equal(res.skipped, true);
  assert.equal(res.reason, 'not_due');
});
