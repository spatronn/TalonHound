import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeIocListStatsPayload,
  formatIocListStatsApiResponse,
  queueIocListStatsRefresh,
  queueIocListStatsRefreshIfMissing,
  runIocListStatsNightlyTick,
  shouldRunIocListStatsNightly,
  resolveIocListStatsSchedule,
  acquireIocListStatsRefreshLock,
  resolveIocListStatsRefreshInProgress,
  isIocListStatsRefreshInProgress,
  resetIocListStatsRefreshStateForTests,
  IOC_STATS_RECALCULATION_IN_PROGRESS,
  IOC_LIST_STATS_REFRESH_LOCK_NAME,
  IOC_LIST_STATS_DEFAULT_CRON,
  IOC_LIST_STATS_DEFAULT_TIMEZONE,
  IOC_LIST_STATS_STALE_AFTER_MS
} from './iocListStatsSnapshot.js';
import { HASHTEXT_ADVISORY_LOCK_NAMES } from './advisoryLocks.js';
import { buildIocListPagination } from './iocListPagination.js';
import { ROLES } from './rbac.js';

test('normalizeIocListStatsPayload aggregates hash types and top sources', () => {
  const payload = normalizeIocListStatsPayload({
    total: 1600000,
    by_type: [
      { observable_type: 'ip', count: 900000 },
      { observable_type: 'md5', count: 100000 },
      { observable_type: 'sha256', count: 50000 },
      { observable_type: 'domain', count: 200000 }
    ],
    by_source: [
      { source_name: 'URLhaus:abuse.ch', count: 400000 },
      { source_name: 'manual-smoke', count: 1000 }
    ]
  });

  assert.equal(payload.total_records, 1600000);
  assert.equal(payload.by_type.find((x) => x.observable_type === 'ip')?.count, 900000);
  assert.equal(payload.by_type.find((x) => x.observable_type === 'hash')?.count, 150000);
  assert.equal(payload.top_sources.length, 2);
});

test('nightly schedule defaults to 03:00 Europe/Istanbul', () => {
  const prevCron = process.env.IOC_LIST_STATS_CRON;
  const prevTz = process.env.IOC_LIST_STATS_TIMEZONE;
  delete process.env.IOC_LIST_STATS_CRON;
  delete process.env.IOC_LIST_STATS_TIMEZONE;
  delete process.env.IOC_LIST_STATS_CRON_TIMEZONE;
  try {
    const s = resolveIocListStatsSchedule();
    assert.equal(s.cron, IOC_LIST_STATS_DEFAULT_CRON);
    assert.equal(s.cron, '0 3 * * *');
    assert.equal(s.timezone, IOC_LIST_STATS_DEFAULT_TIMEZONE);
    assert.equal(s.timezone, 'Europe/Istanbul');
  } finally {
    if (prevCron == null) delete process.env.IOC_LIST_STATS_CRON;
    else process.env.IOC_LIST_STATS_CRON = prevCron;
    if (prevTz == null) delete process.env.IOC_LIST_STATS_TIMEZONE;
    else process.env.IOC_LIST_STATS_TIMEZONE = prevTz;
  }
});

test('shouldRunIocListStatsNightly matches 03:00 Istanbul without double-firing the minute', () => {
  resetIocListStatsRefreshStateForTests();
  // 2026-10-05 00:00 UTC == 03:00 Europe/Istanbul
  const at = new Date('2026-10-05T00:00:30.000Z');
  assert.equal(shouldRunIocListStatsNightly(at, { lastMinuteKey: null }), true);
  assert.equal(
    shouldRunIocListStatsNightly(at, { lastMinuteKey: '20261005T0000Z' }),
    false
  );
  // One hour earlier is 02:00 Istanbul — must not match.
  assert.equal(
    shouldRunIocListStatsNightly(new Date('2026-10-04T23:00:30.000Z'), { lastMinuteKey: null }),
    false
  );
});

test('stale threshold is display-only overnight window (not 6h)', () => {
  assert.ok(IOC_LIST_STATS_STALE_AFTER_MS >= 24 * 60 * 60 * 1000);
  assert.ok(IOC_LIST_STATS_STALE_AFTER_MS < 48 * 60 * 60 * 1000);
});

test('buildIocListPagination uses browse cap when global total unknown', () => {
  const p = buildIocListPagination({
    mode: 'browse',
    globalTotalUnknown: true,
    page: 1,
    pageSize: 25,
    statusFilter: 'active'
  });
  assert.equal(p.global_total, null);
  assert.equal(p.listed_items, 2000);
  assert.equal(p.is_capped, true);
});

test('buildIocListPagination still uses snapshot global total when provided', () => {
  const p = buildIocListPagination({
    mode: 'browse',
    globalTotal: 1672730,
    page: 2,
    pageSize: 25,
    statusFilter: 'active'
  });
  assert.equal(p.global_total, 1672730);
  assert.equal(p.listed_items, 2000);
  assert.equal(p.is_capped, true);
});

test('ioc-list-stats-refresh lock name is registered in advisory lock inventory', () => {
  assert.ok(HASHTEXT_ADVISORY_LOCK_NAMES.includes(IOC_LIST_STATS_REFRESH_LOCK_NAME));
});

test('formatIocListStatsApiResponse accepts refresh_in_progress override', () => {
  const missing = formatIocListStatsApiResponse(null, { refresh_in_progress: true });
  assert.equal(missing.refresh_in_progress, true);
  assert.equal(missing.missing, true);

  const present = formatIocListStatsApiResponse({
    payload: { total: 1, by_type: [], top_sources: [] },
    calculated_at: '2026-01-01T00:00:00.000Z',
    stale: false,
    refresh_in_progress: false
  }, { refresh_in_progress: true });
  assert.equal(present.refresh_in_progress, true);
  assert.equal(present.total, 1);
});

/**
 * Mock pool that simulates a single session advisory lock plus snapshot upserts.
 */
function createLockAwarePool({ failRefresh = false, holdMs = 0 } = {}) {
  let lockHeld = false;
  const events = [];

  function makeClient(tag) {
    return {
      async query(sql, params) {
        const s = String(sql);
        if (s.includes('pg_try_advisory_lock')) {
          events.push(`${tag}:try_lock`);
          if (lockHeld) return { rows: [{ ok: false }] };
          lockHeld = true;
          return { rows: [{ ok: true }] };
        }
        if (s.includes('pg_advisory_unlock')) {
          events.push(`${tag}:unlock`);
          lockHeld = false;
          return { rows: [{ ok: true }] };
        }
        if (s.includes('SET LOCAL')) {
          events.push(`${tag}:set_timeout`);
          return { rows: [] };
        }
        if (s.includes('INSERT INTO ioc_list_stats_snapshots')) {
          events.push(`${tag}:upsert`);
          if (failRefresh) throw new Error('refresh boom');
          return { rows: [] };
        }
        throw new Error(`unexpected client query (${tag}): ${s.slice(0, 80)}`);
      },
      release(err) {
        events.push(err ? `${tag}:release_err` : `${tag}:release`);
      }
    };
  }

  const pool = {
    _lockHeld: () => lockHeld,
    _events: events,
    async connect() {
      events.push('connect');
      return makeClient(`c${events.filter((e) => e === 'connect').length}`);
    },
    async query() {
      throw new Error('pool.query should not be used by refresh path under test');
    }
  };

  async function fetchStats() {
    events.push('fetch_stats');
    if (holdMs > 0) await new Promise((r) => setTimeout(r, holdMs));
    if (failRefresh) {
      // failure happens on upsert after fetch in some tests; allow fetch to succeed
    }
    return {
      total: 42,
      by_type: [{ observable_type: 'ip', count: 42 }],
      by_source: [{ source_name: 't', count: 42 }]
    };
  }

  return { pool, fetchStats, events, isLockHeld: () => lockHeld };
}

test('queueIocListStatsRefresh succeeds and releases lock', async () => {
  resetIocListStatsRefreshStateForTests();
  const { pool, fetchStats, isLockHeld } = createLockAwarePool();
  const result = await queueIocListStatsRefresh(pool, { fetchStats });
  assert.equal(result.queued, true);
  assert.equal(isIocListStatsRefreshInProgress(), true);

  // Wait for background work to finish.
  await new Promise((r) => setTimeout(r, 30));
  for (let i = 0; i < 40 && isIocListStatsRefreshInProgress(); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(isIocListStatsRefreshInProgress(), false);
  assert.equal(isLockHeld(), false);
});

test('concurrent second recalculation does not start and returns in-progress code', async () => {
  resetIocListStatsRefreshStateForTests();
  const { pool, fetchStats, events } = createLockAwarePool({ holdMs: 80 });

  const first = await queueIocListStatsRefresh(pool, { fetchStats });
  assert.equal(first.queued, true);

  const second = await queueIocListStatsRefresh(pool, { fetchStats });
  assert.equal(second.queued, false);
  assert.equal(second.in_progress, true);
  assert.equal(second.code, IOC_STATS_RECALCULATION_IN_PROGRESS);

  const fetchCount = events.filter((e) => e === 'fetch_stats').length;
  assert.equal(fetchCount, 1);

  for (let i = 0; i < 40 && isIocListStatsRefreshInProgress(); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(isIocListStatsRefreshInProgress(), false);
});

test('lock is released after calculation failure', async () => {
  resetIocListStatsRefreshStateForTests();
  const { pool, fetchStats, isLockHeld, events } = createLockAwarePool({ failRefresh: true });

  const result = await queueIocListStatsRefresh(pool, { fetchStats });
  assert.equal(result.queued, true);

  for (let i = 0; i < 40 && isIocListStatsRefreshInProgress(); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(isIocListStatsRefreshInProgress(), false);
  assert.equal(isLockHeld(), false);
  assert.ok(events.some((e) => e.endsWith(':unlock')));
});

test('advisory lock held by another session blocks queue (scheduled+manual share guard)', async () => {
  resetIocListStatsRefreshStateForTests();
  const { pool, fetchStats, isLockHeld } = createLockAwarePool({ holdMs: 60 });

  // Simulate scheduled tick acquiring first.
  const scheduled = await queueIocListStatsRefresh(pool, { fetchStats });
  assert.equal(scheduled.queued, true);

  // Manual request while scheduled holds the lock / in-process mutex.
  const manual = await queueIocListStatsRefresh(pool, { fetchStats });
  assert.equal(manual.queued, false);
  assert.equal(manual.code, IOC_STATS_RECALCULATION_IN_PROGRESS);

  for (let i = 0; i < 40 && isIocListStatsRefreshInProgress(); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(isLockHeld(), false);

  // After release, a new manual request can start.
  const again = await queueIocListStatsRefresh(pool, { fetchStats });
  assert.equal(again.queued, true);
  for (let i = 0; i < 40 && isIocListStatsRefreshInProgress(); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
});

test('acquireIocListStatsRefreshLock returns release no-op when not acquired', async () => {
  resetIocListStatsRefreshStateForTests();
  let lockHeld = true;
  const pool = {
    async connect() {
      return {
        async query(sql) {
          if (String(sql).includes('pg_try_advisory_lock')) {
            return { rows: [{ ok: !lockHeld }] };
          }
          if (String(sql).includes('pg_advisory_unlock')) {
            lockHeld = false;
            return { rows: [{ ok: true }] };
          }
          return { rows: [] };
        },
        release() {}
      };
    }
  };
  const lock = await acquireIocListStatsRefreshLock(pool);
  assert.equal(lock.acquired, false);
  await lock.release();
});

test('resolveIocListStatsRefreshInProgress probes advisory lock', async () => {
  resetIocListStatsRefreshStateForTests();
  let lockHeld = false;
  const pool = {
    async connect() {
      return {
        async query(sql) {
          if (String(sql).includes('pg_try_advisory_lock')) {
            if (lockHeld) return { rows: [{ ok: false }] };
            lockHeld = true;
            return { rows: [{ ok: true }] };
          }
          if (String(sql).includes('pg_advisory_unlock')) {
            lockHeld = false;
            return { rows: [{ ok: true }] };
          }
          return { rows: [] };
        },
        release() {}
      };
    }
  };
  assert.equal(await resolveIocListStatsRefreshInProgress(pool), false);
  lockHeld = true;
  assert.equal(await resolveIocListStatsRefreshInProgress(pool), true);
});

test('POST /api/ioc/stats/refresh authorization remains admin+analyst only', async () => {
  const { readFile } = await import('node:fs/promises');
  const { fileURLToPath } = await import('node:url');
  const { dirname, join } = await import('node:path');
  const here = dirname(fileURLToPath(import.meta.url));
  const serverSrc = await readFile(join(here, '../server.js'), 'utf8');
  assert.match(
    serverSrc,
    /app\.post\(\s*'\/api\/ioc\/stats\/refresh'\s*,\s*requireRole\(\s*ROLES\.ADMIN\s*,\s*ROLES\.ANALYST\s*\)/
  );
  assert.equal(ROLES.READONLY, 'readonly');
  assert.notEqual(ROLES.READONLY, ROLES.ADMIN);
});

test('queueIocListStatsRefreshIfMissing does not recompute when snapshot exists', async () => {
  resetIocListStatsRefreshStateForTests();
  let refreshQueued = false;
  const pool = {
    async query(sql) {
      if (String(sql).includes('FROM ioc_list_stats_snapshots')) {
        return {
          rows: [{
            snapshot_key: 'global_active_ioc_stats',
            payload: { total: 10, total_records: 10, by_type: [], top_sources: [] },
            calculated_at: new Date(),
            updated_at: new Date()
          }]
        };
      }
      throw new Error(`unexpected pool query: ${String(sql).slice(0, 80)}`);
    },
    async connect() {
      refreshQueued = true;
      throw new Error('must not acquire lock when snapshot exists');
    }
  };
  const result = await queueIocListStatsRefreshIfMissing(pool);
  assert.equal(result.queued, false);
  assert.equal(result.missing, false);
  assert.equal(refreshQueued, false);
});

test('queueIocListStatsRefreshIfMissing queues when snapshot missing', async () => {
  resetIocListStatsRefreshStateForTests();
  const { pool, fetchStats } = createLockAwarePool();
  // Override pool.query used by getIocListStatsSnapshot (missing row).
  pool.query = async (sql) => {
    if (String(sql).includes('FROM ioc_list_stats_snapshots')) {
      return { rows: [] };
    }
    throw new Error(`unexpected pool query: ${String(sql).slice(0, 80)}`);
  };
  const result = await queueIocListStatsRefreshIfMissing(pool, { fetchStats });
  assert.equal(result.queued, true);
  assert.equal(result.missing, true);
  for (let i = 0; i < 40 && isIocListStatsRefreshInProgress(); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
});

test('runIocListStatsNightlyTick queues only on cron match and dedupes the minute', async () => {
  resetIocListStatsRefreshStateForTests();
  const { pool, fetchStats, events } = createLockAwarePool({ holdMs: 20 });
  const at = new Date('2026-10-05T00:00:10.000Z'); // 03:00 Istanbul

  const first = await runIocListStatsNightlyTick(pool, { now: at, fetchStats });
  assert.equal(first.matched, true);
  assert.equal(first.queued, true);

  const second = await runIocListStatsNightlyTick(pool, { now: at, fetchStats });
  assert.equal(second.matched, false);
  assert.equal(second.queued, false);

  const offHour = await runIocListStatsNightlyTick(pool, {
    now: new Date('2026-10-04T22:00:10.000Z'),
    fetchStats
  });
  assert.equal(offHour.matched, false);

  for (let i = 0; i < 40 && isIocListStatsRefreshInProgress(); i += 1) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(events.filter((e) => e === 'fetch_stats').length, 1);
});

test('startup path in server.js no longer calls stale-driven refresh tick', async () => {
  const { readFile } = await import('node:fs/promises');
  const { fileURLToPath } = await import('node:url');
  const { dirname, join } = await import('node:path');
  const here = dirname(fileURLToPath(import.meta.url));
  const serverSrc = await readFile(join(here, '../server.js'), 'utf8');
  assert.match(serverSrc, /queueIocListStatsRefreshIfMissing/);
  assert.match(serverSrc, /runIocListStatsNightlyTick|tickIocListStatsNightly/);
  assert.equal(serverSrc.includes('runIocListStatsRefreshTick'), false);
  assert.equal(/snapshot\.stale && !refreshInProgress/.test(serverSrc), false);
});
