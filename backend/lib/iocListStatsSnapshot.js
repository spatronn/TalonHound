import { fetchIocListStats } from './iocActiveSources.js';

export const IOC_LIST_STATS_SNAPSHOT_KEY = 'global_active_ioc_stats';
export const IOC_LIST_STATS_CACHE_TTL_MS = 6 * 60 * 60 * 1000;

/** hashtext()-namespaced session advisory lock (see advisoryLocks.js inventory). */
export const IOC_LIST_STATS_REFRESH_LOCK_NAME = 'talonhound:ioc-list-stats-refresh';

export const IOC_STATS_RECALCULATION_IN_PROGRESS = 'ioc_stats_recalculation_in_progress';

const FILE_HASH_TYPES = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

let refreshInProgress = false;
/** @type {Promise<object|null>|null} */
let refreshPromise = null;

export function isIocListStatsRefreshInProgress() {
  return refreshInProgress;
}

/**
 * Test-only: clear in-process refresh mutex so suites can isolate cases.
 */
export function resetIocListStatsRefreshStateForTests() {
  refreshInProgress = false;
  refreshPromise = null;
}

/**
 * Acquire the global IOC-stats recalculation session advisory lock.
 * Lock is held on a dedicated pooled connection until release().
 *
 * @param {import('pg').Pool} pool
 * @returns {Promise<{ acquired: boolean, release: () => Promise<void> }>}
 */
export async function acquireIocListStatsRefreshLock(pool) {
  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      'SELECT pg_try_advisory_lock(hashtext($1)) AS ok',
      [IOC_LIST_STATS_REFRESH_LOCK_NAME]
    );
    if (rows[0]?.ok === true) {
      let released = false;
      return {
        acquired: true,
        async release() {
          if (released) return;
          released = true;
          try {
            await client.query(
              'SELECT pg_advisory_unlock(hashtext($1))',
              [IOC_LIST_STATS_REFRESH_LOCK_NAME]
            );
          } catch {
            // Connection may already be gone; PostgreSQL frees the lock on close.
          } finally {
            client.release();
          }
        }
      };
    }
    client.release();
    return { acquired: false, async release() {} };
  } catch (err) {
    client.release(err instanceof Error ? err : new Error(String(err)));
    throw err;
  }
}

/**
 * Authoritative cross-process "is recalculation running?" check.
 * Uses the local mutex first, then probes the advisory lock without holding it.
 *
 * @param {import('pg').Pool} pool
 */
export async function resolveIocListStatsRefreshInProgress(pool) {
  if (refreshInProgress) return true;
  const client = await pool.connect();
  try {
    const { rows } = await client.query(
      'SELECT pg_try_advisory_lock(hashtext($1)) AS ok',
      [IOC_LIST_STATS_REFRESH_LOCK_NAME]
    );
    if (rows[0]?.ok === true) {
      await client.query(
        'SELECT pg_advisory_unlock(hashtext($1))',
        [IOC_LIST_STATS_REFRESH_LOCK_NAME]
      );
      return false;
    }
    return true;
  } finally {
    client.release();
  }
}

/**
 * @param {Array<{ observable_type: string, count: number|string }>} byTypeRows
 */
export function normalizeIocListStatsPayload(stats) {
  const byTypeRaw = Array.isArray(stats?.by_type) ? stats.by_type : [];
  const hashCount = byTypeRaw.reduce(
    (acc, row) => acc + (FILE_HASH_TYPES.has(String(row.observable_type || '').toLowerCase())
      ? Number(row.count || 0)
      : 0),
    0
  );

  const byTypeMap = new Map();
  for (const row of byTypeRaw) {
    const t = String(row.observable_type || '').toLowerCase();
    if (FILE_HASH_TYPES.has(t)) continue;
    byTypeMap.set(t, Number(row.count || 0));
  }
  if (hashCount > 0) byTypeMap.set('hash', hashCount);

  const by_type = [
    { observable_type: 'ip', count: byTypeMap.get('ip') || 0 },
    { observable_type: 'url', count: byTypeMap.get('url') || 0 },
    { observable_type: 'domain', count: byTypeMap.get('domain') || 0 },
    { observable_type: 'ipv6', count: byTypeMap.get('ipv6') || 0 },
    { observable_type: 'hash', count: byTypeMap.get('hash') || 0 }
  ];

  const topSources = (Array.isArray(stats?.by_source) ? stats.by_source : [])
    .slice(0, 5)
    .map((row) => ({
      source_name: row.source_name,
      count: Number(row.count || 0)
    }));

  const total = Number(stats?.total || 0);

  return {
    total_records: total,
    total,
    by_type,
    top_sources: topSources,
    by_source: topSources
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} [snapshotKey]
 */
export async function getIocListStatsSnapshot(pool, snapshotKey = IOC_LIST_STATS_SNAPSHOT_KEY) {
  const { rows } = await pool.query(
    `SELECT snapshot_key, payload, calculated_at, updated_at
     FROM ioc_list_stats_snapshots
     WHERE snapshot_key = $1
     LIMIT 1`,
    [snapshotKey]
  );
  const row = rows[0];
  if (!row) return null;

  const calculatedAt = row.calculated_at instanceof Date
    ? row.calculated_at.toISOString()
    : String(row.calculated_at);
  const ageMs = Date.now() - new Date(calculatedAt).getTime();
  const stale = ageMs > IOC_LIST_STATS_CACHE_TTL_MS;

  return {
    snapshot_key: row.snapshot_key,
    payload: row.payload,
    calculated_at: calculatedAt,
    updated_at: row.updated_at,
    stale,
    missing: false,
    cache_ttl_seconds: Math.floor(IOC_LIST_STATS_CACHE_TTL_MS / 1000),
    refresh_in_progress: refreshInProgress
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} [snapshotKey]
 * @param {{ fetchStats?: typeof fetchIocListStats }} [deps]
 */
export async function refreshIocListStatsSnapshot(
  pool,
  snapshotKey = IOC_LIST_STATS_SNAPSHOT_KEY,
  deps = {}
) {
  const fetchStats = deps.fetchStats || fetchIocListStats;
  const started = Date.now();
  console.log('[ioc-list-stats] refresh started', { snapshotKey });

  const client = await pool.connect();
  try {
    await client.query(`SET LOCAL statement_timeout = '900000'`);
    const stats = await fetchStats(pool, 'active');
    const payload = normalizeIocListStatsPayload(stats);
    const calculatedAt = new Date();

    await client.query(
      `INSERT INTO ioc_list_stats_snapshots (snapshot_key, payload, calculated_at, updated_at)
       VALUES ($1, $2::jsonb, $3, NOW())
       ON CONFLICT (snapshot_key) DO UPDATE
         SET payload = EXCLUDED.payload,
             calculated_at = EXCLUDED.calculated_at,
             updated_at = NOW()`,
      [snapshotKey, JSON.stringify(payload), calculatedAt]
    );

    const durationMs = Date.now() - started;
    console.log('[ioc-list-stats] refresh completed', {
      snapshotKey,
      durationMs,
      total_records: payload.total_records
    });

    return {
      snapshot_key: snapshotKey,
      payload,
      calculated_at: calculatedAt.toISOString(),
      duration_ms: durationMs
    };
  } catch (err) {
    console.error('[ioc-list-stats] refresh failed', {
      snapshotKey,
      durationMs: Date.now() - started,
      message: err.message
    });
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Single-flight queue for IOC list stats recalculation.
 * Guarded by both an in-process mutex and a Postgres session advisory lock so
 * manual UI triggers and the scheduled 6-hour tick cannot run concurrently
 * across backend processes.
 *
 * @param {import('pg').Pool} pool
 * @param {{ force?: boolean, snapshotKey?: string, fetchStats?: typeof fetchIocListStats }} [opts]
 * @returns {Promise<{ queued: boolean, in_progress: boolean, code?: string }>}
 */
export async function queueIocListStatsRefresh(pool, opts = {}) {
  if (refreshInProgress && refreshPromise && !opts.force) {
    return {
      queued: false,
      in_progress: true,
      code: IOC_STATS_RECALCULATION_IN_PROGRESS
    };
  }
  if (refreshInProgress && refreshPromise && opts.force) {
    await refreshPromise.catch(() => {});
  }

  const lock = await acquireIocListStatsRefreshLock(pool);
  if (!lock.acquired) {
    return {
      queued: false,
      in_progress: true,
      code: IOC_STATS_RECALCULATION_IN_PROGRESS
    };
  }

  refreshInProgress = true;
  refreshPromise = (async () => {
    try {
      return await refreshIocListStatsSnapshot(
        pool,
        opts.snapshotKey || IOC_LIST_STATS_SNAPSHOT_KEY,
        { fetchStats: opts.fetchStats }
      );
    } finally {
      await lock.release();
      refreshInProgress = false;
      refreshPromise = null;
    }
  })();

  // Surface unexpected failures; callers that fire-and-forget still get logs.
  refreshPromise.catch((err) => {
    console.error('[ioc-list-stats] queued refresh failed', err?.message || err);
  });

  return { queued: true, in_progress: true };
}

/**
 * @param {object|null} snapshot
 * @param {{ refresh_in_progress?: boolean }} [overrides]
 */
export function formatIocListStatsApiResponse(snapshot, overrides = {}) {
  const refreshInProgressFlag = overrides.refresh_in_progress != null
    ? Boolean(overrides.refresh_in_progress)
    : Boolean(snapshot?.refresh_in_progress ?? refreshInProgress);

  if (!snapshot?.payload) {
    return {
      total: 0,
      total_records: 0,
      by_type: [],
      by_source: [],
      top_sources: [],
      last_update: null,
      calculated_at: null,
      stale: true,
      missing: true,
      cache_ttl_seconds: Math.floor(IOC_LIST_STATS_CACHE_TTL_MS / 1000),
      refresh_in_progress: refreshInProgressFlag
    };
  }

  const p = snapshot.payload;
  return {
    total: Number(p.total ?? p.total_records ?? 0),
    total_records: Number(p.total_records ?? p.total ?? 0),
    by_type: p.by_type ?? [],
    by_source: p.by_source ?? p.top_sources ?? [],
    top_sources: p.top_sources ?? p.by_source ?? [],
    last_update: snapshot.calculated_at,
    calculated_at: snapshot.calculated_at,
    stale: Boolean(snapshot.stale),
    missing: false,
    cache_ttl_seconds: snapshot.cache_ttl_seconds ?? Math.floor(IOC_LIST_STATS_CACHE_TTL_MS / 1000),
    refresh_in_progress: refreshInProgressFlag
  };
}

/**
 * Fast read of global total for browse pagination — never computes live stats.
 * @param {import('pg').Pool} pool
 */
export async function readIocListBrowseGlobalTotal(pool) {
  const snap = await getIocListStatsSnapshot(pool);
  const total = snap?.payload?.total ?? snap?.payload?.total_records;
  return total != null ? Number(total) : null;
}
