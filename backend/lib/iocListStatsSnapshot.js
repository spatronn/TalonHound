import { fetchIocListStats } from './iocActiveSources.js';

export const IOC_LIST_STATS_SNAPSHOT_KEY = 'global_active_ioc_stats';
export const IOC_LIST_STATS_CACHE_TTL_MS = 6 * 60 * 60 * 1000;

const FILE_HASH_TYPES = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);

let refreshInProgress = false;
/** @type {Promise<object|null>|null} */
let refreshPromise = null;

export function isIocListStatsRefreshInProgress() {
  return refreshInProgress;
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
    { observable_type: 'ip6', count: byTypeMap.get('ip6') || 0 },
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
 */
export async function refreshIocListStatsSnapshot(pool, snapshotKey = IOC_LIST_STATS_SNAPSHOT_KEY) {
  const started = Date.now();
  console.log('[ioc-list-stats] refresh started', { snapshotKey });

  const client = await pool.connect();
  try {
    await client.query(`SET LOCAL statement_timeout = '900000'`);
    const stats = await fetchIocListStats(pool, 'active');
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
 * @param {import('pg').Pool} pool
 * @param {{ force?: boolean, snapshotKey?: string }} [opts]
 */
export async function queueIocListStatsRefresh(pool, opts = {}) {
  if (refreshInProgress && refreshPromise && !opts.force) {
    return { queued: false, in_progress: true };
  }
  if (refreshInProgress && refreshPromise && opts.force) {
    await refreshPromise.catch(() => {});
  }

  refreshInProgress = true;
  refreshPromise = refreshIocListStatsSnapshot(pool, opts.snapshotKey || IOC_LIST_STATS_SNAPSHOT_KEY)
    .finally(() => {
      refreshInProgress = false;
      refreshPromise = null;
    });

  return { queued: true, in_progress: true };
}

/**
 * @param {object|null} snapshot
 */
export function formatIocListStatsApiResponse(snapshot) {
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
      refresh_in_progress: refreshInProgress
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
    refresh_in_progress: Boolean(snapshot.refresh_in_progress)
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
