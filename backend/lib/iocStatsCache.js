const IOC_STATS_TTL_MS = 60 * 60 * 1000;

let cacheVersion = 0;
/** @type {Map<string, { data: object, createdAt: number, version: number }>} */
const cacheByKey = new Map();

export function getIocStatsTtlMs() {
  return IOC_STATS_TTL_MS;
}

export function invalidateIocStatsCache() {
  cacheVersion += 1;
  cacheByKey.clear();
}

export function readIocStatsCache(cacheKey) {
  const entry = cacheByKey.get(String(cacheKey || ''));
  if (!entry) return null;
  if (entry.version !== cacheVersion) return null;
  if (Date.now() - entry.createdAt > IOC_STATS_TTL_MS) return null;
  return entry.data;
}

export function writeIocStatsCache(cacheKey, data) {
  cacheByKey.set(String(cacheKey || ''), {
    data,
    createdAt: Date.now(),
    version: cacheVersion
  });
}

export function buildIocStatsCacheKey(statusFilter, lastUpdate) {
  return `ioc_stats_${String(statusFilter || 'active')}_${lastUpdate ?? 'null'}_v${cacheVersion}`;
}
