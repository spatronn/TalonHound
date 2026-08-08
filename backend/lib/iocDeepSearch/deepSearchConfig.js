// Env-driven configuration for asynchronous IOC Deep Search. Shared by the API (per-user
// concurrency, de-dup) and the worker (bounded background timeout, hard cap, retention).
// Deliberately parallels iocSearchExport/exportConfig.js so the two async task types tune
// and behave consistently.

function intFromEnv(name, fallback, { min, max } = {}) {
  const raw = Number(process.env[name]);
  let value = Number.isFinite(raw) ? Math.trunc(raw) : fallback;
  if (typeof min === 'number') value = Math.max(value, min);
  if (typeof max === 'number') value = Math.min(value, max);
  return value;
}

export function getDeepSearchConfig() {
  return {
    // Bounded statement timeout for the background materialization query. Much larger than
    // the interactive timeout (IOC_SEARCH_QUERY_TIMEOUT_MS, ~5s) but still finite so a
    // pathological query cannot pin a worker forever. This — NOT an arbitrary row cap — is
    // the real safety bound on Deep Search: a completed search always holds the COMPLETE
    // matching set; one that cannot materialize within this budget fails honestly (57014).
    queryTimeoutMs: intFromEnv('IOC_DEEP_SEARCH_QUERY_TIMEOUT_MS', 600_000, { min: 5_000, max: 3_600_000 }),
    // How often the running-materialization watcher checks for a cancel request so it can
    // pg_cancel_backend the in-flight statement.
    cancelPollMs: intFromEnv('IOC_DEEP_SEARCH_CANCEL_POLL_MS', 1000, { min: 250, max: 30_000 }),
    // Result-set (spool) retention starts when the search completes.
    retentionHours: intFromEnv('IOC_DEEP_SEARCH_RETENTION_HOURS', 24, { min: 1, max: 24 * 30 }),
    // Terminal metadata rows (expired/failed/cancelled) are hard-deleted after this many days.
    metadataRetentionDays: intFromEnv('IOC_DEEP_SEARCH_METADATA_RETENTION_DAYS', 7, { min: 1, max: 90 }),
    maxConcurrentPerUser: intFromEnv('IOC_DEEP_SEARCH_MAX_CONCURRENT_PER_USER', 3, { min: 1, max: 20 }),
    // Batch size for bounded spool deletes during cleanup (avoids long locks on large sets).
    cleanupBatchSize: intFromEnv('IOC_DEEP_SEARCH_CLEANUP_BATCH_SIZE', 10_000, { min: 500, max: 200_000 })
  };
}

export const DEEP_SEARCH_QUEUE_NAME = process.env.IOC_DEEP_SEARCH_QUEUE_NAME || 'ioc-deep-search';

// Result page size for browsing a completed Deep Search. Matches the IOC List max page size.
export function clampDeepSearchPageSize(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return 25;
  return Math.min(Math.max(Math.trunc(n), 1), 100);
}
