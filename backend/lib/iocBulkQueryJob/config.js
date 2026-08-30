// Env-driven knobs for query-wide IOC bulk triage.
// Sync budget matches the expiration worker batch (500): small enough for a
// bounded HTTP request, large enough for typical analyst queries and prod smoke.
// Above that, enqueue onto the existing BullMQ / Action Center pattern.

function intFromEnv(name, fallback, { min, max } = {}) {
  const raw = Number(process.env[name]);
  let value = Number.isFinite(raw) ? Math.trunc(raw) : fallback;
  if (typeof min === 'number') value = Math.max(value, min);
  if (typeof max === 'number') value = Math.min(value, max);
  return value;
}

export function getBulkQueryConfig() {
  return {
    // Explicit-ID bulk is 100; query-wide sync reuses that chunk size internally
    // and allows up to syncMax IDs in one HTTP request via repeated 100-id chunks.
    syncMax: intFromEnv('IOC_BULK_QUERY_SYNC_MAX', 500, { min: 1, max: 5_000 }),
    hardLimit: intFromEnv('IOC_BULK_QUERY_HARD_LIMIT', 50_000, { min: 100, max: 2_000_000 }),
    chunkSize: intFromEnv('IOC_BULK_QUERY_CHUNK_SIZE', 100, { min: 1, max: 100 }),
    maxConcurrentPerUser: intFromEnv('IOC_BULK_QUERY_MAX_CONCURRENT_PER_USER', 2, { min: 1, max: 20 }),
    queryTimeoutMs: intFromEnv('IOC_SEARCH_QUERY_TIMEOUT_MS', 5_000, { min: 100, max: 120_000 }),
    workerQueryTimeoutMs: intFromEnv('IOC_BULK_QUERY_WORKER_TIMEOUT_MS', 600_000, { min: 5_000, max: 3_600_000 }),
    retentionHours: intFromEnv('IOC_BULK_QUERY_RETENTION_HOURS', 24, { min: 1, max: 24 * 30 }),
    metadataRetentionDays: intFromEnv('IOC_BULK_QUERY_METADATA_RETENTION_DAYS', 7, { min: 1, max: 90 }),
    maxRetries: intFromEnv('IOC_BULK_QUERY_MAX_RETRIES', 1, { min: 0, max: 5 })
  };
}

export const BULK_QUERY_QUEUE_NAME = process.env.IOC_BULK_QUERY_QUEUE_NAME || 'ioc-bulk-query';
