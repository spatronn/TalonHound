// Env-driven configuration for asynchronous IOC search exports. Shared by the API
// (which enforces per-user concurrency and validates requests) and the worker (which
// batches, streams and enforces the hard row limit).

import path from 'node:path';

function intFromEnv(name, fallback, { min, max } = {}) {
  const raw = Number(process.env[name]);
  let value = Number.isFinite(raw) ? Math.trunc(raw) : fallback;
  if (typeof min === 'number') value = Math.max(value, min);
  if (typeof max === 'number') value = Math.min(value, max);
  return value;
}

export function getExportConfig() {
  return {
    batchSize: intFromEnv('IOC_EXPORT_BATCH_SIZE', 5000, { min: 100, max: 50_000 }),
    retentionHours: intFromEnv('IOC_EXPORT_RETENTION_HOURS', 24, { min: 1, max: 24 * 30 }),
    maxConcurrentPerUser: intFromEnv('IOC_EXPORT_MAX_CONCURRENT_PER_USER', 2, { min: 1, max: 20 }),
    softLimit: intFromEnv('IOC_EXPORT_SOFT_LIMIT', 100_000, { min: 1000, max: 100_000_000 }),
    hardLimit: intFromEnv('IOC_EXPORT_HARD_LIMIT', 2_000_000, { min: 1000, max: 1_000_000_000 }),
    maxRetries: intFromEnv('IOC_EXPORT_MAX_RETRIES', 3, { min: 0, max: 10 }),
    progressUpdateEvery: intFromEnv('IOC_EXPORT_PROGRESS_UPDATE_ROWS', 10_000, { min: 500, max: 1_000_000 }),
    storageDir: String(process.env.IOC_EXPORT_STORAGE_DIR || '/data/ioc-search-exports')
  };
}

export const EXPORT_QUEUE_NAME = process.env.IOC_EXPORT_QUEUE_NAME || 'ioc-search-export';

// Resolve an export's on-disk path and guarantee it stays inside the storage dir
// (defence-in-depth against path traversal; filenames are server-generated UUIDs).
export function resolveExportFilePath(storageDir, fileName) {
  const base = path.resolve(storageDir);
  const resolved = path.resolve(base, fileName);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error('Resolved export path escapes storage directory');
  }
  return resolved;
}
