/**
 * Global feed-synchronization concurrency policy.
 *
 * Pure config helpers — no I/O. These decide (a) how many feed syncs may run at
 * once across the whole deployment and (b) the per-feed exclusion identity used
 * to guarantee a single feed never runs two overlapping syncs.
 *
 * The concurrency ceiling itself is enforced at the queue choke point via
 * BullMQ global concurrency (Redis-backed, see queue.js / worker.js), so it holds
 * across every trigger (scheduled, manual, retry, recovery) and every worker
 * process/container — not merely within one Node process.
 */

export const FEED_SYNC_CONCURRENCY_DEFAULT = 2;

/**
 * Resolve FEED_SYNC_CONCURRENCY following the repo convention (readPositiveInt):
 * malformed / non-integer / < 1 values fall back to a safe default rather than
 * throwing. Never yields 0 or a negative value.
 *
 * @param {unknown} raw            Raw env value (string | number | undefined).
 * @param {{ fallback?: number, logger?: (msg: string) => void }} [opts]
 * @returns {number} A positive integer concurrency limit.
 */
export function resolveFeedSyncConcurrency(raw, { fallback = FEED_SYNC_CONCURRENCY_DEFAULT, logger } = {}) {
  const safeFallback = Number.isInteger(fallback) && fallback >= 1 ? fallback : FEED_SYNC_CONCURRENCY_DEFAULT;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return safeFallback;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    if (logger) {
      logger(`Invalid FEED_SYNC_CONCURRENCY=${JSON.stringify(raw)}; falling back to ${safeFallback}`);
    }
    return safeFallback;
  }
  return n;
}

/**
 * Per-feed exclusion identity. Two queue jobs sharing this identity must never
 * run concurrently; jobs with distinct identities may. Keyed on the integration
 * source so all triggers (scheduled/manual/retry) for the same feed collide.
 *
 * MalwareBazaar recent-import and historical-recovery intentionally coexist
 * (they cover disjoint time ranges), so recovery gets a distinct identity —
 * preserving the prior malwareBazaarJobsCanCoexist() semantics.
 *
 * @param {string} integrationKey  Stable source key (e.g. 'threatfox-abusech').
 * @param {string} [jobName]       BullMQ job name.
 * @returns {string} Exclusion identity.
 */
export function feedSyncLockIdentity(integrationKey, jobName) {
  const key = String(integrationKey || 'unknown').trim() || 'unknown';
  if (jobName === 'malwarebazaar-historical-recovery') {
    return `${key}#recovery`;
  }
  return key;
}
