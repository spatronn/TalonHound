/**
 * In-memory sliding-window rate limiter with opportunistic + periodic pruning
 * so bucket Maps cannot grow without bound under rotating client keys.
 */

/**
 * @param {{
 *   windowMs?: number,
 *   maxBuckets?: number,
 *   sweepIntervalMs?: number,
 *   now?: () => number,
 *   setIntervalFn?: typeof setInterval,
 *   clearIntervalFn?: typeof clearInterval
 * }} [opts]
 */
export function createSlidingWindowRateLimit(opts = {}) {
  const windowMs = Math.max(Number(opts.windowMs) || 60_000, 1);
  const maxBuckets = Math.max(Number(opts.maxBuckets) || 10_000, 1);
  const sweepIntervalMs = Math.max(Number(opts.sweepIntervalMs) || 60_000, 1_000);
  const nowFn = opts.now || (() => Date.now());
  const setIntervalFn = opts.setIntervalFn || setInterval;
  const clearIntervalFn = opts.clearIntervalFn || clearInterval;

  /** @type {Map<string, { start: number, count: number }>} */
  const buckets = new Map();

  function pruneExpired(now = nowFn()) {
    for (const [key, bucket] of buckets) {
      if (now - bucket.start >= windowMs) buckets.delete(key);
    }
  }

  function enforceMaxSize() {
    while (buckets.size > maxBuckets) {
      const oldest = buckets.keys().next().value;
      if (oldest === undefined) break;
      buckets.delete(oldest);
    }
  }

  /**
   * Drop expired buckets and, if still over capacity, evict oldest insertion order.
   * @param {number} [now]
   * @returns {number} remaining size
   */
  function prune(now = nowFn()) {
    pruneExpired(now);
    enforceMaxSize();
    return buckets.size;
  }

  /**
   * @param {string} bucketKey
   * @param {number} limitPerWindow
   * @returns {boolean} true when under limit
   */
  function check(bucketKey, limitPerWindow) {
    const now = nowFn();
    const key = String(bucketKey || '');
    let bucket = buckets.get(key);
    if (!bucket || now - bucket.start >= windowMs) {
      if (bucket) buckets.delete(key);
      bucket = { start: now, count: 0 };
      buckets.set(key, bucket);
      // Opportunistic cleanup whenever a window rolls over.
      pruneExpired(now);
      enforceMaxSize();
    }
    bucket.count += 1;
    return bucket.count <= limitPerWindow;
  }

  const timer = setIntervalFn(() => {
    prune();
  }, sweepIntervalMs);
  if (typeof timer?.unref === 'function') timer.unref();

  function stop() {
    clearIntervalFn(timer);
  }

  return {
    check,
    prune,
    size: () => buckets.size,
    stop,
    /** @internal test helper */
    _buckets: buckets
  };
}
