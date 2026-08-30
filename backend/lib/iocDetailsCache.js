/**
 * Bounded TTL cache for IOC details responses.
 * On write: prune expired entries, then enforce max size (insertion-order eviction).
 */

/**
 * @param {{
 *   ttlMs?: number,
 *   maxEntries?: number,
 *   now?: () => number
 * }} [opts]
 */
export function createIocDetailsCache(opts = {}) {
  const rawTtl = Number(opts.ttlMs);
  // Allow sub-second TTLs in tests; production callers pass >= 15s via env default.
  const ttlMs = Number.isFinite(rawTtl) && rawTtl > 0
    ? Math.max(rawTtl, 1)
    : 15_000;
  const maxEntries = Math.max(Number(opts.maxEntries) || 500, 1);
  const nowFn = opts.now || (() => Date.now());

  /** @type {Map<string, { expiresAt: number, payload: unknown }>} */
  const cache = new Map();

  /**
   * Remove expired entries; if still over maxEntries, delete oldest keys.
   * @param {number} [now]
   * @returns {number} remaining size
   */
  function prune(now = nowFn()) {
    for (const [key, entry] of cache) {
      if (!entry || entry.expiresAt <= now) cache.delete(key);
    }
    while (cache.size > maxEntries) {
      const oldest = cache.keys().next().value;
      if (oldest === undefined) break;
      cache.delete(oldest);
    }
    return cache.size;
  }

  function get(publicId) {
    const key = String(publicId || '');
    if (!key) return null;
    const entry = cache.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= nowFn()) {
      cache.delete(key);
      return null;
    }
    return entry;
  }

  function set(publicId, payload) {
    const key = String(publicId || '');
    if (!key) return;
    // Refresh insertion order for LRU-ish eviction under pressure.
    cache.delete(key);
    cache.set(key, { expiresAt: nowFn() + ttlMs, payload });
    prune();
  }

  function del(publicId) {
    if (publicId) cache.delete(String(publicId));
  }

  function clear() {
    cache.clear();
  }

  return {
    get,
    set,
    delete: del,
    clear,
    prune,
    size: () => cache.size,
    /** @internal */
    _map: cache
  };
}

/**
 * Remove expired entries and enforce max size on an IOC details cache instance.
 * Exported for unit tests (also available as `cache.prune()`).
 * @param {{ prune: (now?: number) => number }} cache
 * @param {number} [now]
 */
export function pruneIocDetailsCache(cache, now) {
  return cache.prune(now);
}
