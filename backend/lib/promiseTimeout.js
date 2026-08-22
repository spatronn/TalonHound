/**
 * Bounded settlement for an optional/non-critical async operation.
 *
 * Resolves with the operation's value on success, or with `fallback` when the
 * operation rejects OR fails to settle within `timeoutMs`. It never rejects, so
 * a caller can treat a slow/broken dependency as "degraded but available"
 * instead of letting it stall the whole request path.
 *
 * This is the missing guard for external calls on the GET /api/integrations
 * critical path (notably the Redis-backed `getRepeatableJobs()` used to compute
 * Next Run). That call runs on an ioredis connection created with
 * `maxRetriesPerRequest: null`, so during a Redis reconnect/blip the command is
 * queued and the promise neither resolves nor rejects — a plain `.catch()`
 * fallback is therefore unreachable and the Feeds page load hangs. Racing it
 * against a timeout makes the intended fallback reachable.
 *
 * @template T
 * @param {Promise<T> | T} promise      The operation to bound.
 * @param {object} opts
 * @param {number} opts.timeoutMs        Max time to wait before falling back.
 * @param {T | (() => T)} opts.fallback  Value (or factory) used on timeout/rejection.
 *                                        Pass a factory when the fallback is mutable
 *                                        (e.g. `() => new Map()`) so callers never
 *                                        share the same instance.
 * @returns {Promise<T>}
 */
export function settleWithTimeout(promise, { timeoutMs, fallback }) {
  const resolveFallback = () => (typeof fallback === 'function' ? fallback() : fallback);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    // The timer is cleared as soon as the operation settles, and otherwise lives
    // only until timeoutMs. It is intentionally NOT unref'd: a request-scoped
    // fallback must fire even if it is momentarily the sole pending timer.
    const timer = setTimeout(() => finish(resolveFallback()), timeoutMs);
    Promise.resolve(promise).then(
      (value) => finish(value),
      () => finish(resolveFallback())
    );
  });
}
