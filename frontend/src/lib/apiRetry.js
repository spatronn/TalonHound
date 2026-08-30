// Bounded, transient-only retry for idempotent GET requests.
//
// Scope is deliberately narrow so a genuine failure stays visible instead of
// being masked by retries:
//   - only network-level failures (no HTTP response reached us) and the
//     gateway/unavailable statuses 502/503/504 are treated as transient;
//   - 4xx (auth/validation) and 500 (likely a server bug) are NOT retried —
//     retrying those hides real errors and can amplify load;
//   - attempts are capped and use a short backoff.
//
// This exists because the Feeds page load can hit a brief backend/Redis/DB blip
// (the same class of transient the backend now bounds server-side); a single
// automatic retry turns "randomly fails, works on manual refresh" into a load
// that self-heals, without weakening error reporting.

const TRANSIENT_STATUSES = new Set([502, 503, 504]);

export function isTransientLoadError(err) {
  if (!err) return false;
  const status = err?.response?.status;
  // No response at all: network error, connection reset, or client-side timeout.
  if (status == null) return true;
  return TRANSIENT_STATUSES.has(Number(status));
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Run an idempotent GET with bounded retries on transient failures only.
 *
 * @param {() => Promise<any>} doRequest  Performs one GET attempt.
 * @param {object} [opts]
 * @param {number} [opts.retries=2]        Max retries after the first attempt.
 * @param {number[]} [opts.backoffsMs]     Backoff before each retry.
 * @param {(err:any)=>boolean} [opts.isTransient]
 * @param {(ms:number)=>Promise<void>} [opts.sleep]  Injectable for tests.
 */
export async function getWithTransientRetry(doRequest, opts = {}) {
  const retries = Number.isFinite(opts.retries) ? Math.max(0, opts.retries) : 2;
  const backoffsMs = opts.backoffsMs || [250, 600];
  const isTransient = opts.isTransient || isTransientLoadError;
  const sleep = opts.sleep || delay;

  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      // eslint-disable-next-line no-await-in-loop
      return await doRequest();
    } catch (err) {
      lastErr = err;
      const hasMoreAttempts = attempt < retries;
      if (!hasMoreAttempts || !isTransient(err)) throw err;
      // eslint-disable-next-line no-await-in-loop
      await sleep(backoffsMs[Math.min(attempt, backoffsMs.length - 1)] ?? 0);
    }
  }
  throw lastErr;
}
