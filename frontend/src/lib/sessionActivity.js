/**
 * Genuine user-activity heartbeat (security: enforce bounded browser sessions).
 *
 * The server enforces a 60-minute idle timeout that is advanced ONLY by an explicit
 * heartbeat — never by ordinary API traffic or background polling. This module emits
 * that heartbeat, and ONLY in response to real interaction (pointer / keyboard / form
 * submit / tab refocus). Because background polling never dispatches these DOM events,
 * an idle-but-open browser stops sending heartbeats and the session correctly expires.
 *
 * A leading-edge throttle bounds writes to at most one request per interval while the
 * user is genuinely active (≈1 DB write every few minutes), and exactly zero while idle.
 */

export const DEFAULT_HEARTBEAT_MIN_INTERVAL_MS = 4 * 60 * 1000;

const INTERACTION_EVENTS = ['pointerdown', 'keydown', 'submit'];

/**
 * @param {{ post: Function }} api authenticated axios instance
 * @param {{ minIntervalMs?: number, now?: () => number }} [options]
 * @returns {() => void} stop function that detaches listeners
 */
export function startSessionActivityTracking(api, options = {}) {
  if (typeof window === 'undefined') return () => {};
  const minIntervalMs = Number(options.minIntervalMs) > 0
    ? Number(options.minIntervalMs)
    : DEFAULT_HEARTBEAT_MIN_INTERVAL_MS;
  const now = options.now || (() => Date.now());

  // Start "already sent" so the freshly-issued session isn't heartbeated immediately;
  // the first heartbeat fires only after a full interval of genuine activity.
  let lastSent = now();
  let stopped = false;

  const onActivity = () => {
    if (stopped) return;
    const t = now();
    if (t - lastSent < minIntervalMs) return;
    lastSent = t;
    // Fire-and-forget. Failures (e.g. an already-expired session returning 401) are
    // handled by the axios response interceptor, not here.
    Promise.resolve(api.post('/auth/activity')).catch(() => {});
  };

  const onVisibility = () => {
    if (document.visibilityState === 'visible') onActivity();
  };

  for (const evt of INTERACTION_EVENTS) {
    window.addEventListener(evt, onActivity, { passive: true, capture: true });
  }
  document.addEventListener('visibilitychange', onVisibility);

  return function stop() {
    stopped = true;
    for (const evt of INTERACTION_EVENTS) {
      window.removeEventListener(evt, onActivity, { capture: true });
    }
    document.removeEventListener('visibilitychange', onVisibility);
  };
}
