/**
 * Centralized bounded-session configuration (security: enforce bounded browser sessions).
 *
 * Three independent limits protect an interactive browser session:
 *   - ACCESS_TOKEN_TTL         short-lived stateless access JWT (default 15m)
 *   - SESSION_IDLE_TIMEOUT     max time between genuine user activity (default 60m)
 *   - SESSION_ABSOLUTE_TIMEOUT hard cap from original login, never extended (default 24h)
 *
 * These apply ONLY to interactive user sessions (cookie / bearer JWT principals).
 * Machine principals (X-Api-Ingest-Token, /api/v1 API keys) are a separate security
 * domain and are intentionally unaffected.
 *
 * Values may be expressed as a bare number (seconds) or with a unit suffix
 * (ms | s | m | h | d), matching the existing JWT_EXPIRES_IN convention. Parsing is
 * done once and validated at startup so a misconfiguration fails fast rather than
 * silently degrading the security posture.
 */

const UNIT_MS = { ms: 1, s: 1000, m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 };

/**
 * Parse a duration string/number into milliseconds.
 * @param {string|number|undefined|null} input
 * @param {number} fallbackMs used when input is empty/absent
 * @returns {number} milliseconds (> 0), or throws for a present-but-invalid value
 */
export function parseDurationMs(input, fallbackMs) {
  if (input == null || String(input).trim() === '') return fallbackMs;
  const s = String(input).trim();
  const m = s.match(/^(\d+)\s*(ms|s|m|h|d)?$/i);
  if (!m) {
    throw new Error(`Invalid duration: ${JSON.stringify(input)}`);
  }
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`Invalid duration (must be > 0): ${JSON.stringify(input)}`);
  }
  const unit = (m[2] || 's').toLowerCase();
  return n * UNIT_MS[unit];
}

/**
 * Resolve session policy from an environment object (defaults to process.env).
 * @param {NodeJS.ProcessEnv} [env]
 */
export function getSessionConfig(env = process.env) {
  const accessTtlMs = parseDurationMs(env.ACCESS_TOKEN_TTL, 15 * 60 * 1000);
  const idleMs = parseDurationMs(env.SESSION_IDLE_TIMEOUT, 60 * 60 * 1000);
  const absoluteMs = parseDurationMs(env.SESSION_ABSOLUTE_TIMEOUT, 24 * 60 * 60 * 1000);
  // Server-side throttle on last_activity_at writes (defense-in-depth against a
  // misbehaving/hostile client hammering the heartbeat). Independent of the
  // frontend debounce. Never larger than the idle window.
  const activityMinUpdateMs = Math.min(
    parseDurationMs(env.SESSION_ACTIVITY_MIN_UPDATE, 60 * 1000),
    idleMs
  );
  // How long revoked/expired session rows are retained for audit/forensics before
  // the maintenance worker deletes them.
  const cleanupRetentionDays = Math.max(
    Number.parseInt(env.SESSION_CLEANUP_RETENTION_DAYS ?? '7', 10) || 7,
    1
  );
  // Grace window during which the immediately-previous refresh secret is still accepted,
  // so concurrent tab refreshes on a shared cookie don't false-trip replay detection.
  const refreshGraceMs = Math.min(
    parseDurationMs(env.SESSION_REFRESH_GRACE, 30 * 1000),
    idleMs
  );
  return {
    accessTtlMs,
    accessTtlSeconds: Math.floor(accessTtlMs / 1000),
    idleMs,
    absoluteMs,
    activityMinUpdateMs,
    refreshGraceMs,
    cleanupRetentionDays
  };
}

/**
 * Validate the resolved policy is internally consistent. Called at startup.
 * Throws for a genuinely broken configuration; returns warnings for merely
 * unusual (but functional) values.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {{ config: ReturnType<typeof getSessionConfig>, warnings: string[] }}
 */
export function validateSessionConfig(env = process.env) {
  const config = getSessionConfig(env);
  const warnings = [];
  if (config.accessTtlMs > config.idleMs) {
    throw new Error(
      'ACCESS_TOKEN_TTL must be <= SESSION_IDLE_TIMEOUT (short access token drives silent refresh)'
    );
  }
  if (config.idleMs > config.absoluteMs) {
    throw new Error('SESSION_IDLE_TIMEOUT must be <= SESSION_ABSOLUTE_TIMEOUT');
  }
  if (config.accessTtlMs > 60 * 60 * 1000) {
    warnings.push('ACCESS_TOKEN_TTL exceeds 1h; access tokens should be short-lived');
  }
  if (config.absoluteMs > 7 * 24 * 60 * 60 * 1000) {
    warnings.push('SESSION_ABSOLUTE_TIMEOUT exceeds 7d; sessions live longer than recommended');
  }
  return { config, warnings };
}
