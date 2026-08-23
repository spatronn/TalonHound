// Scheduled active health probes for on-demand enrichment providers.
//
// Owned by the existing ioc-expiration-worker poll loop (backend image, full
// provider deps available) — no new container, no host cron, no second
// scheduler system. Cadence and retry are driven off each provider's persisted
// last_check_at in enrichment_provider_health, so the schedule is restart-safe
// and needs no separate timer state:
//
//   * never checked          -> due immediately (first probe soon after startup)
//   * healthy / stale         -> re-probe every ~24h
//   * transient failure       -> retry ~5m, then ~30m (degraded), then 24h cadence
//   * auth failure / unhealthy -> back to 24h cadence (no excessive ret/retry of bad creds)
//
// A Postgres advisory lock makes a run exclusive across overlapping ticks and
// multiple worker instances, so the same provider is never probed twice at once.

import {
  ACTIVE_PROBE_PROVIDERS,
  runProviderHealthProbe,
  readProviderHealthRows,
  healthRetryDelaysMs
} from './enrichmentProviderHealthCheck.js';

const DEFAULT_INTERVAL_MS = 24 * 60 * 60 * 1000;

// Stable 32-bit-ish key for pg advisory lock (matches the app's hashtext pattern).
const PROBE_LOCK_NAME = 'enrichment-health-probe';

export function healthProbeIntervalMs() {
  const configured = Number(process.env.ENRICHMENT_HEALTH_PROBE_INTERVAL_MS);
  return Number.isFinite(configured) && configured >= 60 * 1000
    ? configured
    : DEFAULT_INTERVAL_MS;
}

/**
 * How long after the last check this provider should wait before its next probe.
 * Encodes the retry ladder for transient failures without any separate timer.
 */
export function nextProbeDelayMs(row) {
  if (!row) return 0;
  const status = String(row.status || '').toLowerCase();
  const category = String(row.error_category || '').toLowerCase();
  const consecutive = Number(row.consecutive_failures || 0);
  const transient = category === 'network' || category === 'timeout' || category === 'http';
  // Still inside the retry cycle: degraded from a transient error, not yet Unhealthy.
  if (transient && status === 'degraded' && consecutive > 0) {
    const delays = healthRetryDelaysMs();
    return delays[Math.min(consecutive - 1, delays.length - 1)];
  }
  return healthProbeIntervalMs();
}

export function isProbeDue(row, nowMs = Date.now()) {
  if (!row || !row.last_check_at) return true;
  const checkedMs = Date.parse(row.last_check_at);
  if (!Number.isFinite(checkedMs)) return true;
  return (nowMs - checkedMs) >= nextProbeDelayMs(row);
}

async function withProbeLock(pool, fn) {
  const client = await pool.connect();
  let held = false;
  try {
    const { rows } = await client.query(
      'SELECT pg_try_advisory_lock(hashtext($1)) AS acquired',
      [PROBE_LOCK_NAME]
    );
    held = Boolean(rows[0]?.acquired);
    if (!held) return { locked: false };
    return await fn();
  } finally {
    if (held) {
      await client.query('SELECT pg_advisory_unlock(hashtext($1))', [PROBE_LOCK_NAME]).catch(() => {});
    }
    client.release();
  }
}

/**
 * Probe every active-probe provider that is currently due. Providers are probed
 * sequentially (never a simultaneous burst). Disabled / unconfigured providers
 * are skipped without any external call. Best-effort: never throws.
 *
 * @returns {Promise<{locked:boolean, probed:string[], skipped:string[], results:object[]}>}
 */
export async function runDueEnrichmentHealthProbes(pool, { now = Date.now(), logger = console } = {}) {
  const nowMs = now instanceof Date ? now.getTime() : Number(now) || Date.now();
  try {
    const outcome = await withProbeLock(pool, async () => {
      const rows = await readProviderHealthRows(pool);
      const probed = [];
      const skipped = [];
      const results = [];
      for (const provider of ACTIVE_PROBE_PROVIDERS) {
        if (!isProbeDue(rows.get(provider) || null, nowMs)) {
          skipped.push(provider);
          continue;
        }
        const result = await runProviderHealthProbe(pool, provider, { source: 'scheduled' });
        results.push(result);
        if (result.ran) probed.push(provider);
        else skipped.push(provider);
      }
      return { locked: true, probed, skipped, results };
    });
    if (outcome && outcome.locked === false) {
      return { locked: false, probed: [], skipped: [], results: [] };
    }
    return outcome;
  } catch (err) {
    try {
      logger?.warn?.('[health-probe] scheduled probe run failed', { error: String(err?.message || err) });
    } catch { /* logging must not throw */ }
    return { locked: false, probed: [], skipped: [], results: [], error: String(err?.message || err) };
  }
}
