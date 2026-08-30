import { readProviderHealthRows, resolveActiveProbeHealth } from './enrichmentProviderHealthCheck.js';

const DAY_MS = 24 * 60 * 60 * 1000;

export const PROVIDER_HEALTH_STATUSES = Object.freeze([
  'healthy',
  'degraded',
  'unhealthy',
  'unknown'
]);

export const DEFAULT_PROVIDER_HEALTH_FRESHNESS_MS = DAY_MS;

export function providerHealthFreshnessMs() {
  const configured = Number(process.env.ENRICHMENT_PROVIDER_HEALTH_FRESHNESS_MS);
  return Number.isFinite(configured) && configured >= 60_000
    ? configured
    : DEFAULT_PROVIDER_HEALTH_FRESHNESS_MS;
}

function instant(value) {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? { value, ms } : null;
}

function latest(...values) {
  return values.map(instant).filter(Boolean).sort((a, b) => b.ms - a.ms)[0] || null;
}

function isRateLimited(evidence = {}) {
  const text = `${evidence.failure_code || ''} ${evidence.failure_message || ''}`.toLowerCase();
  return text.includes('rate_limit') || text.includes('rate limit') || text.includes('429');
}

/**
 * Canonical provider-health policy. Enabled/configured are deliberately separate
 * from runtime health; only fresh runtime evidence can produce Healthy.
 */
export function resolveProviderHealth(evidence = {}, options = {}) {
  const nowMs = options.now instanceof Date
    ? options.now.getTime()
    : Number.isFinite(options.now)
      ? options.now
      : Date.now();
  const freshnessMs = Math.max(
    60_000,
    Number(options.freshnessMs || evidence.freshness_ms || providerHealthFreshnessMs())
  );
  const success = latest(evidence.last_success_at);
  const failure = latest(evidence.last_failure_at);
  const checked = latest(evidence.last_checked_at, success?.value, failure?.value);
  const successFresh = Boolean(success && nowMs - success.ms <= freshnessMs);
  const failureFresh = Boolean(failure && nowMs - failure.ms <= freshnessMs);
  const failureIsLatest = Boolean(failure && (!success || failure.ms >= success.ms));

  let status = 'unknown';
  let reason = evidence.configured === false ? 'not_configured' : 'no_recent_evidence';

  if (failureFresh && failureIsLatest) {
    if (isRateLimited(evidence)) {
      status = 'degraded';
      reason = 'rate_limited';
    } else if (successFresh && evidence.failure_authoritative !== true) {
      status = 'degraded';
      reason = 'partial_failure';
    } else {
      status = 'unhealthy';
      reason = 'recent_failure';
    }
  } else if (successFresh) {
    status = 'healthy';
    reason = 'recent_success';
  } else if (success) {
    reason = 'stale_success';
  } else if (failure) {
    reason = 'stale_failure';
  }

  return {
    status,
    reason,
    last_success_at: success?.value || null,
    last_failure_at: failure?.value || null,
    last_checked_at: checked?.value || null,
    freshness_ms: freshnessMs
  };
}

function maxTimestamp(...values) {
  return latest(...values)?.value || null;
}

/**
 * Last real enrichment activity per provider, sourced from enrichment_usage_daily
 * (day granularity). This is deliberately independent of provider health: health
 * probes never write usage telemetry, so this cannot be inflated by a health
 * check. Surfaced as "Last enrichment activity", never as health evidence.
 */
async function loadLastEnrichmentActivity(pool) {
  const map = {};
  try {
    const { rows } = await pool.query(`
      SELECT provider_key, MAX(bucket_date) AS last_activity
      FROM enrichment_usage_daily
      WHERE request_count > 0
      GROUP BY provider_key
    `);
    for (const row of rows) {
      const at = row.last_activity ? new Date(row.last_activity).toISOString() : null;
      if (at) map[row.provider_key] = at;
    }
  } catch {
    /* usage table missing -> no activity info */
  }
  return map;
}

function spamhausHealth(row, freshnessMs, now) {
  const states = Array.isArray(row.sync_state) ? row.sync_state : [];
  const successAt = states.map((s) => s.last_success_at).filter(Boolean)
    .reduce((acc, value) => maxTimestamp(acc, value), null);
  const failed = states.filter((s) => String(s.status).toLowerCase() === 'failed');
  const failureAt = failed.map((s) => s.last_attempt_at || s.updated_at).filter(Boolean)
    .reduce((acc, value) => maxTimestamp(acc, value), null);
  const cadenceMs = Math.max(1, Number(row.sync_interval_hours || 24)) * 2 * 60 * 60 * 1000;
  const resolved = resolveProviderHealth({
    configured: row.configured,
    last_success_at: successAt,
    last_failure_at: failureAt,
    failure_authoritative: failed.length === states.length && states.length > 0
  }, { freshnessMs: Math.max(freshnessMs, cadenceMs), now });

  if (failed.length > 0 && failed.length < states.length && resolved.status === 'unhealthy') {
    return { ...resolved, status: 'degraded', reason: 'partial_failure' };
  }
  return resolved;
}

/**
 * Attach canonical health to already-sanitized provider summaries.
 *
 * Health for active-probe providers (VirusTotal, IPinfo Lite, AbuseIPDB, RDAP)
 * comes solely from explicit health-check evidence in enrichment_provider_health
 * — manual "Test Connection" and scheduled 24h probes. Elapsed time since the
 * last analyst *enrichment* never affects health; it is surfaced separately as
 * `last_enrichment_at`. Spamhaus DROP keeps its operational (dataset-sync) health.
 */
export async function attachProviderHealth(pool, providers, options = {}) {
  const freshnessMs = Number(options.freshnessMs || providerHealthFreshnessMs());
  const [healthRows, activity] = await Promise.all([
    readProviderHealthRows(pool),
    loadLastEnrichmentActivity(pool)
  ]);

  return providers.map((row) => {
    if (row.provider === 'spamhaus_drop') {
      const health = spamhausHealth(row, freshnessMs, options.now);
      return { ...row, health, status: health.status };
    }

    const health = resolveActiveProbeHealth(healthRows.get(row.provider) || null, {
      now: options.now,
      staleMs: options.staleMs
    });
    const lastEnrichmentAt = activity[row.provider] || null;

    return { ...row, health, status: health.status, last_enrichment_at: lastEnrichmentAt };
  });
}

/**
 * Best-effort provider-level runtime evidence recorder. Existing provider result
 * tables remain authoritative data stores; this keeps exact latest timestamps
 * available for providers (notably VirusTotal) without scanning result caches.
 */
export async function recordProviderHealthSignal(pool, {
  provider,
  outcome,
  rateLimited = false,
  errorMessage = null
} = {}) {
  const key = String(provider || '').trim();
  if (!pool || !key || !['success', 'failure'].includes(outcome)) return false;
  const success = outcome === 'success';
  const message = success
    ? null
    : String(errorMessage || (rateLimited ? 'Provider rate limited' : 'Provider interaction failed')).slice(0, 500);
  try {
    await pool.query(
      `INSERT INTO threat_intel_provider_configs
         (provider, last_success_at, last_error_at, last_error_message, updated_at)
       VALUES ($1, CASE WHEN $2 THEN NOW() ELSE NULL END, CASE WHEN $2 THEN NULL ELSE NOW() END, $3, NOW())
       ON CONFLICT (provider) DO UPDATE SET
         last_success_at = CASE WHEN $2 THEN NOW() ELSE threat_intel_provider_configs.last_success_at END,
         last_error_at = CASE WHEN $2 THEN threat_intel_provider_configs.last_error_at ELSE NOW() END,
         last_error_message = CASE WHEN $2 THEN NULL ELSE $3 END,
         updated_at = NOW()`,
      [key, success, message]
    );
    return true;
  } catch {
    return false;
  }
}
