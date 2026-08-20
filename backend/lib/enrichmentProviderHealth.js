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

async function queryOne(pool, sql, params = []) {
  try {
    const result = await pool.query(sql, params);
    return result.rows?.[0] || {};
  } catch {
    return {};
  }
}

async function loadRuntimeEvidence(pool) {
  const [ipinfo, abuseipdb, rdap] = await Promise.all([
    queryOne(pool, `
      SELECT
        MAX(last_enriched_at) FILTER (WHERE provider_status = 'success') AS last_success_at,
        MAX(last_enriched_at) FILTER (WHERE provider_status IN ('failed','unavailable','auth_error','rate_limited')) AS last_failure_at
      FROM ioc_ip_enrichment
    `),
    queryOne(pool, `
      SELECT
        MAX(last_enriched_at) FILTER (WHERE provider_status = 'success') AS last_success_at,
        MAX(last_enriched_at) FILTER (WHERE provider_status IN ('failed','auth_error','rate_limited')) AS last_failure_at
      FROM ioc_abuseipdb_enrichment
    `),
    queryOne(pool, `
      SELECT
        MAX(last_success_at) AS last_success_at,
        MAX(last_attempt_at) FILTER (WHERE last_error IS NOT NULL) AS last_failure_at
      FROM ioc_domain_enrichment
    `)
  ]);
  return { ipinfo_lite: ipinfo, abuseipdb, rdap };
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
 */
export async function attachProviderHealth(pool, providers, options = {}) {
  const freshnessMs = Number(options.freshnessMs || providerHealthFreshnessMs());
  const runtime = await loadRuntimeEvidence(pool);

  return providers.map((row) => {
    if (row.provider === 'spamhaus_drop') {
      const health = spamhausHealth(row, freshnessMs, options.now);
      return { ...row, health, status: health.status };
    }

    const extra = runtime[row.provider] || {};
    const lastSuccessAt = maxTimestamp(row.last_success_at, extra.last_success_at);
    const lastFailureAt = maxTimestamp(row.last_error_at, extra.last_failure_at);
    const manualFailure = Boolean(
      row.last_test_at && row.last_error_at
      && Date.parse(row.last_test_at) === Date.parse(row.last_error_at)
      && (!row.last_success_at || Date.parse(row.last_error_at) >= Date.parse(row.last_success_at))
    );
    const health = resolveProviderHealth({
      configured: row.configured,
      last_success_at: lastSuccessAt,
      last_failure_at: lastFailureAt,
      last_checked_at: maxTimestamp(row.last_test_at, extra.last_attempt_at, lastSuccessAt, lastFailureAt),
      failure_authoritative: manualFailure,
      failure_message: row.last_error_message,
      failure_code: row.last_error_code
    }, { freshnessMs, now: options.now });

    return { ...row, health, status: health.status };
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
