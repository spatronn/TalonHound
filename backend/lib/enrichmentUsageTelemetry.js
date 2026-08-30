// Enrichment usage telemetry recorder.
//
// One concurrency-safe upsert per logical enrichment request into
// enrichment_usage_daily. Recording is best-effort: a telemetry failure MUST NEVER
// convert a successful enrichment into a failed one, so every write path swallows
// its error (logged, not thrown). Enrichment entry points call recordEnrichmentUsage
// (single request) or writeEnrichmentUsage (pre-aggregated batch, e.g. bulk IP).
//
// Metric semantics (see migration 153):
//   request_count       logical enrichment request initiated for a provider
//   external_call_count  real outbound provider attempt (primary consumption metric)
//   cache_hit_count      request satisfied without an external provider lookup
//   success_count        logical request completed successfully
//   failure_count        logical request failed
//   rate_limit_count     external call explicitly rate limited (HTTP 429 / equivalent)
//   total_external_response_time_ms / external_response_count  provider-call latency
//
// Retry policy: the current providers perform exactly one outbound attempt per
// logical request (no internal retry loop), so external_call_count == outbound
// attempts. If a provider later adds retries, increment external_call_count once
// per real outbound attempt while keeping request_count at one per logical request.

import { createServiceLogger } from './appLogger.js';
import { recordProviderHealthSignal } from './enrichmentProviderHealth.js';

const defaultLogger = createServiceLogger('enrichment-usage');

/** Normalized, bounded IOC-type dimension. */
export const USAGE_IOC_TYPES = Object.freeze(['ip', 'domain', 'url', 'hash', 'other']);

const COUNTER_KEYS = Object.freeze([
  'request_count',
  'external_call_count',
  'cache_hit_count',
  'success_count',
  'failure_count',
  'rate_limit_count',
  'total_external_response_time_ms',
  'external_response_count'
]);

/**
 * Collapse any provider/observable type string into the bounded usage dimension.
 * @param {string} raw
 * @returns {'ip'|'domain'|'url'|'hash'|'other'}
 */
export function normalizeUsageIocType(raw) {
  const t = String(raw || '').trim().toLowerCase();
  if (!t) return 'other';
  if (t === 'ip' || t === 'ipv4' || t === 'ipv6' || t === 'ip_address') return 'ip';
  if (t === 'domain' || t === 'hostname' || t === 'fqdn' || t === 'host') return 'domain';
  if (t === 'url' || t === 'uri') return 'url';
  if (t === 'hash' || t === 'file_hash' || t === 'filehash'
    || t === 'sha256' || t === 'sha1' || t === 'md5' || t === 'sha512') return 'hash';
  return 'other';
}

/** Zeroed counter delta. */
export function emptyUsageDelta() {
  const delta = {};
  for (const key of COUNTER_KEYS) delta[key] = 0;
  return delta;
}

function coerceCount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

/**
 * Build a counter delta for a single classified logical request.
 * @param {object} outcome
 * @param {'success'|'failure'} outcome.outcome  terminal classification
 * @param {boolean} [outcome.external]     a real outbound provider call was made
 * @param {boolean} [outcome.cacheHit]     served from cache (no external call)
 * @param {boolean} [outcome.rateLimited]  external call was rate limited
 * @param {number}  [outcome.responseTimeMs] latency of the external call (external only)
 * @param {number}  [outcome.count]        logical requests represented (default 1)
 */
export function buildUsageDelta({
  outcome,
  external = false,
  cacheHit = false,
  rateLimited = false,
  responseTimeMs = null,
  count = 1
} = {}) {
  // count defaults to 1 (single request); an explicit 0 must yield a zero delta so
  // bulk callers can pass per-category counts (some of which are legitimately zero).
  const n = count === undefined || count === null ? 1 : coerceCount(count);
  const isExternal = external === true;
  const hasLatency = isExternal
    && Number.isFinite(Number(responseTimeMs))
    && Number(responseTimeMs) >= 0;
  return {
    request_count: n,
    external_call_count: isExternal ? n : 0,
    cache_hit_count: cacheHit === true ? n : 0,
    success_count: outcome === 'success' ? n : 0,
    failure_count: outcome === 'failure' ? n : 0,
    rate_limit_count: rateLimited === true ? n : 0,
    total_external_response_time_ms: hasLatency ? Math.round(Number(responseTimeMs)) : 0,
    external_response_count: hasLatency ? n : 0
  };
}

/** Sum a list of counter deltas (used to fold a bulk request into one upsert). */
export function sumUsageDeltas(deltas) {
  const total = emptyUsageDelta();
  for (const delta of deltas || []) {
    if (!delta) continue;
    for (const key of COUNTER_KEYS) total[key] += coerceCount(delta[key]);
  }
  return total;
}

/** True when a delta carries at least one non-zero counter (nothing to write otherwise). */
export function usageDeltaHasData(delta) {
  if (!delta) return false;
  return COUNTER_KEYS.some((key) => coerceCount(delta[key]) > 0);
}

/** SQL + ordered params for the atomic daily upsert. Exposed for unit testing. */
export function buildUsageUpsert(providerKey, iocType, delta) {
  // Bucket by the canonical TalonHound System Timezone, which is the app-wide
  // definition of "today" (system_settings.active_system_timezone; the pool's session
  // TimeZone is set to it). CURRENT_DATE therefore yields today in the system tz. The
  // read range and the frontend both resolve "today" in the same system tz, so all
  // three layers agree — never UTC-by-default (the app forbids silent UTC adoption).
  const sql = `INSERT INTO enrichment_usage_daily (
      bucket_date, provider_key, ioc_type,
      request_count, external_call_count, cache_hit_count,
      success_count, failure_count, rate_limit_count,
      total_external_response_time_ms, external_response_count, updated_at
    ) VALUES (CURRENT_DATE, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
    ON CONFLICT (bucket_date, provider_key, ioc_type) DO UPDATE SET
      request_count = enrichment_usage_daily.request_count + EXCLUDED.request_count,
      external_call_count = enrichment_usage_daily.external_call_count + EXCLUDED.external_call_count,
      cache_hit_count = enrichment_usage_daily.cache_hit_count + EXCLUDED.cache_hit_count,
      success_count = enrichment_usage_daily.success_count + EXCLUDED.success_count,
      failure_count = enrichment_usage_daily.failure_count + EXCLUDED.failure_count,
      rate_limit_count = enrichment_usage_daily.rate_limit_count + EXCLUDED.rate_limit_count,
      total_external_response_time_ms = enrichment_usage_daily.total_external_response_time_ms + EXCLUDED.total_external_response_time_ms,
      external_response_count = enrichment_usage_daily.external_response_count + EXCLUDED.external_response_count,
      updated_at = NOW()`;
  const params = [
    String(providerKey),
    String(iocType),
    delta.request_count,
    delta.external_call_count,
    delta.cache_hit_count,
    delta.success_count,
    delta.failure_count,
    delta.rate_limit_count,
    delta.total_external_response_time_ms,
    delta.external_response_count
  ];
  return { sql, params };
}

/**
 * Persist a pre-aggregated counter delta. Best-effort: never throws.
 * @returns {Promise<boolean>} true when a row was written, false on skip/failure.
 */
export async function writeEnrichmentUsage(pool, { provider, iocType, delta, logger = defaultLogger } = {}) {
  try {
    if (!pool || typeof pool.query !== 'function') return false;
    const providerKey = String(provider || '').trim();
    if (!providerKey) return false;
    if (!usageDeltaHasData(delta)) return false;
    const normalizedType = normalizeUsageIocType(iocType);
    const { sql, params } = buildUsageUpsert(providerKey, normalizedType, delta);
    await pool.query(sql, params);
    return true;
  } catch (err) {
    // Analytics must never break enrichment. Log and move on.
    try {
      logger?.warn?.('enrichment usage telemetry write failed', {
        provider,
        error: String(err?.message || err)
      });
    } catch { /* logging must not throw */ }
    return false;
  }
}

/**
 * Record a single classified logical enrichment request. Best-effort: never throws.
 * @see buildUsageDelta for the outcome descriptor.
 */
export async function recordEnrichmentUsage(pool, {
  provider,
  iocType,
  outcome,
  external = false,
  cacheHit = false,
  rateLimited = false,
  responseTimeMs = null,
  count = 1,
  logger = defaultLogger
} = {}) {
  const delta = buildUsageDelta({ outcome, external, cacheHit, rateLimited, responseTimeMs, count });
  const written = await writeEnrichmentUsage(pool, { provider, iocType, delta, logger });
  if (external) {
    await recordProviderHealthSignal(pool, { provider, outcome, rateLimited });
  }
  return written;
}
