// Read side of the Enrichment Usage analytics page.
//
// Pure query/validation/shape helpers. All SQL is parameterized and reads ONLY from
// the small pre-aggregated enrichment_usage_daily table (never ioc_items /
// ioc_enrichments / audit_logs). The route issues a small, fixed number of these
// queries per request (provider breakdown + time series + type breakdown +
// collection start), so there is no per-provider N+1 and no multi-million-row scan.

import { USAGE_IOC_TYPES } from './enrichmentUsageTelemetry.js';

export const RANGE_PRESETS = Object.freeze(['today', 'last_7_days', 'last_30_days', 'custom']);
export const DEFAULT_RANGE_PRESET = 'last_30_days';
export const MAX_RANGE_DAYS = 366;

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** UTC 'YYYY-MM-DD' for a Date (defaults to now). Matches Postgres CURRENT_DATE in UTC. */
export function toIsoDate(date = new Date()) {
  const d = date instanceof Date ? date : new Date(date);
  return d.toISOString().slice(0, 10);
}

function isValidIsoDate(value) {
  if (!DATE_RE.test(String(value || ''))) return false;
  const d = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(d.getTime()) && toIsoDate(d) === value;
}

function addDays(isoDate, days) {
  const d = new Date(`${isoDate}T00:00:00.000Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return toIsoDate(d);
}

/** Inclusive day count between two ISO dates. */
export function daysBetween(fromIso, toIso) {
  const from = new Date(`${fromIso}T00:00:00.000Z`).getTime();
  const to = new Date(`${toIso}T00:00:00.000Z`).getTime();
  return Math.floor((to - from) / 86400000) + 1;
}

/**
 * Resolve the date range from query params.
 *
 * `todayArg` is the canonical "today" (a 'YYYY-MM-DD' string), which callers MUST
 * supply from the DB session clock (SELECT CURRENT_DATE) so it is expressed in the
 * TalonHound System Timezone — the same tz the telemetry write buckets on and the
 * frontend renders in. `addDays`/`daysBetween` below are pure calendar-string
 * arithmetic (timezone-agnostic), so only this anchor date carries the tz. A Date is
 * tolerated as a defensive fallback only; production always passes CURRENT_DATE.
 *
 * @returns {{ok:true, from:string, to:string, preset:string}|{ok:false, error:string}}
 */
export function resolveRange({ range, from, to } = {}, todayArg) {
  const today = (typeof todayArg === 'string' && isValidIsoDate(todayArg))
    ? todayArg
    : toIsoDate(todayArg instanceof Date ? todayArg : new Date());
  const preset = String(range || '').trim().toLowerCase();

  if (!preset || preset === DEFAULT_RANGE_PRESET) {
    return { ok: true, from: addDays(today, -29), to: today, preset: DEFAULT_RANGE_PRESET };
  }
  if (preset === 'today') {
    return { ok: true, from: today, to: today, preset: 'today' };
  }
  if (preset === 'last_7_days') {
    return { ok: true, from: addDays(today, -6), to: today, preset: 'last_7_days' };
  }
  if (preset === 'custom') {
    if (!isValidIsoDate(from) || !isValidIsoDate(to)) {
      return { ok: false, error: 'from and to must be valid YYYY-MM-DD dates for a custom range' };
    }
    if (from > to) {
      return { ok: false, error: 'from must not be after to' };
    }
    if (daysBetween(from, to) > MAX_RANGE_DAYS) {
      return { ok: false, error: `date range must not exceed ${MAX_RANGE_DAYS} days` };
    }
    return { ok: true, from, to, preset: 'custom' };
  }
  return { ok: false, error: `range must be one of: ${RANGE_PRESETS.join(', ')}` };
}

/**
 * Resolve the provider filter against the known provider keys.
 * Empty / 'all' => no filter. Unknown => rejected.
 */
export function resolveProviderFilter(provider, knownKeys = []) {
  const raw = String(provider || '').trim().toLowerCase();
  if (!raw || raw === 'all') return { ok: true, provider: null };
  const known = new Set((knownKeys || []).map((k) => String(k).toLowerCase()));
  if (!known.has(raw)) return { ok: false, error: 'unknown provider' };
  return { ok: true, provider: raw };
}

/** Resolve the IOC-type filter. Empty / 'all' => no filter. Unknown => rejected. */
export function resolveIocTypeFilter(iocType) {
  const raw = String(iocType || '').trim().toLowerCase();
  if (!raw || raw === 'all') return { ok: true, iocType: null };
  if (!USAGE_IOC_TYPES.includes(raw)) return { ok: false, error: 'unknown iocType' };
  return { ok: true, iocType: raw };
}

/**
 * Validate + normalize the whole query. On failure returns { ok:false, status, error }.
 * @returns {{ok:true, params:{from,to,preset,provider,iocType}}|{ok:false, status:number, error:string}}
 */
export function parseUsageQuery(query = {}, { knownProviders = [], today } = {}) {
  const range = resolveRange(query, today);
  if (!range.ok) return { ok: false, status: 400, error: range.error };

  const providerFilter = resolveProviderFilter(query.provider, knownProviders);
  if (!providerFilter.ok) return { ok: false, status: 400, error: providerFilter.error };

  const typeFilter = resolveIocTypeFilter(query.iocType ?? query.ioc_type);
  if (!typeFilter.ok) return { ok: false, status: 400, error: typeFilter.error };

  return {
    ok: true,
    params: {
      from: range.from,
      to: range.to,
      preset: range.preset,
      provider: providerFilter.provider,
      iocType: typeFilter.iocType
    }
  };
}

// --- SQL builders -----------------------------------------------------------

const SUM_COLUMNS = `
    COALESCE(SUM(request_count), 0)::bigint AS request_count,
    COALESCE(SUM(external_call_count), 0)::bigint AS external_call_count,
    COALESCE(SUM(cache_hit_count), 0)::bigint AS cache_hit_count,
    COALESCE(SUM(success_count), 0)::bigint AS success_count,
    COALESCE(SUM(failure_count), 0)::bigint AS failure_count,
    COALESCE(SUM(rate_limit_count), 0)::bigint AS rate_limit_count,
    COALESCE(SUM(total_external_response_time_ms), 0)::bigint AS total_external_response_time_ms,
    COALESCE(SUM(external_response_count), 0)::bigint AS external_response_count`;

function whereClause({ from, to, provider, iocType }, startIndex = 1) {
  const clauses = ['bucket_date BETWEEN $1 AND $2'];
  const params = [from, to];
  let idx = startIndex + 2;
  if (provider) { clauses.push(`provider_key = $${idx}`); params.push(provider); idx += 1; }
  if (iocType) { clauses.push(`ioc_type = $${idx}`); params.push(iocType); idx += 1; }
  return { text: clauses.join(' AND '), params };
}

/** Per-provider totals over the range (respects the ioc-type filter, not the provider filter). */
export function buildProviderBreakdownQuery({ from, to, iocType } = {}) {
  const where = whereClause({ from, to, iocType });
  return {
    sql: `SELECT provider_key,${SUM_COLUMNS}
      FROM enrichment_usage_daily
      WHERE ${where.text}
      GROUP BY provider_key`,
    params: where.params
  };
}

/** Daily time series over the range (respects provider + ioc-type filters). */
export function buildSeriesQuery({ from, to, provider, iocType } = {}) {
  const where = whereClause({ from, to, provider, iocType });
  return {
    sql: `SELECT bucket_date::text AS date,${SUM_COLUMNS}
      FROM enrichment_usage_daily
      WHERE ${where.text}
      GROUP BY bucket_date
      ORDER BY bucket_date ASC`,
    params: where.params
  };
}

/** Per-IOC-type totals over the range (respects the provider filter, not the type filter). */
export function buildTypeBreakdownQuery({ from, to, provider } = {}) {
  const where = whereClause({ from, to, provider });
  return {
    sql: `SELECT ioc_type,${SUM_COLUMNS}
      FROM enrichment_usage_daily
      WHERE ${where.text}
      GROUP BY ioc_type`,
    params: where.params
  };
}

/** Earliest bucket_date ever recorded (telemetry collection start). */
export function buildCollectionStartQuery() {
  return { sql: 'SELECT MIN(bucket_date)::text AS started_on FROM enrichment_usage_daily', params: [] };
}

// --- Shaping ----------------------------------------------------------------

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

/** Round to at most 1 decimal place. */
function round1(value) {
  return Math.round(num(value) * 10) / 10;
}

/** Derive rates + avg latency from a raw counter row. */
export function deriveMetrics(row = {}) {
  const request = num(row.request_count);
  const external = num(row.external_call_count);
  const cache = num(row.cache_hit_count);
  const success = num(row.success_count);
  const failure = num(row.failure_count);
  const rateLimit = num(row.rate_limit_count);
  const totalMs = num(row.total_external_response_time_ms);
  const extRespCount = num(row.external_response_count);
  const completed = success + failure;
  return {
    request_count: request,
    external_call_count: external,
    cache_hit_count: cache,
    success_count: success,
    failure_count: failure,
    rate_limit_count: rateLimit,
    // cache hit rate is against logical requests (cache hits + external attempts)
    cache_hit_rate: request > 0 ? round1((cache / request) * 100) : null,
    success_rate: completed > 0 ? round1((success / completed) * 100) : null,
    avg_external_response_time_ms: extRespCount > 0 ? Math.round(totalMs / extRespCount) : null
  };
}

/** Fold provider rows into overall summary metrics. */
export function summarizeProviderRows(rows = []) {
  const totals = {
    request_count: 0,
    external_call_count: 0,
    cache_hit_count: 0,
    success_count: 0,
    failure_count: 0,
    rate_limit_count: 0,
    total_external_response_time_ms: 0,
    external_response_count: 0
  };
  for (const row of rows) {
    for (const key of Object.keys(totals)) totals[key] += num(row[key]);
  }
  return deriveMetrics(totals);
}

/**
 * Merge aggregate provider rows with the provider registry so every known provider
 * appears (even with zero usage / disabled), and unknown-but-recorded providers
 * (renamed / removed) are still surfaced. Sorted by external calls desc, then requests.
 * @param {Array} rows           aggregate rows keyed by provider_key
 * @param {Array} registry       [{ key, displayName, enabled, configured, quota }]
 */
export function shapeProviderBreakdown(rows = [], registry = []) {
  const byKey = new Map(rows.map((r) => [String(r.provider_key), r]));
  const registryByKey = new Map(registry.map((p) => [String(p.key), p]));
  const keys = new Set([...byKey.keys(), ...registryByKey.keys()]);

  const providers = [...keys].map((key) => {
    const meta = registryByKey.get(key) || null;
    const metrics = deriveMetrics(byKey.get(key) || {});
    return {
      provider_key: key,
      display_name: meta?.displayName || key,
      known: Boolean(meta),
      enabled: meta ? meta.enabled !== false : null,
      configured: meta ? meta.configured !== false : null,
      quota: meta?.quota || null,
      ...metrics
    };
  });

  providers.sort((a, b) => {
    if (b.external_call_count !== a.external_call_count) return b.external_call_count - a.external_call_count;
    if (b.request_count !== a.request_count) return b.request_count - a.request_count;
    return String(a.display_name).localeCompare(String(b.display_name));
  });
  return providers;
}

/** Shape the ioc-type breakdown rows (stable order matching USAGE_IOC_TYPES). */
export function shapeTypeBreakdown(rows = []) {
  const byType = new Map(rows.map((r) => [String(r.ioc_type), r]));
  return USAGE_IOC_TYPES
    .filter((t) => byType.has(t))
    .map((t) => ({ ioc_type: t, ...deriveMetrics(byType.get(t)) }));
}

/**
 * Normalize an optional, operator-configured quota descriptor into a safe shape, or
 * null when no reliable quota is known. Quota is NEVER inferred from usage: only an
 * explicit numeric limit (optionally with a provider-reported `used`) is surfaced.
 * Future source: threat_intel_provider_configs.config->'quota'.
 * @param {any} raw expected shape { limit, used?, window?, source? }
 */
export function normalizeProviderQuota(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const limit = Number(raw.limit);
  if (!Number.isFinite(limit) || limit <= 0) return null; // no reliable limit => unavailable
  const usedRaw = Number(raw.used);
  const hasUsed = Number.isFinite(usedRaw) && usedRaw >= 0;
  const window = ['daily', 'monthly', 'hourly', 'total'].includes(String(raw.window))
    ? String(raw.window)
    : null;
  return {
    limit,
    used: hasUsed ? usedRaw : null,
    // percentage only when the provider/config supplies a real used figure
    used_pct: hasUsed ? round1((usedRaw / limit) * 100) : null,
    window,
    source: typeof raw.source === 'string' ? raw.source : 'configured'
  };
}

/** Shape the daily series rows into plain counter objects (zeros filled client-side). */
export function shapeSeries(rows = []) {
  return rows.map((r) => ({
    date: String(r.date),
    request_count: num(r.request_count),
    external_call_count: num(r.external_call_count),
    cache_hit_count: num(r.cache_hit_count),
    success_count: num(r.success_count),
    failure_count: num(r.failure_count),
    rate_limit_count: num(r.rate_limit_count)
  }));
}
