/**
 * Manual-only DNSMania enrichment (passive DNS history).
 * External calls only on user Enrich / Refresh — GET returns cached DB row.
 */

import { normalizeDnsmaniaLookup } from '../lib/dnsmaniaTarget.js';

export const DNSMANIA_PROVIDER = 'dnsmania';
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_LIMIT = 50;
const DEFAULT_IP_LIMIT = 5;
const MAX_RAW_JSON_CHARS = 256 * 1024;
const MAX_CONCURRENCY = 3;

let activeLookups = 0;
const waiters = [];

function acquireSlot() {
  if (activeLookups < MAX_CONCURRENCY) {
    activeLookups += 1;
    return Promise.resolve();
  }
  return new Promise((resolve) => waiters.push(resolve));
}

function releaseSlot() {
  activeLookups = Math.max(0, activeLookups - 1);
  const next = waiters.shift();
  if (next) {
    activeLookups += 1;
    next();
  }
}

function parseBoolEnv(raw, defaultValue = true) {
  if (raw == null || raw === '') return defaultValue;
  const v = String(raw).trim().toLowerCase();
  if (['0', 'false', 'no', 'off'].includes(v)) return false;
  if (['1', 'true', 'yes', 'on'].includes(v)) return true;
  return defaultValue;
}

export function getDnsmaniaConfig() {
  const baseUrl = String(process.env.DNSMANIA_BASE_URL || '').trim().replace(/\/+$/, '');
  const timeoutMs = Math.max(Number(process.env.DNSMANIA_TIMEOUT_MS || DEFAULT_TIMEOUT_MS), 1000);
  const enabled = parseBoolEnv(process.env.DNSMANIA_ENABLED, true);
  return {
    provider: DNSMANIA_PROVIDER,
    baseUrl,
    timeoutMs,
    enabled,
    configured: Boolean(baseUrl),
    limit: DEFAULT_LIMIT,
    ipLimit: DEFAULT_IP_LIMIT
  };
}

function truncateRawJson(payload) {
  if (payload == null) return null;
  try {
    const text = JSON.stringify(payload);
    if (text.length <= MAX_RAW_JSON_CHARS) return payload;
    return {
      truncated: true,
      original_bytes: text.length,
      preview: text.slice(0, Math.min(4000, MAX_RAW_JSON_CHARS))
    };
  } catch {
    return { truncated: true, error: 'unserializable_raw_response' };
  }
}

function toIsoOrNull(value) {
  if (value == null || value === '') return null;
  let raw = String(value).trim();
  // DNSMania returns UTC wall-clock without timezone, e.g. "2026-07-17 14:44:30.978"
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(raw)) {
    raw = `${raw.replace(' ', 'T')}Z`;
  }
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function toEpochMs(value) {
  if (value == null || value === '') return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function toNonNegativeFiniteNumber(value) {
  if (value == null || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function isErrorDnsRecordType(recordType) {
  const rt = String(recordType || '').toUpperCase();
  return rt === 'NXDOMAIN' || rt === 'SERVFAIL' || rt === 'REFUSED';
}

function isResolvableDomainRelation(rel) {
  return Boolean(rel?.value);
}

/**
 * Derive latest DNS observation status from normalized relations.
 * Prefer max(last_seen); fall back to first_seen. Same-timestamp A/AAAA/CNAME
 * group as one resolvable observation — do not treat sibling A rows as separate "latest".
 *
 * @param {Array<object>} relations
 * @returns {{
 *   latest_dns_status: string|null,
 *   latest_dns_status_first_seen: string|null,
 *   latest_dns_status_last_seen: string|null,
 *   last_successfully_resolved: string|null,
 *   nxdomain_observed: boolean
 * }}
 */
export function deriveLatestDnsStatusFromRelations(relations) {
  const list = Array.isArray(relations) ? relations : [];
  let latest = null;
  let latestMs = -1;
  let lastResolvedMs = -1;
  let lastResolvedIso = null;
  let nxdomainObserved = false;

  for (const rel of list) {
    const rt = String(rel?.record_type || '').toUpperCase() || null;
    if (isErrorDnsRecordType(rt)) nxdomainObserved = true;

    const ms = toEpochMs(rel?.last_seen) ?? toEpochMs(rel?.first_seen);
    if (ms != null && isResolvableDomainRelation(rel) && ms >= lastResolvedMs) {
      lastResolvedMs = ms;
      lastResolvedIso = toIsoOrNull(rel.last_seen) || toIsoOrNull(rel.first_seen);
    }

    if (ms == null) continue;
    // Prefer error/status rows over sibling A/AAAA answers when timestamps tie
    // (same query often emits multiple A rows in the same second).
    if (ms > latestMs || (ms === latestMs && isErrorDnsRecordType(rt) && !isErrorDnsRecordType(latest?.record_type))) {
      latestMs = ms;
      latest = rel;
    }
  }

  if (!latest) {
    return {
      latest_dns_status: null,
      latest_dns_status_first_seen: null,
      latest_dns_status_last_seen: null,
      last_successfully_resolved: lastResolvedIso,
      nxdomain_observed: nxdomainObserved
    };
  }

  const latestType = String(latest.record_type || '').toUpperCase() || null;
  let status = latestType;
  if (!status && isResolvableDomainRelation(latest)) status = 'RESOLVED';
  if (!status && latest.value == null) status = 'NXDOMAIN';

  return {
    latest_dns_status: status,
    latest_dns_status_first_seen: toIsoOrNull(latest.first_seen),
    latest_dns_status_last_seen: toIsoOrNull(latest.last_seen),
    last_successfully_resolved: lastResolvedIso,
    nxdomain_observed: nxdomainObserved || isErrorDnsRecordType(status)
  };
}

function mergeLatestDnsFields(summary, relations) {
  const derived = deriveLatestDnsStatusFromRelations(relations);
  const timeline = Array.isArray(summary?.dns_timeline) && summary.dns_timeline.length
    ? summary.dns_timeline
    : buildDnsTimelineFromRelations(relations);
  return {
    ...summary,
    latest_dns_status: summary?.latest_dns_status ?? derived.latest_dns_status,
    latest_dns_status_first_seen: summary?.latest_dns_status_first_seen ?? derived.latest_dns_status_first_seen,
    latest_dns_status_last_seen: summary?.latest_dns_status_last_seen ?? derived.latest_dns_status_last_seen,
    last_successfully_resolved: summary?.last_successfully_resolved ?? derived.last_successfully_resolved,
    nxdomain_observed: summary?.nxdomain_observed === true || derived.nxdomain_observed,
    dns_timeline: timeline
  };
}

/**
 * Group DNSMania relation rows into chronological status periods.
 * Sibling A/AAAA answers that share the same first/last seen window collapse into one RESOLVED period.
 * NXDOMAIN/SERVFAIL/REFUSED remain their own periods (API already aggregates observation counts).
 *
 * @param {Array<object>} relations
 * @returns {Array<object>} oldest → newest
 */
export function buildDnsTimelineFromRelations(relations) {
  const list = Array.isArray(relations) ? relations : [];
  const groups = new Map();

  for (const rel of list) {
    const rt = String(rel?.record_type || '').toUpperCase() || null;
    const firstSeen = toIsoOrNull(rel?.first_seen);
    const lastSeen = toIsoOrNull(rel?.last_seen);
    const count = Number.isFinite(Number(rel?.count)) ? Number(rel.count) : 0;
    const isError = isErrorDnsRecordType(rt) || (!rel?.value && !rel?.domain && Boolean(rt));

    if (isError) {
      const key = `err:${rt || 'NXDOMAIN'}:${firstSeen || ''}:${lastSeen || ''}`;
      const existing = groups.get(key);
      if (existing) {
        existing.observation_count += count || 0;
      } else {
        groups.set(key, {
          status: rt || 'NXDOMAIN',
          record_type: rt || 'NXDOMAIN',
          first_seen: firstSeen,
          last_seen: lastSeen,
          observation_count: count || 0,
          values: []
        });
      }
      continue;
    }

    if (!rel?.value && !rel?.domain) continue;

    // Collapse sibling answers that share the same observation window + type.
    const key = `ok:${rt || 'RESOLVED'}:${firstSeen || ''}:${lastSeen || ''}`;
    const existing = groups.get(key);
    const value = rel.value || rel.domain || null;
    if (existing) {
      existing.observation_count += count || 0;
      if (value && !existing.values.includes(value)) existing.values.push(value);
    } else {
      groups.set(key, {
        status: 'RESOLVED',
        record_type: rt || null,
        first_seen: firstSeen,
        last_seen: lastSeen,
        observation_count: count || 0,
        values: value ? [value] : []
      });
    }
  }

  return [...groups.values()].sort((a, b) => {
    const aMs = toEpochMs(a.first_seen) ?? toEpochMs(a.last_seen) ?? 0;
    const bMs = toEpochMs(b.first_seen) ?? toEpochMs(b.last_seen) ?? 0;
    if (aMs !== bMs) return aMs - bMs;
    const aLast = toEpochMs(a.last_seen) ?? 0;
    const bLast = toEpochMs(b.last_seen) ?? 0;
    return aLast - bLast;
  });
}

/**
 * Map DNSMania domain response → normalized payload.
 * @param {object} body
 * @param {string} lookupValue
 */
export function normalizeDnsmaniaDomainResponse(body, lookupValue) {
  const records = Array.isArray(body?.records) ? body.records : [];
  const firstSeen = toIsoOrNull(body?.first_seen);
  const lastSeen = toIsoOrNull(body?.last_seen);
  const known = firstSeen != null || lastSeen != null || records.length > 0;

  const relations = records.map((r) => ({
    record_type: r?.record_type != null ? String(r.record_type) : null,
    value: r?.ip != null ? String(r.ip) : null,
    first_seen: toIsoOrNull(r?.first_seen),
    last_seen: toIsoOrNull(r?.last_seen),
    count: Number.isFinite(Number(r?.count)) ? Number(r.count) : null
  }));

  const latest = deriveLatestDnsStatusFromRelations(relations);
  const dnsTimeline = buildDnsTimelineFromRelations(relations);
  const associatedIpCount = Number.isFinite(Number(body?.unique_ips))
    ? Number(body.unique_ips)
    : relations.filter((r) => r.value).length;
  const observationCount = Number.isFinite(Number(body?.total_observations))
    ? Number(body.total_observations)
    : null;

  return {
    provider: DNSMANIA_PROVIDER,
    status: known ? 'completed' : 'no_data',
    lookup_type: 'domain',
    lookup_value: lookupValue,
    known,
    summary: {
      first_seen: firstSeen,
      last_seen: lastSeen,
      associated_ip_count: associatedIpCount,
      observation_count: observationCount,
      nxdomain_observed: latest.nxdomain_observed,
      latest_dns_status: latest.latest_dns_status,
      latest_dns_status_first_seen: latest.latest_dns_status_first_seen,
      latest_dns_status_last_seen: latest.latest_dns_status_last_seen,
      last_successfully_resolved: latest.last_successfully_resolved,
      dns_timeline: dnsTimeline,
      relation_count: relations.length,
      pagination_returned: body?.pagination?.returned != null ? Number(body.pagination.returned) : relations.length
    },
    relations,
    raw: body
  };
}

/**
 * Map DNSMania IP response → normalized payload.
 * @param {object} body
 * @param {string} lookupValue
 */
export function normalizeDnsmaniaIpResponse(body, lookupValue) {
  const domains = Array.isArray(body?.domains) ? body.domains : [];
  const firstSeen = toIsoOrNull(body?.first_seen);
  const lastSeen = toIsoOrNull(body?.last_seen);
  const known = firstSeen != null || lastSeen != null || domains.length > 0;

  const relations = domains.map((d) => ({
    domain: d?.domain != null ? String(d.domain) : null,
    record_type: d?.record_type != null ? String(d.record_type) : null,
    first_seen: toIsoOrNull(d?.first_seen),
    last_seen: toIsoOrNull(d?.last_seen),
    count: Number.isFinite(Number(d?.count)) ? Number(d.count) : null
  }));

  const associatedDomainCount = toNonNegativeFiniteNumber(body?.unique_domains)
    ?? toNonNegativeFiniteNumber(body?.pagination?.total);
  const observationCount = toNonNegativeFiniteNumber(body?.total_observations);
  const associatedDomainsReturned = toNonNegativeFiniteNumber(body?.pagination?.returned)
    ?? relations.length;

  return {
    provider: DNSMANIA_PROVIDER,
    status: known ? 'completed' : 'no_data',
    lookup_type: 'ip',
    lookup_value: lookupValue,
    known,
    summary: {
      first_seen: firstSeen,
      last_seen: lastSeen,
      associated_domain_count: associatedDomainCount,
      associated_domain_count_is_exact: associatedDomainCount != null,
      associated_domains_returned: associatedDomainsReturned,
      observation_count: observationCount,
      relation_count: relations.length,
      pagination_returned: associatedDomainsReturned
    },
    relations,
    raw: body
  };
}

async function fetchJson(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal
    });
    const text = await res.text();
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        const err = new Error('DNSMania returned malformed JSON');
        err.code = 'malformed_json';
        err.status = res.status;
        throw err;
      }
    }
    if (!res.ok) {
      const msg = body?.error?.message || body?.message || `DNSMania HTTP ${res.status}`;
      const err = new Error(String(msg).slice(0, 500));
      err.code = 'http_error';
      err.status = res.status;
      throw err;
    }
    if (body == null || typeof body !== 'object') {
      const err = new Error('DNSMania returned empty response');
      err.code = 'empty_response';
      throw err;
    }
    return body;
  } catch (err) {
    if (err?.name === 'AbortError' || /aborted/i.test(String(err?.message || ''))) {
      const timeoutErr = new Error('DNSMania request timed out');
      timeoutErr.code = 'timeout';
      throw timeoutErr;
    }
    if (err?.code) throw err;
    const wrapped = new Error(String(err?.message || 'DNSMania request failed').slice(0, 500));
    wrapped.code = 'network_error';
    throw wrapped;
  } finally {
    clearTimeout(timer);
  }
}

export async function lookupDomain(domain, options = {}) {
  const cfg = options.config || getDnsmaniaConfig();
  if (!cfg.configured) {
    const err = new Error('DNSMania base URL is not configured');
    err.code = 'not_configured';
    throw err;
  }
  if (!cfg.enabled) {
    const err = new Error('DNSMania enrichment is currently disabled');
    err.code = 'disabled';
    throw err;
  }
  const limit = Number(options.limit ?? cfg.limit) || DEFAULT_LIMIT;
  const encoded = encodeURIComponent(domain);
  const url = `${cfg.baseUrl}/api/v1/domain/${encoded}?limit=${limit}&offset=0`;
  await acquireSlot();
  try {
    return await fetchJson(url, cfg.timeoutMs);
  } finally {
    releaseSlot();
  }
}

export async function lookupIp(ip, options = {}) {
  const cfg = options.config || getDnsmaniaConfig();
  if (!cfg.configured) {
    const err = new Error('DNSMania base URL is not configured');
    err.code = 'not_configured';
    throw err;
  }
  if (!cfg.enabled) {
    const err = new Error('DNSMania enrichment is currently disabled');
    err.code = 'disabled';
    throw err;
  }
  const limit = Number(options.limit ?? cfg.ipLimit) || DEFAULT_IP_LIMIT;
  const encoded = encodeURIComponent(ip);
  const url = `${cfg.baseUrl}/api/v1/ip/${encoded}?limit=${limit}&offset=0`;
  await acquireSlot();
  try {
    return await fetchJson(url, cfg.timeoutMs);
  } finally {
    releaseSlot();
  }
}

export async function getEnrichmentByLookupKey(pool, lookupKey) {
  const { rows } = await pool.query(
    `SELECT * FROM ioc_dnsmania_enrichment WHERE lookup_key = $1 LIMIT 1`,
    [String(lookupKey)]
  );
  return rows[0] || null;
}

export async function upsertDnsmaniaEnrichment(pool, record) {
  const now = new Date().toISOString();
  const status = String(record.provider_status || 'failed');
  const { rows } = await pool.query(
    `INSERT INTO ioc_dnsmania_enrichment (
       lookup_key, lookup_type, lookup_value, observable_value, ioc_type,
       provider_status, known, normalized_summary, relations_json, raw_json,
       error_code, error_message, enriched_at, last_attempt_at, last_success_at
     ) VALUES (
       $1, $2, $3, $4, $5,
       $6, $7, $8::jsonb, $9::jsonb, $10::jsonb,
       $11, $12, $13::timestamptz, $14::timestamptz, $15::timestamptz
     )
     ON CONFLICT (lookup_key) DO UPDATE SET
       lookup_type = EXCLUDED.lookup_type,
       lookup_value = EXCLUDED.lookup_value,
       observable_value = EXCLUDED.observable_value,
       ioc_type = EXCLUDED.ioc_type,
       provider_status = EXCLUDED.provider_status,
       known = EXCLUDED.known,
       normalized_summary = EXCLUDED.normalized_summary,
       relations_json = EXCLUDED.relations_json,
       raw_json = EXCLUDED.raw_json,
       error_code = EXCLUDED.error_code,
       error_message = EXCLUDED.error_message,
       enriched_at = EXCLUDED.enriched_at,
       last_attempt_at = EXCLUDED.last_attempt_at,
       last_success_at = COALESCE(EXCLUDED.last_success_at, ioc_dnsmania_enrichment.last_success_at),
       updated_at = NOW()
     RETURNING *`,
    [
      record.lookup_key,
      record.lookup_type,
      record.lookup_value,
      record.observable_value,
      record.ioc_type,
      status,
      Boolean(record.known),
      JSON.stringify(record.normalized_summary || {}),
      JSON.stringify(record.relations_json || []),
      record.raw_json != null ? JSON.stringify(truncateRawJson(record.raw_json)) : null,
      record.error_code || null,
      record.error_message || null,
      status === 'completed' || status === 'no_data' ? now : null,
      now,
      status === 'completed' || status === 'no_data' ? now : null
    ]
  );
  return rows[0];
}

/**
 * Manual enrich / refresh — always calls DNSMania when enabled.
 */
export async function enrichIocWithDnsmania(pool, parsed, options = {}) {
  const cfg = options.config || getDnsmaniaConfig();
  const lookupFns = {
    lookupDomain: options.lookupDomainFn || lookupDomain,
    lookupIp: options.lookupIpFn || lookupIp
  };

  if (!cfg.configured) {
    const err = new Error('DNSMania base URL is not configured');
    err.code = 'not_configured';
    throw err;
  }
  if (!cfg.enabled) {
    const err = new Error('DNSMania enrichment is currently disabled');
    err.code = 'disabled';
    throw err;
  }

  try {
    let normalized;
    if (parsed.lookup_type === 'ip') {
      const body = await lookupFns.lookupIp(parsed.lookup_value, { config: cfg });
      normalized = normalizeDnsmaniaIpResponse(body, parsed.lookup_value);
    } else {
      const body = await lookupFns.lookupDomain(parsed.lookup_value, { config: cfg });
      normalized = normalizeDnsmaniaDomainResponse(body, parsed.lookup_value);
    }

    const row = await upsertDnsmaniaEnrichment(pool, {
      lookup_key: parsed.lookup_key,
      lookup_type: parsed.lookup_type,
      lookup_value: parsed.lookup_value,
      observable_value: parsed.observable_value,
      ioc_type: parsed.ioc_type,
      provider_status: normalized.status,
      known: normalized.known,
      normalized_summary: normalized.summary,
      relations_json: normalized.relations,
      raw_json: normalized.raw,
      error_code: null,
      error_message: null
    });

    return { row, fromLookup: true, dataSource: 'provider', error: null };
  } catch (err) {
    const code = String(err?.code || 'failed');
    const message = String(err?.message || 'DNSMania enrichment failed').slice(0, 2000);
    const existing = await getEnrichmentByLookupKey(pool, parsed.lookup_key);
    const row = await upsertDnsmaniaEnrichment(pool, {
      lookup_key: parsed.lookup_key,
      lookup_type: parsed.lookup_type,
      lookup_value: parsed.lookup_value,
      observable_value: parsed.observable_value,
      ioc_type: parsed.ioc_type,
      provider_status: code === 'disabled' ? 'disabled' : 'failed',
      known: false,
      normalized_summary: existing?.normalized_summary || {},
      relations_json: existing?.relations_json || [],
      raw_json: existing?.raw_json || null,
      error_code: code,
      error_message: message
    });
    return { row, fromLookup: true, dataSource: 'error', error: err };
  }
}

export function rowToApiPayload(row, extra = {}) {
  if (!row) {
    return {
      provider: DNSMANIA_PROVIDER,
      status: extra.status || 'not_run',
      enriched: false,
      known: false,
      lookup_type: extra.lookup_type || null,
      lookup_value: extra.lookup_value || null,
      summary: null,
      relations: [],
      enriched_at: null,
      last_attempt_at: null,
      error_code: null,
      error_message: null,
      ...extra
    };
  }

  const summaryRaw = typeof row.normalized_summary === 'string'
    ? JSON.parse(row.normalized_summary)
    : (row.normalized_summary || {});
  const relations = typeof row.relations_json === 'string'
    ? JSON.parse(row.relations_json)
    : (row.relations_json || []);
  const summary = row.lookup_type === 'domain'
    ? mergeLatestDnsFields(summaryRaw, relations)
    : mergeLegacyIpFields(summaryRaw, relations);

  return {
    provider: DNSMANIA_PROVIDER,
    status: row.provider_status,
    enriched: row.provider_status === 'completed' || row.provider_status === 'no_data',
    known: Boolean(row.known),
    lookup_type: row.lookup_type,
    lookup_value: row.lookup_value,
    observable_value: row.observable_value,
    ioc_type: row.ioc_type,
    summary,
    relations: Array.isArray(relations) ? relations : [],
    enriched_at: row.enriched_at,
    last_attempt_at: row.last_attempt_at,
    last_success_at: row.last_success_at,
    error_code: row.error_code,
    error_message: row.error_message,
    cached: Boolean(extra.cached),
    data_source: extra.data_source || null,
    message: extra.message || null,
    ...extra
  };
}

function mergeLegacyIpFields(summary, relations) {
  const existingCount = toNonNegativeFiniteNumber(summary?.associated_domain_count);
  const returnedCount = toNonNegativeFiniteNumber(summary?.associated_domains_returned)
    ?? toNonNegativeFiniteNumber(summary?.pagination_returned)
    ?? (Array.isArray(relations) ? relations.length : 0);
  if (existingCount != null) {
    return {
      ...summary,
      associated_domain_count: existingCount,
      associated_domain_count_is_exact: summary?.associated_domain_count_is_exact === true,
      associated_domains_returned: returnedCount
    };
  }

  const distinctPersistedDomains = new Set(
    (Array.isArray(relations) ? relations : [])
      .map((relation) => String(relation?.domain || '').trim().toLowerCase())
      .filter(Boolean)
  ).size;
  return {
    ...summary,
    associated_domain_count_fallback: distinctPersistedDomains,
    associated_domain_count_is_exact: false,
    associated_domains_returned: returnedCount
  };
}

/** Admin Enrichment Providers page — env-configured, no API key. */
export function getDnsmaniaProviderAdminSummary() {
  const cfg = getDnsmaniaConfig();
  return {
    provider: DNSMANIA_PROVIDER,
    name: 'DNSMania',
    enabled: cfg.enabled && cfg.configured,
    configured: cfg.configured,
    auth_required: false,
    status: !cfg.configured ? 'not_configured' : (cfg.enabled ? 'healthy' : 'disabled'),
    dnsmania_base_url: cfg.baseUrl || null,
    timeout_ms: cfg.timeoutMs,
    max_concurrency: MAX_CONCURRENCY,
    description: 'Passive DNS history from DNSMania (DNSTAP). Manual on-demand enrichment from IOC Details > Intelligence.'
  };
}

export { normalizeDnsmaniaLookup };
