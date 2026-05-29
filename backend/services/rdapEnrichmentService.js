/**
 * On-demand RDAP domain enrichment (no DNS lookups).
 * Resolves authoritative RDAP servers via IANA bootstrap (data.iana.org/rdap/dns.json).
 */

import { resolveRdapDomainUrlCandidates } from '../lib/rdapBootstrap.js';

const RDAP_TIMEOUT_MS = Number(process.env.RDAP_TIMEOUT_MS || 10000);
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const FORCE_COOLDOWN_MS = 5 * 60 * 1000;
const FAILED_CACHE_MS = 60 * 60 * 1000;
const MAX_CONCURRENCY = Math.min(Math.max(Number(process.env.RDAP_MAX_CONCURRENCY || 3), 1), 5);
const RDAP_USER_AGENT = String(
  process.env.RDAP_USER_AGENT || 'demo-runbook-rdap/1.0 (+https://github.com/spatronn/demo-runbook)'
).trim();

const RDAP_BASE = String(process.env.RDAP_BASE_URL || 'https://rdap.org').replace(/\/$/, '');

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

function parseIsoDate(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function normalizeEventAction(action) {
  return String(action || '').trim().toLowerCase().replace(/_/g, ' ');
}

function pickEventDate(events, matchers) {
  if (!Array.isArray(events)) return null;
  for (const ev of events) {
    const act = normalizeEventAction(ev?.eventAction);
    if (matchers.some((m) => act === m || act.includes(m))) {
      const dt = parseIsoDate(ev?.eventDate);
      if (dt) return dt;
    }
  }
  return null;
}

function parseVcardName(vcardArray) {
  if (!Array.isArray(vcardArray) || vcardArray.length < 2) return null;
  const entries = vcardArray[1];
  if (!Array.isArray(entries)) return null;
  for (const row of entries) {
    if (!Array.isArray(row) || row.length < 4) continue;
    const key = String(row[0] || '').toLowerCase();
    if (key === 'fn' || key === 'org') {
      const val = String(row[3] || '').trim();
      if (val) return val;
    }
  }
  return null;
}

function extractRegistrar(entities) {
  if (!Array.isArray(entities)) return null;
  for (const ent of entities) {
    const roles = Array.isArray(ent?.roles) ? ent.roles.map((r) => String(r).toLowerCase()) : [];
    if (!roles.includes('registrar')) continue;
    const fromVcard = parseVcardName(ent?.vcardArray);
    if (fromVcard) return fromVcard;
    const handle = String(ent?.handle || '').trim();
    if (handle) return handle;
  }
  return null;
}

function extractNameservers(nameservers) {
  if (!Array.isArray(nameservers)) return [];
  const out = [];
  for (const ns of nameservers) {
    const name = String(ns?.ldhName || ns?.unicodeName || ns?.objectClassName || '').trim().toLowerCase();
    if (name && !out.includes(name)) out.push(name);
  }
  return out;
}

function extractStatuses(status) {
  if (!Array.isArray(status)) return [];
  return status.map((s) => String(s || '').trim()).filter(Boolean);
}

function detectRedactedOrPrivate(raw) {
  try {
    const blob = JSON.stringify(raw).toLowerCase();
    const hints = ['redacted', 'privacy', 'withheld', 'gdpr', 'data protected', 'not disclosed', 'private'];
    return hints.some((h) => blob.includes(h));
  } catch {
    return false;
  }
}

/**
 * @param {object} raw RDAP JSON
 * @param {string} rootDomain
 */
export function parseRdapDomainResponse(raw, rootDomain) {
  const registrationDate = pickEventDate(raw?.events, ['registration', 'registered']);
  const expirationDate = pickEventDate(raw?.events, ['expiration', 'expiry', 'expire']);
  const lastChangedDate = pickEventDate(raw?.events, ['last changed', 'last update', 'changed', 'last modified']);

  let domainAgeDays = null;
  if (registrationDate) {
    const regMs = Date.parse(registrationDate);
    if (Number.isFinite(regMs)) {
      domainAgeDays = Math.max(0, Math.floor((Date.now() - regMs) / 86400000));
    }
  }

  const nameservers = extractNameservers(raw?.nameservers);
  const statuses = extractStatuses(raw?.status);
  const registrar = extractRegistrar(raw?.entities);

  const record = {
    rdap_status: 'success',
    registrar,
    registration_date: registrationDate,
    expiration_date: expirationDate,
    last_changed_date: lastChangedDate,
    domain_age_days: domainAgeDays,
    nameservers,
    statuses,
    rdap_raw_json: raw,
    error_message: null
  };

  record.derived_signals = buildDerivedSignals(record, rootDomain);
  return record;
}

export function buildDerivedSignals(record, rootDomain) {
  const now = Date.now();
  const regMs = record.registration_date ? Date.parse(record.registration_date) : NaN;
  const expMs = record.expiration_date ? Date.parse(record.expiration_date) : NaN;
  let domainAgeDays = record.domain_age_days;
  if (domainAgeDays == null && Number.isFinite(regMs)) {
    domainAgeDays = Math.max(0, Math.floor((now - regMs) / 86400000));
  }

  const newlyRegistered = domainAgeDays != null ? domainAgeDays <= 30 : null;
  const expiringSoon = Number.isFinite(expMs)
    ? expMs > now && (expMs - now) <= 30 * 86400000
    : null;

  const nameservers = Array.isArray(record.nameservers) ? record.nameservers : [];
  const statuses = Array.isArray(record.statuses) ? record.statuses : [];

  return {
    rdap_available: record.rdap_status === 'success',
    newly_registered_domain: newlyRegistered === true,
    domain_age_days: domainAgeDays,
    expiring_soon: expiringSoon === true,
    registrar_available: Boolean(record.registrar),
    nameserver_count: nameservers.length,
    nameservers_available: nameservers.length > 0,
    statuses_available: statuses.length > 0,
    redacted_or_private: detectRedactedOrPrivate(record.rdap_raw_json),
    root_domain: rootDomain
  };
}

function isAbortError(err) {
  return err?.name === 'AbortError'
    || err?.code === 'ABORT_ERR'
    || /aborted/i.test(String(err?.message || ''));
}

function wrapRdapFetchError(err) {
  if (isAbortError(err)) {
    const timeoutErr = new Error(`RDAP lookup timed out after ${RDAP_TIMEOUT_MS}ms`);
    timeoutErr.code = 'timeout';
    return timeoutErr;
  }
  return err;
}

async function fetchRdapJsonFromUrl(url, signal) {
  const res = await fetch(url, {
    headers: {
      Accept: 'application/rdap+json, application/json',
      'User-Agent': RDAP_USER_AGENT
    },
    signal,
    redirect: 'follow'
  });

  if (res.status === 429) {
    const retryAfter = res.headers.get('retry-after');
    const err = new Error('RDAP rate limit reached');
    err.code = 'rate_limit';
    err.retryAfter = retryAfter;
    throw err;
  }

  if (res.status === 404) {
    const err = new Error('RDAP data not found for domain');
    err.code = 'not_found';
    throw err;
  }

  if (!res.ok) {
    const err = new Error(`RDAP lookup failed (${res.status})`);
    err.code = 'http_error';
    err.status = res.status;
    throw err;
  }

  return await res.json();
}

/**
 * Fetch RDAP JSON for a root domain via IANA bootstrap (fallback: rdap.org).
 * @param {string} rootDomain
 */
export async function fetchRdapDomain(rootDomain) {
  await acquireSlot();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), RDAP_TIMEOUT_MS);
  try {
    const urls = await resolveRdapDomainUrlCandidates(rootDomain, { fallbackBase: RDAP_BASE });
    let lastErr = null;
    for (const url of urls) {
      try {
        return await fetchRdapJsonFromUrl(url, ctrl.signal);
      } catch (err) {
        lastErr = wrapRdapFetchError(err);
        if (lastErr.code === 'rate_limit' || lastErr.code === 'not_found' || lastErr.code === 'timeout') {
          throw lastErr;
        }
      }
    }
    throw lastErr || new Error('RDAP lookup failed');
  } catch (err) {
    throw wrapRdapFetchError(err);
  } finally {
    clearTimeout(timer);
    releaseSlot();
  }
}

export function rowToApiPayload(row, {
  cached = false,
  enriched = true,
  observableValue,
  rootDomain,
  iocType,
  original_value = null,
  normalized_host = null,
  rdap_domain = null,
  input_type = null
} = {}) {
  const rdapDomain = rdap_domain || rootDomain;
  const normHost = normalized_host || observableValue;

  if (!row) {
    return {
      enriched: false,
      cached: false,
      observable_value: observableValue,
      root_domain: rdapDomain,
      rdap_domain: rdapDomain,
      normalized_host: normHost,
      original_value: original_value || observableValue,
      input_type,
      ioc_type: iocType
    };
  }

  const signals = row.derived_signals && typeof row.derived_signals === 'object'
    ? row.derived_signals
    : {};

  return {
    enriched: enriched && row.rdap_status === 'success',
    cached,
    observable_value: row.observable_value || observableValue,
    root_domain: row.root_domain || rdapDomain,
    rdap_domain: row.root_domain || rdapDomain,
    normalized_host: normHost || row.observable_value || observableValue,
    original_value: original_value || null,
    input_type: input_type || row.ioc_type || iocType,
    ioc_type: row.ioc_type || iocType,
    rdap_status: row.rdap_status,
    registrar: row.registrar,
    registration_date: row.registration_date,
    expiration_date: row.expiration_date,
    last_changed_date: row.last_changed_date,
    domain_age_days: row.domain_age_days,
    nameservers: Array.isArray(row.nameservers) ? row.nameservers : [],
    statuses: Array.isArray(row.statuses) ? row.statuses : [],
    derived_signals: signals,
    error_message: row.error_message,
    last_enriched_at: row.last_enriched_at
  };
}

export function isCacheFresh(row, { force = false } = {}) {
  if (!row?.last_enriched_at) return false;
  const at = Date.parse(row.last_enriched_at);
  if (!Number.isFinite(at)) return false;

  const ageMs = Date.now() - at;
  if (row.rdap_status === 'failed') {
    return ageMs < FAILED_CACHE_MS;
  }

  if (force) {
    const signals = row.derived_signals || {};
    const lastForce = signals.last_force_refresh_at ? Date.parse(signals.last_force_refresh_at) : NaN;
    if (Number.isFinite(lastForce) && (Date.now() - lastForce) < FORCE_COOLDOWN_MS) {
      return true;
    }
    return false;
  }

  return row.rdap_status === 'success' && ageMs < CACHE_TTL_MS;
}

export async function getEnrichmentByRootDomain(pool, rootDomain) {
  const { rows } = await pool.query(
    `SELECT * FROM ioc_domain_enrichment WHERE root_domain = $1 LIMIT 1`,
    [rootDomain]
  );
  return rows[0] || null;
}

export async function upsertEnrichment(pool, {
  observableValue,
  rootDomain,
  iocType,
  record
}) {
  const now = new Date().toISOString();
  const { rows } = await pool.query(
    `INSERT INTO ioc_domain_enrichment (
      observable_value, root_domain, ioc_type,
      rdap_status, registrar, registration_date, expiration_date, last_changed_date, domain_age_days,
      nameservers, statuses, derived_signals, rdap_raw_json, error_message, last_enriched_at, updated_at
    ) VALUES (
      $1, $2, $3,
      $4, $5, $6, $7, $8, $9,
      $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb, $14, $15::timestamptz, NOW()
    )
    ON CONFLICT (root_domain) DO UPDATE SET
      observable_value = EXCLUDED.observable_value,
      ioc_type = EXCLUDED.ioc_type,
      rdap_status = EXCLUDED.rdap_status,
      registrar = EXCLUDED.registrar,
      registration_date = EXCLUDED.registration_date,
      expiration_date = EXCLUDED.expiration_date,
      last_changed_date = EXCLUDED.last_changed_date,
      domain_age_days = EXCLUDED.domain_age_days,
      nameservers = EXCLUDED.nameservers,
      statuses = EXCLUDED.statuses,
      derived_signals = EXCLUDED.derived_signals,
      rdap_raw_json = EXCLUDED.rdap_raw_json,
      error_message = EXCLUDED.error_message,
      last_enriched_at = EXCLUDED.last_enriched_at,
      updated_at = NOW()
    RETURNING *`,
    [
      observableValue,
      rootDomain,
      iocType,
      record.rdap_status,
      record.registrar,
      record.registration_date,
      record.expiration_date,
      record.last_changed_date,
      record.domain_age_days,
      JSON.stringify(record.nameservers || []),
      JSON.stringify(record.statuses || []),
      JSON.stringify(record.derived_signals || {}),
      record.rdap_raw_json ? JSON.stringify(record.rdap_raw_json) : null,
      record.error_message,
      now
    ]
  );
  return rows[0];
}

export async function refreshRdapEnrichment(pool, parsed, { force = false } = {}) {
  const observableValue = parsed.observable_value || parsed.normalized_host;
  const rootDomain = parsed.rdap_domain || parsed.root_domain;
  const iocType = parsed.ioc_type;
  const existing = await getEnrichmentByRootDomain(pool, rootDomain);

  // POST refresh is user-initiated: retry after failures; only short-circuit fresh successes.
  if (existing?.rdap_status === 'success' && isCacheFresh(existing, { force })) {
    return {
      row: existing,
      cached: true,
      fromLookup: false
    };
  }

  try {
    const raw = await fetchRdapDomain(rootDomain);
    const record = parseRdapDomainResponse(raw, rootDomain);
    record.derived_signals = {
      ...record.derived_signals,
      ...(force ? { last_force_refresh_at: new Date().toISOString() } : {})
    };
    const row = await upsertEnrichment(pool, { observableValue, rootDomain, iocType, record });
    return { row, cached: false, fromLookup: true };
  } catch (err) {
    const failedRecord = {
      rdap_status: err.code === 'not_found' ? 'unavailable' : 'failed',
      registrar: null,
      registration_date: null,
      expiration_date: null,
      last_changed_date: null,
      domain_age_days: null,
      nameservers: [],
      statuses: [],
      rdap_raw_json: null,
      error_message: String(err?.message || 'RDAP lookup failed').slice(0, 2000),
      derived_signals: buildDerivedSignals({ rdap_status: 'failed' }, rootDomain)
    };
    if (force) {
      failedRecord.derived_signals.last_force_refresh_at = new Date().toISOString();
    }
    const row = await upsertEnrichment(pool, {
      observableValue,
      rootDomain,
      iocType,
      record: failedRecord
    });
    return { row, cached: false, fromLookup: true, error: err };
  }
}

/** Admin Enrichment Providers page — RDAP is built-in (no API key). */
export function getRdapProviderAdminSummary() {
  const enabled = process.env.RDAP_ENABLED !== '0';
  return {
    provider: 'rdap',
    name: 'RDAP / WHOIS',
    enabled,
    configured: true,
    auth_required: false,
    status: enabled ? 'healthy' : 'disabled',
    rdap_base_url: RDAP_BASE,
    iana_bootstrap_url: 'https://data.iana.org/rdap/dns.json',
    cache_ttl_hours: Math.round(CACHE_TTL_MS / (60 * 60 * 1000)),
    timeout_ms: RDAP_TIMEOUT_MS,
    max_concurrency: MAX_CONCURRENCY,
    description: 'Public RDAP domain registration lookups for domain and URL IOCs. On-demand from IOC Details > Intelligence.'
  };
}
