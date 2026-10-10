// Central enrichment-provider registry + capability/state guard.
//
// One place that knows every enrichment provider (identifier, display name, how
// to read its enabled/configured state). The guard is the single choke point all
// enrichment execution entry points call before making any external provider
// call. Adding a provider = add one registry entry; no execution site needs to
// change for the disable policy to apply to it.
//
// State loaders delegate to each provider's existing config getter so the
// enabled/configured semantics stay identical to the rest of the app (VirusTotal
// and IPinfo default to enabled when no row exists; AbuseIPDB defaults to
// disabled; RDAP is env-configured).

//
// Each entry also carries the provider's *capabilities* — the one place that
// answers "which IOC does this provider apply to, against which lookup target,
// and is the stored result still fresh?". Every automated trigger (MCP
// enrich_ioc / bulk_enrich_iocs via lib/enrichmentOrchestrator.js) derives
// provider applicability from here, mirroring the IOC Details UI matrix
// (frontend/src/lib/iocProviderApplicability.js): direct coverage for the IOC's
// own type plus Derived Infrastructure for URL hosts. The provider's *execution*
// stays in its existing UI/REST code path and is attached at startup with
// registerEnrichmentExecutor, so UI, REST and MCP run the same function.

import {
  getIpinfoLiteConfig,
  getEnrichmentByIp as getIpinfoEnrichmentByIp,
  isCacheFresh as isIpinfoCacheFresh
} from '../services/ipinfoLiteService.js';
import {
  getAbuseIpdbConfig,
  getEnrichmentByIp as getAbuseIpdbEnrichmentByIp,
  isCacheFresh as isAbuseIpdbCacheFresh
} from '../services/abuseipdbService.js';
import {
  getUrlscanConfig,
  getUrlscanEnrichmentByIoc,
  isCacheFresh as isUrlscanCacheFresh
} from '../services/urlscanService.js';
import {
  URLSCAN_PROVIDER,
  URLSCAN_SUPPORTED_OBSERVABLE_TYPES,
  isSupportedUrlscanIocType
} from './urlscanEnrichment.js';
import { getRdapProviderAdminSummary, getEnrichmentByRootDomain } from '../services/rdapEnrichmentService.js';
import { getSpamhausDropEnrichmentByIp } from '../services/spamhausDropEnrichmentService.js';
import { getSpamhausDropConfig, getSpamhausDropSyncState } from './spamhausDropSync.js';
import { resolveIpEnrichmentTarget } from './ipEnrichmentEligibility.js';
import { extractIpLiteralFromIoc } from './iocIpExtraction.js';
import { normalizeRdapTarget, isRdapSupportedIocType } from './domainRoot.js';
import { resolveVtEnrichmentRow } from './virustotalEnrichmentReuse.js';

export const VIRUSTOTAL_PROVIDER = 'virustotal';

const HASH_TYPES = new Set(['hash', 'file_hash', 'md5', 'sha1', 'sha256']);
const IP_TYPES = new Set(['ip', 'ipv4', 'ipv6', 'ip6']);

/** Canonical observable category used for provider applicability. */
export function observableCategory(observableType) {
  const t = String(observableType || '').trim().toLowerCase();
  if (HASH_TYPES.has(t)) return 'hash';
  if (IP_TYPES.has(t)) return 'ip';
  if (t === 'domain' || t === 'hostname') return 'domain';
  if (t === 'url') return 'url';
  return t || 'other';
}

function notApplicable(reason) {
  return { applicable: false, reason };
}

function scopeFor(category) {
  return category === 'url' ? 'derived' : 'direct';
}

function toIso(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isFinite(d.getTime()) ? d.toISOString() : null;
}

/** IPinfo / AbuseIPDB: public IP IOCs, or the public IP literal host of a URL IOC. */
function resolvePublicIpTarget(ioc) {
  const category = observableCategory(ioc.observable_type);
  if (category !== 'ip' && category !== 'url') return notApplicable('unsupported_type');
  const r = resolveIpEnrichmentTarget(ioc.observable, category);
  if (!r.eligible) return notApplicable(r.reason || 'unsupported_type');
  return { applicable: true, scope: scopeFor(category), target_type: 'ip', target_value: r.ip };
}

/** Spamhaus DROP: IP IOCs, or the IP literal host of a URL IOC (local dataset). */
function resolveIpLiteralTarget(ioc) {
  const category = observableCategory(ioc.observable_type);
  if (category !== 'ip' && category !== 'url') return notApplicable('unsupported_type');
  const ip = extractIpLiteralFromIoc(ioc.observable, category);
  if (!ip) return notApplicable(category === 'url' ? 'domain_host' : 'invalid_ip');
  return { applicable: true, scope: scopeFor(category), target_type: 'ip', target_value: ip };
}

/** RDAP: domain IOCs, or the registrable domain of a URL IOC's host. */
function resolveRdapTarget(ioc) {
  const category = observableCategory(ioc.observable_type);
  if (!isRdapSupportedIocType(category)) return notApplicable('unsupported_type');
  const parsed = normalizeRdapTarget(ioc.observable, category);
  if (!parsed.ok) return notApplicable(parsed.code === 'unsupported' ? 'ip_host' : (parsed.code || 'invalid'));
  return { applicable: true, scope: scopeFor(category), target_type: 'domain', target_value: parsed.rdap_domain };
}

/** VirusTotal: every IOC type, looked up directly. */
function resolveVirustotalTarget(ioc) {
  const category = observableCategory(ioc.observable_type);
  if (!['ip', 'domain', 'url', 'hash'].includes(category)) return notApplicable('unsupported_type');
  return { applicable: true, scope: 'direct', target_type: category, target_value: String(ioc.observable || '') };
}

/** urlscan.io: domain and URL observables only (passive search only). */
function resolveUrlscanTarget(ioc) {
  const supported = isSupportedUrlscanIocType(ioc.observable_type);
  if (!supported) return notApplicable('unsupported_type');
  return {
    applicable: true,
    scope: 'direct',
    target_type: supported,
    target_value: String(ioc.observable || '')
  };
}

// Freshness = "would a normal (non-force) refresh reuse the stored result?",
// answered with each provider's own cache rule so automation never spends quota
// the UI would not spend.
async function virustotalFreshness(pool, _target, ioc) {
  // Same lookup as the IOC Details GET (incl. exact-hash alias reuse): a VT file
  // report stored under an md5/sha1 alias covers this sha256 too.
  const { row } = await resolveVtEnrichmentRow(pool, Number(ioc.id));
  if (!row) return { fresh: false, last_enriched_at: null };
  const expires = row.expires_at ? new Date(row.expires_at).getTime() : 0;
  const usable = row.status === 'success' || row.status === 'not_found';
  return {
    fresh: usable && expires > Date.now(),
    stored_status: row.status || null,
    last_enriched_at: toIso(row.fetched_at),
    expires_at: toIso(row.expires_at)
  };
}

async function ipinfoFreshness(pool, target) {
  const row = await getIpinfoEnrichmentByIp(pool, target.target_value);
  return {
    fresh: Boolean(row) && isIpinfoCacheFresh(row),
    stored_status: row?.provider_status || null,
    last_enriched_at: toIso(row?.last_enriched_at)
  };
}

async function abuseipdbFreshness(pool, target) {
  const row = await getAbuseIpdbEnrichmentByIp(pool, target.target_value);
  if (!row) return { fresh: false, last_enriched_at: null };
  const config = await getAbuseIpdbConfig(pool);
  // Note: the AbuseIPDB cache rule also holds failed/rate-limited rows for 1h.
  return {
    fresh: isAbuseIpdbCacheFresh(row, config),
    stored_status: row.provider_status || null,
    last_enriched_at: toIso(row.last_enriched_at)
  };
}

async function rdapFreshness(pool, target) {
  // refreshRdapEnrichment is DB-first: any stored row is reused unless forced.
  const row = await getEnrichmentByRootDomain(pool, target.target_value);
  return {
    fresh: Boolean(row),
    stored_status: row?.rdap_status || null,
    last_enriched_at: toIso(row?.last_success_at || row?.last_enriched_at || row?.updated_at)
  };
}

async function spamhausDropFreshness(pool, target) {
  // Local dataset: a stored listed/not_listed result is fresh until the dataset
  // is re-synced after it was computed.
  const row = await getSpamhausDropEnrichmentByIp(pool, target.target_value);
  if (!row || (row.provider_status !== 'listed' && row.provider_status !== 'not_listed')) {
    return { fresh: false, last_enriched_at: toIso(row?.enriched_at) };
  }
  const syncState = await getSpamhausDropSyncState(pool);
  const lastSync = syncState
    .map((s) => (s.last_success_at ? new Date(s.last_success_at).getTime() : 0))
    .reduce((a, b) => Math.max(a, b), 0);
  const enrichedAt = row.enriched_at ? new Date(row.enriched_at).getTime() : 0;
  return {
    fresh: enrichedAt > 0 && enrichedAt >= lastSync,
    stored_status: row.provider_status,
    last_enriched_at: toIso(row.enriched_at)
  };
}

async function urlscanFreshness(pool, _target, ioc) {
  const row = await getUrlscanEnrichmentByIoc(pool, Number(ioc.id));
  if (!row) return { fresh: false, last_enriched_at: null };
  const config = await getUrlscanConfig(pool);
  const usable = row.status === 'success' || row.status === 'not_found' || row.status === 'skipped';
  return {
    fresh: usable && isUrlscanCacheFresh(row, config),
    stored_status: row.status || null,
    last_enriched_at: toIso(row.fetched_at),
    expires_at: toIso(row.expires_at)
  };
}

/** Normalize any config getter's result to the state shape the guard needs. */
function pickState(cfg) {
  return {
    enabled: cfg?.enabled === true,
    configured: cfg?.configured !== false
  };
}

// VirusTotal's config getter lives in server.js and cannot be imported here
// without an import cycle, so mirror the minimal rule from
// getThreatIntelProviderConfig (enabled unless the row explicitly says false).
async function loadVirustotalState(pool) {
  const { rows } = await pool.query(
    'SELECT enabled, api_key FROM threat_intel_provider_configs WHERE provider = $1 LIMIT 1',
    [VIRUSTOTAL_PROVIDER]
  );
  const row = rows[0] || null;
  const key = String(row?.api_key || '').trim() || String(process.env.VIRUSTOTAL_API_KEY || '').trim();
  return { enabled: row?.enabled !== false, configured: Boolean(key) };
}

// Capability fields (all optional for providers that are never auto-triggered):
//   external                 — makes an outbound third-party call (may consume quota)
//   supportedObservableTypes — IOC categories the provider can enrich (direct or derived)
//   resolveTarget(ioc)       — { applicable, scope: direct|derived, target_type, target_value } | { applicable:false, reason }
//   readFreshness(pool, target, ioc) — { fresh, last_enriched_at, expires_at? }
//   automationRatePerMin     — default per-provider budget for automated triggers
//                              (env ENRICHMENT_AUTOMATION_RATE_PER_MIN_<KEY> overrides)
const DEFAULT_PROVIDERS = [
  {
    key: VIRUSTOTAL_PROVIDER,
    displayName: 'VirusTotal',
    loadState: (pool) => loadVirustotalState(pool),
    external: true,
    supportedObservableTypes: ['ip', 'domain', 'url', 'hash'],
    resolveTarget: resolveVirustotalTarget,
    readFreshness: virustotalFreshness,
    // VirusTotal public API allowance is 4 requests/minute.
    automationRatePerMin: 4
  },
  {
    key: 'ipinfo_lite',
    displayName: 'IPinfo Lite',
    loadState: async (pool) => pickState(await getIpinfoLiteConfig(pool)),
    external: true,
    supportedObservableTypes: ['ip', 'url'],
    resolveTarget: resolvePublicIpTarget,
    readFreshness: ipinfoFreshness,
    automationRatePerMin: 30
  },
  {
    key: 'abuseipdb',
    displayName: 'AbuseIPDB',
    loadState: async (pool) => pickState(await getAbuseIpdbConfig(pool)),
    external: true,
    supportedObservableTypes: ['ip', 'url'],
    resolveTarget: resolvePublicIpTarget,
    readFreshness: abuseipdbFreshness,
    automationRatePerMin: 20
  },
  {
    key: 'rdap',
    displayName: 'RDAP / WHOIS',
    loadState: async () => pickState(getRdapProviderAdminSummary()),
    external: true,
    supportedObservableTypes: ['domain', 'url'],
    resolveTarget: resolveRdapTarget,
    readFreshness: rdapFreshness,
    automationRatePerMin: 20
  },
  {
    key: 'spamhaus_drop',
    displayName: 'Spamhaus DROP',
    loadState: async (pool) => ({ enabled: Boolean((await getSpamhausDropConfig(pool)).enabled), configured: true }),
    // Local CIDR dataset lookup — no outbound call, no quota.
    external: false,
    supportedObservableTypes: ['ip', 'url'],
    resolveTarget: resolveIpLiteralTarget,
    readFreshness: spamhausDropFreshness,
    automationRatePerMin: 120
  },
  {
    key: URLSCAN_PROVIDER,
    displayName: 'urlscan.io',
    loadState: async (pool) => pickState(await getUrlscanConfig(pool)),
    external: true,
    supportedObservableTypes: [...URLSCAN_SUPPORTED_OBSERVABLE_TYPES],
    resolveTarget: resolveUrlscanTarget,
    readFreshness: urlscanFreshness,
    // Search API free-tier minute budgets are modest; keep automation conservative.
    automationRatePerMin: 10
  }
];

const registry = new Map();
for (const provider of DEFAULT_PROVIDERS) registry.set(provider.key, provider);

/** key -> async ({ pool, audit, req, ioc, target, force }) => { status: httpStatus, body } */
const executors = new Map();

/**
 * Register (or override) a provider entry. New providers get the disable policy
 * automatically — no execution site changes required.
 * @param {{ key: string, displayName?: string, loadState?: (pool: any) => Promise<{enabled:boolean, configured?:boolean}> }} entry
 */
export function registerEnrichmentProvider(entry) {
  if (!entry || !entry.key) throw new Error('Enrichment provider entry requires a key');
  registry.set(entry.key, {
    displayName: entry.displayName || entry.key,
    loadState: entry.loadState || (async () => ({ enabled: true, configured: true })),
    ...entry
  });
}

export function getEnrichmentProvider(providerKey) {
  return registry.get(providerKey) || null;
}

export function listEnrichmentProviders() {
  return [...registry.values()];
}

/**
 * Attach the provider's canonical refresh function — the same function its UI /
 * REST refresh route runs — so automated triggers never fork provider logic.
 * Contract: `fn({ pool, audit, req, ioc, target, force })` resolves to the
 * route's `{ status, body }` (HTTP status + JSON body) without touching `res`.
 * @param {string} providerKey
 * @param {Function} fn
 */
export function registerEnrichmentExecutor(providerKey, fn) {
  if (!registry.has(providerKey)) throw new UnknownProviderError(providerKey);
  if (typeof fn !== 'function') throw new Error('Enrichment executor must be a function');
  executors.set(providerKey, fn);
}

export function getEnrichmentExecutor(providerKey) {
  return executors.get(providerKey) || null;
}

/** Test helper: drop registered executors. */
export function resetEnrichmentExecutorsForTests() {
  executors.clear();
}

export class ProviderDisabledError extends Error {
  constructor(providerKey, displayName) {
    const message = `${displayName} enrichment provider is disabled.`;
    super(message);
    this.name = 'ProviderDisabledError';
    this.code = 'PROVIDER_DISABLED';
    this.provider = providerKey;
    this.httpStatus = 409;
    this.userMessage = message;
  }
}

export class UnknownProviderError extends Error {
  constructor(providerKey) {
    super(`Unknown enrichment provider: ${providerKey}`);
    this.name = 'UnknownProviderError';
    this.code = 'UNKNOWN_PROVIDER';
    this.provider = providerKey;
    this.httpStatus = 404;
    this.userMessage = 'Unknown enrichment provider.';
  }
}

/**
 * Central guard. Resolves provider existence + enabled state from the registry.
 * Throws ProviderDisabledError (409) when disabled — before any external call is
 * made. Returns the resolved state on success.
 */
export async function assertProviderEnabled(pool, providerKey) {
  const entry = registry.get(providerKey);
  if (!entry) throw new UnknownProviderError(providerKey);
  const state = await entry.loadState(pool);
  if (!state.enabled) throw new ProviderDisabledError(providerKey, entry.displayName);
  return state;
}

/**
 * Standard PROVIDER_DISABLED response body. Includes back-compat `provider_status`
 * / `status` aliases so existing IOC-detail cards keep recognizing the disabled
 * state until the card-gating follow-up lands.
 */
export function providerDisabledPayload(err) {
  return {
    error: 'PROVIDER_DISABLED',
    provider: err.provider,
    message: err.userMessage,
    provider_status: 'disabled',
    status: 'disabled'
  };
}

/**
 * Express helper for execution entry points. Returns true when the provider is
 * enabled (caller proceeds). When disabled, writes the standard 409 and returns
 * false so the caller can `return` without making any external call. Non-disabled
 * errors (e.g. unknown provider, DB failure) are rethrown for the caller's
 * existing error handling.
 *
 * ENFORCEMENT CONTRACT: the disable policy is enforced per entry point — there is
 * no global execution middleware that intercepts every provider call. Adding a
 * provider to the registry auto-covers it at every entry point that already calls
 * this guard, but any NEW execution entry point (HTTP route, worker job, or
 * internal trigger) that invokes a provider's external client MUST call
 * guardProviderEnabled (or runWithProviderEnabled) first — otherwise it bypasses
 * the policy. New execution sites should use runWithProviderEnabled so the guard
 * cannot be forgotten.
 */
export async function guardProviderEnabled(pool, providerKey, res) {
  try {
    await assertProviderEnabled(pool, providerKey);
    return true;
  } catch (err) {
    if (err && err.code === 'PROVIDER_DISABLED') {
      res.status(err.httpStatus || 409).json(providerDisabledPayload(err));
      return false;
    }
    throw err;
  }
}

/**
 * Response-free variant of guardProviderEnabled for refresh functions that
 * return `{ status, body }`: null when enabled, else the standard 409 outcome.
 */
export async function providerDisabledOutcome(pool, providerKey) {
  try {
    await assertProviderEnabled(pool, providerKey);
    return null;
  } catch (err) {
    if (err && err.code === 'PROVIDER_DISABLED') {
      return { status: err.httpStatus || 409, body: providerDisabledPayload(err) };
    }
    throw err;
  }
}

/**
 * Recommended single-call wrapper for execution entry points: guards the provider
 * and only runs `fn` when enabled. Returns fn's result, or undefined when the
 * request was rejected (the standard 409 has already been written to `res`).
 * Using this keeps the external call and its guard inseparable at the call site.
 */
export async function runWithProviderEnabled(pool, providerKey, res, fn) {
  if (!(await guardProviderEnabled(pool, providerKey, res))) return undefined;
  return fn();
}
