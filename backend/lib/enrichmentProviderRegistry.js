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

import { getIpinfoLiteConfig } from '../services/ipinfoLiteService.js';
import { getAbuseIpdbConfig } from '../services/abuseipdbService.js';
import { getRdapProviderAdminSummary } from '../services/rdapEnrichmentService.js';
import { getSpamhausDropConfig } from './spamhausDropSync.js';

export const VIRUSTOTAL_PROVIDER = 'virustotal';

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

const DEFAULT_PROVIDERS = [
  { key: VIRUSTOTAL_PROVIDER, displayName: 'VirusTotal', loadState: (pool) => loadVirustotalState(pool) },
  { key: 'ipinfo_lite', displayName: 'IPinfo Lite', loadState: async (pool) => pickState(await getIpinfoLiteConfig(pool)) },
  { key: 'abuseipdb', displayName: 'AbuseIPDB', loadState: async (pool) => pickState(await getAbuseIpdbConfig(pool)) },
  { key: 'rdap', displayName: 'RDAP / WHOIS', loadState: async () => pickState(getRdapProviderAdminSummary()) },
  {
    key: 'spamhaus_drop',
    displayName: 'Spamhaus DROP',
    loadState: async (pool) => ({ enabled: Boolean((await getSpamhausDropConfig(pool)).enabled), configured: true })
  }
];

const registry = new Map();
for (const provider of DEFAULT_PROVIDERS) registry.set(provider.key, provider);

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
 * Recommended single-call wrapper for execution entry points: guards the provider
 * and only runs `fn` when enabled. Returns fn's result, or undefined when the
 * request was rejected (the standard 409 has already been written to `res`).
 * Using this keeps the external call and its guard inseparable at the call site.
 */
export async function runWithProviderEnabled(pool, providerKey, res, fn) {
  if (!(await guardProviderEnabled(pool, providerKey, res))) return undefined;
  return fn();
}
