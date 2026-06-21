import { ipEnrichStripHostPort } from './ipEnrichmentTarget.js';

export const PROVIDER_KEYS = Object.freeze(['virustotal', 'ipinfo', 'abuseipdb', 'rdap']);

const HASH_TYPES = new Set([
  'file_hash',
  'hash',
  'md5',
  'sha1',
  'sha256',
  'ssdeep',
  'imphash',
  'tlsh'
]);

const IP_TYPES = new Set(['ip', 'ipv4', 'ipv6', 'ip6']);
const DOMAIN_TYPES = new Set(['domain', 'hostname']);
const URL_TYPES = new Set(['url']);

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/** @returns {'hash'|'ip'|'domain'|'url'|string} */
export function normalizeIocType(iocType) {
  const t = String(iocType || '').trim().toLowerCase();
  if (HASH_TYPES.has(t)) return 'hash';
  if (IP_TYPES.has(t)) return 'ip';
  if (DOMAIN_TYPES.has(t)) return 'domain';
  if (URL_TYPES.has(t)) return 'url';
  return t || 'other';
}

export function isHashIocType(iocType) {
  return normalizeIocType(iocType) === 'hash';
}

export function isIpIocType(iocType) {
  return normalizeIocType(iocType) === 'ip';
}

export function isIpAddress(value) {
  const host = ipEnrichStripHostPort(value);
  if (!host) return false;
  return IPV4_RE.test(host) || host.includes(':');
}

/**
 * Extract hostname from URL IOC values (http/https only).
 * @returns {string|null}
 */
export function extractHostFromIocValue(iocValue, iocType) {
  if (normalizeIocType(iocType) !== 'url') return null;
  const raw = String(iocValue || '').trim();
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = ipEnrichStripHostPort(u.hostname);
    return host || null;
  } catch {
    return null;
  }
}

/**
 * Whether an enrichment provider applies to the current IOC type (direct coverage).
 * URL IOCs only get VirusTotal here; host-derived enrichment is shown separately.
 */
export function isProviderApplicable(providerKey, iocType, { rdapEligible = false } = {}) {
  const key = String(providerKey || '').trim().toLowerCase();
  const normalized = normalizeIocType(iocType);

  if (key === 'virustotal') return true;
  if (key === 'ipinfo' || key === 'abuseipdb') return normalized === 'ip';
  if (key === 'rdap') return normalized === 'domain' && Boolean(rdapEligible);
  return false;
}

export function getApplicableProvidersForIocType(iocType, options = {}) {
  return PROVIDER_KEYS.filter((key) => isProviderApplicable(key, iocType, options));
}

/**
 * Providers applicable to infrastructure extracted from a URL IOC host.
 * @returns {string[]}
 */
export function getDerivedInfrastructureProviders(iocValue, iocType, { rdapEligible = false } = {}) {
  const ctx = getDerivedInfrastructureContext(iocValue, iocType, { rdapEligible });
  return ctx?.providers ?? [];
}

/**
 * @returns {{ host: string, hostKind: 'ip'|'domain', providers: string[] }|null}
 */
export function getDerivedInfrastructureContext(iocValue, iocType, { rdapEligible = false } = {}) {
  if (normalizeIocType(iocType) !== 'url') return null;

  const host = extractHostFromIocValue(iocValue, iocType);
  if (!host) return null;

  const hostKind = isIpAddress(host) ? 'ip' : 'domain';
  const providers = [];

  if (hostKind === 'ip') {
    providers.push('ipinfo', 'abuseipdb');
  } else if (rdapEligible) {
    providers.push('rdap');
  }

  if (!providers.length) return null;

  return { host, hostKind, providers };
}

export function isDerivedProviderApplicable(providerKey, derivedContext) {
  if (!derivedContext?.providers?.length) return false;
  return derivedContext.providers.includes(String(providerKey || '').trim().toLowerCase());
}
