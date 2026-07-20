import { parse as parseTld } from 'tldts';
import { ipEnrichStripHostPort } from './ipEnrichmentTarget.js';

export const PROVIDER_KEYS = Object.freeze(['virustotal', 'ipinfo', 'abuseipdb', 'rdap', 'spamhaus_drop', 'dnsmania']);

/** ICANN registrable domain only — private suffixes (e.g. netlify.app) are not treated as the RDAP root. */
const RDAP_TLD_OPTS = { allowPrivateDomains: false, detectIp: false };
const RDAP_HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;

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
 * Central hostname extractor for domain and URL observables — the single source of truth
 * for frontend host parsing (RDAP eligibility, derived-infrastructure routing).
 *
 * Supports http://, https://, protocol-relative (//host), schemeless host/path, and bare
 * hosts. When no scheme is present, https:// is prepended only for parsing — the input value
 * is never mutated. Returns the lowercased host (domain or IP literal; port/path/query/
 * fragment stripped) or null. IP-vs-domain classification and RDAP TLD eligibility are the
 * caller's responsibility.
 * @returns {string|null}
 */
export function extractHostFromObservable(value, iocType) {
  const type = normalizeIocType(iocType);
  if (type !== 'url' && type !== 'domain') return null;
  const raw = String(value || '').trim();
  if (!raw) return null;

  // Relative paths (single leading slash) are never valid observable values
  if (raw.startsWith('/') && !raw.startsWith('//')) return null;

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith('//');
  const looksLikePath = raw.includes('/') && !raw.includes('@');
  let hostname = '';

  if (hasScheme || looksLikePath) {
    try {
      const urlStr = raw.startsWith('//') ? `https:${raw}` : (hasScheme ? raw : `https://${raw}`);
      const u = new URL(urlStr);
      // Reject explicit non-http schemes (e.g. ftp://); synthetic https:// is always fine
      if (hasScheme && !raw.startsWith('//') && u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      hostname = ipEnrichStripHostPort(u.hostname);
    } catch {
      if (looksLikePath) {
        hostname = ipEnrichStripHostPort(raw.split('/')[0].split('?')[0].split('#')[0]);
      }
    }
  } else {
    // Bare host with no scheme/path — require it to look like a hostname or IP literal
    hostname = ipEnrichStripHostPort(raw.split('?')[0].split('#')[0]);
    if (!hostname.includes('.') && !hostname.includes(':')) return null;
  }

  if (!hostname || /\s/.test(hostname)) return null;
  return hostname;
}

/**
 * Extract hostname from URL IOC values only. Thin wrapper over extractHostFromObservable,
 * kept for existing callers/tests that operate strictly on url-typed IOCs.
 * @returns {string|null}
 */
export function extractHostFromIocValue(iocValue, iocType) {
  if (normalizeIocType(iocType) !== 'url') return null;
  return extractHostFromObservable(iocValue, iocType);
}

/**
 * UI-only RDAP eligibility for domain/url observables (backend validation stays independent).
 * Uses the central host extractor + isIpAddress classifier so the frontend has a single
 * parsing path. Returns eligibility plus the resolved host and registrable RDAP domain.
 * @returns {{ eligible: boolean, host: string|null, rdapDomain: string|null, reason: string|null }}
 */
export function isRdapEligibleObservable(iocValue, iocType) {
  const type = normalizeIocType(iocType);
  if (type !== 'domain' && type !== 'url') {
    return { eligible: false, host: null, rdapDomain: null, reason: 'unsupported_type' };
  }

  const raw = String(iocValue || '').trim();
  if (!raw) {
    return { eligible: false, host: null, rdapDomain: null, reason: 'empty' };
  }

  if (RDAP_HASH_RE.test(raw)) {
    return { eligible: false, host: null, rdapDomain: null, reason: 'hash' };
  }

  if (type === 'domain' && isIpAddress(raw)) {
    return { eligible: false, host: raw, rdapDomain: null, reason: 'ip_observable' };
  }

  const host = extractHostFromObservable(raw, type);
  if (!host) {
    return { eligible: false, host: null, rdapDomain: null, reason: 'invalid' };
  }

  if (isIpAddress(host)) {
    return { eligible: false, host, rdapDomain: null, reason: 'ip_host' };
  }

  const parsed = parseTld(host, RDAP_TLD_OPTS);
  const rdapDomain = parsed.domain ? String(parsed.domain).toLowerCase() : null;
  if (!rdapDomain) {
    return { eligible: false, host, rdapDomain: null, reason: 'no_registrable_domain' };
  }

  return { eligible: true, host, rdapDomain, reason: null };
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
  if (key === 'spamhaus_drop') return normalized === 'ip';
  if (key === 'rdap') return normalized === 'domain' && Boolean(rdapEligible);
  if (key === 'dnsmania') return normalized === 'domain' || normalized === 'url' || normalized === 'ip';
  return false;
}

export function getApplicableProvidersForIocType(iocType, options = {}) {
  return getDirectApplicableProviders(iocType, options);
}

/** Direct IOC enrichment providers (excludes URL extracted-host providers). */
export function getDirectApplicableProviders(iocType, options = {}) {
  return PROVIDER_KEYS.filter((key) => isProviderApplicable(key, iocType, options));
}

/**
 * Providers for infrastructure extracted from a URL host.
 * @param {'ip'|'domain'} derivedEntityType
 */
export function getDerivedApplicableProviders(derivedEntityType, { rdapEligible = false } = {}) {
  const kind = String(derivedEntityType || '').toLowerCase();
  if (kind === 'ip') return ['ipinfo', 'abuseipdb', 'spamhaus_drop'];
  if (kind === 'domain' && rdapEligible) return ['rdap'];
  return [];
}

/**
 * Providers applicable to infrastructure extracted from a URL IOC host.
 * @returns {string[]}
 */
export function getDerivedInfrastructureProviders(iocValue, iocType, { rdapEligible = false } = {}) {
  const ctx = getDerivedInfrastructure(iocValue, iocType, { rdapEligible });
  return ctx?.providers ?? [];
}

/** @returns {{ host: string, hostKind: 'ip'|'domain', providers: string[] }|null} */
export function getDerivedInfrastructure(iocValue, iocType, { rdapEligible = false } = {}) {
  return getDerivedInfrastructureContext(iocValue, iocType, { rdapEligible });
}

/**
 * @returns {{ host: string, hostKind: 'ip'|'domain', providers: string[] }|null}
 */
export function getDerivedInfrastructureContext(iocValue, iocType, { rdapEligible = false } = {}) {
  if (normalizeIocType(iocType) !== 'url') return null;

  const host = extractHostFromIocValue(iocValue, iocType);
  if (!host) return null;

  const hostKind = isIpAddress(host) ? 'ip' : 'domain';
  const providers = getDerivedApplicableProviders(hostKind, { rdapEligible });

  if (!providers.length) return null;

  return { host, hostKind, providers };
}

export function isDerivedProviderApplicable(providerKey, derivedContext) {
  if (!derivedContext?.providers?.length) return false;
  return derivedContext.providers.includes(String(providerKey || '').trim().toLowerCase());
}
