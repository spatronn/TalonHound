import { ipEnrichStripHostPort } from './ipEnrichmentTarget.js';

export const PROVIDER_KEYS = Object.freeze(['virustotal', 'ipinfo', 'abuseipdb', 'rdap', 'spamhaus_drop', 'dnsmania']);

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
 * Extract hostname from URL IOC values.
 * Supports http://, https://, protocol-relative (//), and schemeless URLs with a path.
 * When no scheme is present, prepends https:// temporarily for parsing only — never
 * modifies the stored IOC value.
 * @returns {string|null}
 */
export function extractHostFromIocValue(iocValue, iocType) {
  if (normalizeIocType(iocType) !== 'url') return null;
  const raw = String(iocValue || '').trim();
  if (!raw) return null;

  // Relative paths (single leading slash) are never valid URL IOC values
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
    // Bare string with no scheme and no path — must look like a hostname (has a dot or is IPv6)
    hostname = ipEnrichStripHostPort(raw.split('?')[0].split('#')[0]);
    if (!hostname.includes('.') && !hostname.startsWith('[')) return null;
  }

  if (!hostname || /\s/.test(hostname)) return null;
  return hostname;
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
