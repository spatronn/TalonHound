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

/**
 * Whether an enrichment provider applies to the current IOC type.
 * URL IOCs only get VirusTotal here; IP/domain-derived enrichment stays out of direct coverage.
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
