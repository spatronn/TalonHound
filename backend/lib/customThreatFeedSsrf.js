import { BlockList, isIP } from 'node:net';
import dns from 'node:dns/promises';

/** Default max redirect hops for custom threat feed fetches. */
export const DEFAULT_MAX_FEED_REDIRECTS = 5;

const BLOCKED_HOSTNAMES = new Set(['localhost', 'metadata', 'metadata.google.internal']);

/**
 * Single BlockList used by validate + resolve + fetch.
 * Private/internal feeds are not a supported product requirement.
 */
const FORBIDDEN_DESTINATIONS = new BlockList();
FORBIDDEN_DESTINATIONS.addSubnet('0.0.0.0', 8, 'ipv4');       // unspecified
FORBIDDEN_DESTINATIONS.addSubnet('10.0.0.0', 8, 'ipv4');       // RFC1918
FORBIDDEN_DESTINATIONS.addSubnet('127.0.0.0', 8, 'ipv4');      // loopback
FORBIDDEN_DESTINATIONS.addSubnet('169.254.0.0', 16, 'ipv4');   // link-local / metadata
FORBIDDEN_DESTINATIONS.addSubnet('172.16.0.0', 12, 'ipv4');    // RFC1918
FORBIDDEN_DESTINATIONS.addSubnet('192.168.0.0', 16, 'ipv4');   // RFC1918
FORBIDDEN_DESTINATIONS.addSubnet('224.0.0.0', 4, 'ipv4');      // multicast
FORBIDDEN_DESTINATIONS.addSubnet('240.0.0.0', 4, 'ipv4');      // reserved
FORBIDDEN_DESTINATIONS.addSubnet('::', 128, 'ipv6');           // unspecified
FORBIDDEN_DESTINATIONS.addSubnet('::1', 128, 'ipv6');          // loopback
FORBIDDEN_DESTINATIONS.addSubnet('fc00::', 7, 'ipv6');         // ULA
FORBIDDEN_DESTINATIONS.addSubnet('fe80::', 10, 'ipv6');        // link-local
FORBIDDEN_DESTINATIONS.addSubnet('ff00::', 8, 'ipv6');         // multicast

/**
 * @param {string} address
 * @returns {boolean}
 */
export function isForbiddenFeedDestinationIp(address) {
  const raw = String(address || '').trim().replace(/^\[|\]$/g, '');
  if (!raw) return true;
  const version = isIP(raw);
  if (!version) return true;
  return FORBIDDEN_DESTINATIONS.check(raw, version === 6 ? 'ipv6' : 'ipv4');
}

/**
 * Normalize hostname from a URL instance (strips brackets).
 * @param {string} hostname
 */
export function normalizeFeedHostname(hostname) {
  return String(hostname || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
}

function isBlockedHostname(hostname) {
  const host = normalizeFeedHostname(hostname);
  if (!host) return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (host === '127.0.0.1' || host === '::1' || host === '0.0.0.0') return true;
  if (host.endsWith('.local') || host.endsWith('.localhost')) return true;
  if (host.endsWith('.internal')) return true;
  return false;
}

/**
 * Shared sync URL policy: http(s) only + hostname / IP literal denylist.
 * DNS resolution is performed separately before connect (see resolveSafeFeedHost).
 *
 * @param {string} urlString
 * @returns {{ ok: true, url: string, parsed: URL, url_host: string } | { ok: false, error: string }}
 */
export function validateFeedUrlPolicy(urlString) {
  const raw = String(urlString || '').trim();
  if (!raw) return { ok: false, error: 'URL is required' };

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: 'URL must be a valid http or https URL' };
  }

  const protocol = String(parsed.protocol || '').toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    return { ok: false, error: 'Only http and https URLs are allowed' };
  }

  const hostname = normalizeFeedHostname(parsed.hostname);
  if (!hostname) {
    return { ok: false, error: 'URL must include a hostname' };
  }

  if (isBlockedHostname(hostname)) {
    return { ok: false, error: 'Private, loopback, and localhost URLs are not allowed' };
  }

  if (isIP(hostname) && isForbiddenFeedDestinationIp(hostname)) {
    return { ok: false, error: 'Private, loopback, and localhost URLs are not allowed' };
  }

  return {
    ok: true,
    url: raw,
    parsed,
    url_host: hostname
  };
}

/**
 * Resolve hostname and require every A/AAAA record to be an allowed destination.
 *
 * @param {string} hostname
 * @param {{ lookup?: typeof dns.lookup, isForbiddenAddress?: (address: string) => boolean }} [options]
 * @returns {Promise<{ address: string, family: number }[]>}
 */
export async function resolveSafeFeedHost(hostname, options = {}) {
  const host = normalizeFeedHostname(hostname);
  if (!host) {
    const err = new Error('URL must include a hostname');
    err.code = 'invalid_url';
    throw err;
  }

  if (isBlockedHostname(host)) {
    const err = new Error('Private, loopback, and localhost URLs are not allowed');
    err.code = 'destination_blocked';
    throw err;
  }

  const isForbidden = options.isForbiddenAddress || isForbiddenFeedDestinationIp;
  const lookup = options.lookup || dns.lookup;

  if (isIP(host)) {
    if (isForbidden(host)) {
      const err = new Error('Private, loopback, and localhost URLs are not allowed');
      err.code = 'destination_blocked';
      throw err;
    }
    return [{ address: host, family: isIP(host) }];
  }

  let records;
  try {
    records = await lookup(host, { all: true, verbatim: true });
  } catch (cause) {
    const err = new Error(`DNS lookup failed for feed host: ${host}`);
    err.code = 'dns_lookup_failed';
    err.cause = cause;
    throw err;
  }

  const list = Array.isArray(records) ? records : [];
  if (list.length === 0) {
    const err = new Error(`DNS lookup returned no addresses for feed host: ${host}`);
    err.code = 'dns_lookup_failed';
    throw err;
  }

  for (const record of list) {
    const address = String(record?.address || '').trim();
    if (!address || !isIP(address) || isForbidden(address)) {
      const err = new Error('Resolved feed host address is not allowed');
      err.code = 'destination_blocked';
      err.blockedAddress = address || null;
      throw err;
    }
  }

  return list.map((r) => ({
    address: String(r.address),
    family: Number(r.family) === 6 ? 6 : 4
  }));
}

/**
 * Full destination gate used before each connect / redirect hop.
 *
 * @param {string} urlString
 * @param {{ lookup?: typeof dns.lookup, isForbiddenAddress?: (address: string) => boolean }} [options]
 */
export async function assertSafeFeedDestination(urlString, options = {}) {
  const check = validateFeedUrlPolicy(urlString);
  if (!check.ok) {
    const err = new Error(check.error);
    err.code = 'invalid_url';
    throw err;
  }
  const addresses = await resolveSafeFeedHost(check.parsed.hostname, options);
  return { ...check, addresses };
}

/**
 * @param {URL} a
 * @param {URL} b
 */
export function isSameFeedOrigin(a, b) {
  return a.protocol === b.protocol
    && normalizeFeedHostname(a.hostname) === normalizeFeedHostname(b.hostname)
    && a.port === b.port;
}

/**
 * Strip userinfo; never preserve URL credentials when building the next hop.
 * @param {URL} url
 */
export function stripUrlUserinfo(url) {
  const next = new URL(url.href);
  next.username = '';
  next.password = '';
  return next;
}
