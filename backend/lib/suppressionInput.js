/**
 * Input handling for manual IOC suppressions.
 *
 * Suppression matching is an exact `lower(ioc_type) = lower(observable_type)`
 * comparison (see queryIocSuppressedFromDb), so the type stored on a suppression
 * must be a concrete observable_type the platform actually uses:
 *   ip | ipv6 | domain | url | md5 | sha1 | sha256
 *
 * The product spec groups hashes as "file_hash", but a generic file_hash type
 * would never match a stored sha256 IOC. We therefore detect the concrete hash
 * type by length and reuse the existing normalizers so a manual suppression and
 * an imported IOC canonicalize identically.
 */

import { isIP } from 'node:net';
import { normalizeIpAddress } from './publicIp.js';
import { normalizeUrlForMatch } from './observable-normalization.js';

export const SUPPRESSION_TYPES = Object.freeze(['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']);

const HASH_LEN_TO_TYPE = { 32: 'md5', 40: 'sha1', 64: 'sha256' };

/** Basic hostname/domain shape (labels, TLD, no scheme/space). */
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/i;

/**
 * Best-effort type detection from a raw indicator value.
 * @returns {'ip'|'ipv6'|'domain'|'url'|'md5'|'sha1'|'sha256'|null}
 */
export function detectSuppressionType(rawValue) {
  const v = String(rawValue || '').trim();
  if (!v) return null;

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return 'url';

  const ipCore = v.split('/')[0].trim();
  const ipVersion = isIP(ipCore);
  if (ipVersion === 4) return 'ip';
  if (ipVersion === 6) return 'ipv6';

  if (/^[a-f0-9]+$/i.test(v) && HASH_LEN_TO_TYPE[v.length]) return HASH_LEN_TO_TYPE[v.length];

  if (v.includes('/')) return 'url';
  if (DOMAIN_RE.test(v)) return 'domain';
  return null;
}

/** True when `type` is one of the supported concrete suppression types. */
export function isSupportedSuppressionType(type) {
  return SUPPRESSION_TYPES.includes(String(type || '').trim().toLowerCase());
}

/**
 * Normalize a suppression value for its type, mirroring import-time
 * canonicalization so manual suppressions match feed-imported IOCs.
 * @returns {{ ok: true, iocType: string, iocValue: string } | { ok: false, message: string }}
 */
export function normalizeSuppressionInput({ ioc_value, ioc_type } = {}) {
  const rawValue = String(ioc_value ?? '').trim();
  if (!rawValue) return { ok: false, message: 'IOC value is required' };

  let type = String(ioc_type ?? '').trim().toLowerCase();
  if (!type) {
    type = detectSuppressionType(rawValue);
    if (!type) return { ok: false, message: 'Could not detect IOC type from value; please select a type' };
  }
  if (!isSupportedSuppressionType(type)) {
    return { ok: false, message: `Unsupported IOC type. Supported: ${SUPPRESSION_TYPES.join(', ')}` };
  }

  if (type === 'ip' || type === 'ipv6') {
    const normalized = normalizeIpAddress(rawValue);
    if (!normalized) return { ok: false, message: 'Invalid IP address' };
    const version = isIP(normalized);
    if (type === 'ip' && version !== 4) return { ok: false, message: 'Value is not a valid IPv4 address' };
    if (type === 'ipv6' && version !== 6) return { ok: false, message: 'Value is not a valid IPv6 address' };
    return { ok: true, iocType: type, iocValue: normalized };
  }

  if (type === 'url') {
    const normalized = normalizeUrlForMatch(rawValue);
    if (!normalized) return { ok: false, message: 'Invalid URL' };
    return { ok: true, iocType: type, iocValue: normalized };
  }

  if (type === 'md5' || type === 'sha1' || type === 'sha256') {
    const hash = rawValue.toLowerCase();
    const expectedLen = Number(Object.keys(HASH_LEN_TO_TYPE).find((len) => HASH_LEN_TO_TYPE[len] === type));
    if (!/^[a-f0-9]+$/.test(hash) || hash.length !== expectedLen) {
      return { ok: false, message: `Invalid ${type} hash` };
    }
    return { ok: true, iocType: type, iocValue: hash };
  }

  // domain
  const domain = rawValue.toLowerCase().replace(/\.$/, '');
  if (!DOMAIN_RE.test(rawValue)) return { ok: false, message: 'Invalid domain' };
  return { ok: true, iocType: 'domain', iocValue: domain };
}
