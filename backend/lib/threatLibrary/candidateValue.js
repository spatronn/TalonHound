/**
 * Observable value normalization shared by the deterministic extractor and the
 * table interpreter. Values are always strings — a hash such as
 * "005e6014…" must never pass through Number(). Kept free of zone/table
 * imports so documentZones → tableSemantics → candidateValue has no cycle.
 */

import { normalizeObservable } from '../observable-normalization.js';
import { normalizeIpAddress, isValidIpAddress, validatePublicIp } from '../publicIp.js';
import { inferExactHashType, normalizeHashValue } from '../fileArtifacts/hashNormalize.js';
import { resolveStorageObservableType, inferObservableType } from '../manualIocCreate.js';
import { refangObservable } from './defang.js';

/** RFC documentation / loopback only — not vendor safety allowlists. */
const RFC_EXAMPLE_DOMAINS = new Set(['example.com', 'example.org', 'example.net', 'localhost', 'invalid', 'test']);

const IPV4_CIDR_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:3[0-2]|[12]?\d)$/;
const IPV6_CIDR_RE = /^[0-9a-f:]+\/(?:1[0-2]\d|[1-9]?\d)$/i;

function ipv4ToInt(ip) {
  return String(ip)
    .split('.')
    .reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
}

function intToIpv4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/**
 * Canonical CIDR string: network address + prefix. Never explodes to hosts.
 * @param {string} ip
 * @param {number} prefix
 */
export function canonicalizeIpv4Cidr(ip, prefix) {
  const host = normalizeIpAddress(ip);
  if (!host || host.includes(':')) return null;
  const p = Number(prefix);
  if (!Number.isInteger(p) || p < 0 || p > 32) return null;
  const mask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
  return `${intToIpv4(ipv4ToInt(host) & mask)}/${p}`;
}

export function isRfcExampleDomain(domain) {
  const d = String(domain || '').toLowerCase();
  if (RFC_EXAMPLE_DOMAINS.has(d)) return true;
  for (const fp of RFC_EXAMPLE_DOMAINS) {
    if (d.endsWith(`.${fp}`)) return true;
  }
  return false;
}

/**
 * Private / reserved address space (RFC 1918, loopback, link-local, multicast…)
 * is documentation of a victim network or an example, never external threat
 * infrastructure on its own.
 * @param {string} normalizedIp
 */
export function isPrivateOrReservedAddress(normalizedIp) {
  const ip = String(normalizedIp || '');
  if (!ip) return false;
  return validatePublicIp(ip) == null;
}

/**
 * @param {string} raw
 * @param {string} [hintType]
 */
export function normalizeCandidateValue(raw, hintType = null) {
  const refanged = refangObservable(raw);
  if (!refanged) return { ok: false, error: 'empty' };

  if (hintType === 'cve' || /^CVE-\d{4}-\d{4,7}$/i.test(refanged)) {
    return {
      ok: true,
      candidateType: 'cve',
      originalValue: String(raw).trim(),
      normalizedValue: refanged.toUpperCase(),
      isIoc: false
    };
  }
  if (hintType === 'attack_technique' || /^T\d{4}(?:\.\d{3})?$/i.test(refanged)) {
    return {
      ok: true,
      candidateType: 'attack_technique',
      originalValue: String(raw).trim(),
      normalizedValue: refanged.toUpperCase(),
      isIoc: false
    };
  }

  let inferred = hintType || inferObservableType(refanged);
  if (hintType === 'ipv6') inferred = 'ip';
  if (hintType === 'cidr') inferred = 'cidr';

  const slash = refanged.indexOf('/');
  const looksCidr =
    inferred === 'cidr' ||
    hintType === 'cidr' ||
    (slash > 0 && (IPV4_CIDR_RE.test(refanged) || (refanged.includes(':') && IPV6_CIDR_RE.test(refanged))));
  if (looksCidr && slash > 0) {
    const addr = refanged.slice(0, slash);
    const prefix = Number(refanged.slice(slash + 1));
    if (addr.includes(':')) {
      if (!isValidIpAddress(addr) || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
        return { ok: false, error: 'invalid_cidr' };
      }
      return {
        ok: true,
        candidateType: 'cidr',
        originalValue: String(raw).trim(),
        normalizedValue: `${normalizeIpAddress(addr)}/${prefix}`,
        isIoc: true,
        parsed: { prefix, family: 'ipv6' }
      };
    }
    const canonical = canonicalizeIpv4Cidr(addr, prefix);
    if (!canonical) return { ok: false, error: 'invalid_cidr' };
    const network = canonical.split('/')[0];
    const reserved = isPrivateOrReservedAddress(network);
    return {
      ok: true,
      candidateType: 'cidr',
      originalValue: String(raw).trim(),
      normalizedValue: canonical,
      isIoc: true,
      likelyContextOnly: reserved,
      reservedAddress: reserved,
      parsed: { prefix, family: 'ipv4' }
    };
  }
  if (!inferred) return { ok: false, error: 'unrecognized' };

  if (inferred === 'ip' || inferred === 'ipv6') {
    if (!isValidIpAddress(refanged.split('/')[0])) {
      return { ok: false, error: 'invalid_ip' };
    }
    const norm = normalizeIpAddress(refanged.split('/')[0]);
    const isV6 = norm.includes(':');
    const reserved = isPrivateOrReservedAddress(norm);
    return {
      ok: true,
      candidateType: isV6 ? 'ipv6' : 'ip',
      originalValue: String(raw).trim(),
      normalizedValue: norm,
      isIoc: true,
      likelyContextOnly: reserved,
      reservedAddress: reserved
    };
  }

  if (inferred === 'url' || /^https?:\/\//i.test(refanged)) {
    const storage = resolveStorageObservableType(refanged, 'url');
    if (!storage.ok) return { ok: false, error: storage.error };
    return {
      ok: true,
      candidateType: 'url',
      originalValue: String(raw).trim(),
      normalizedValue: normalizeObservable('url', storage.value),
      isIoc: true
    };
  }

  if (inferred === 'hash' || hintType === 'md5' || hintType === 'sha1' || hintType === 'sha256') {
    const normalized = normalizeHashValue(refanged);
    const exact = inferExactHashType(normalized) || (hintType && ['md5', 'sha1', 'sha256'].includes(hintType) ? hintType : null);
    if (!exact) return { ok: false, error: 'invalid_hash' };
    return {
      ok: true,
      candidateType: exact,
      originalValue: String(raw).trim(),
      normalizedValue: normalized,
      isIoc: true
    };
  }

  const domain = normalizeObservable('domain', refanged.replace(/\.$/, ''));
  if (!domain || !domain.includes('.')) return { ok: false, error: 'invalid_domain' };
  return {
    ok: true,
    candidateType: 'domain',
    originalValue: String(raw).trim(),
    normalizedValue: domain,
    isIoc: true,
    likelyContextOnly: isRfcExampleDomain(domain)
  };
}
