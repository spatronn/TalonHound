import { isIP } from 'node:net';
import { isPrivateOrReservedIp } from './feedFormatter.js';

function expandIpv6(host) {
  let h = String(host || '').trim().toLowerCase();
  if (!h.includes('::')) return h.split(':').map((p) => p.padStart(4, '0'));
  const [left, right] = h.split('::');
  const leftParts = left ? left.split(':').filter(Boolean) : [];
  const rightParts = right ? right.split(':').filter(Boolean) : [];
  const missing = 8 - leftParts.length - rightParts.length;
  const mid = Array(Math.max(0, missing)).fill('0000');
  return [...leftParts, ...mid, ...rightParts].map((p) => p.padStart(4, '0'));
}

function isPrivateOrReservedIpv6(host) {
  const parts = expandIpv6(host);
  if (parts.length !== 8) return true;
  const first = parseInt(parts[0], 16);
  if (parts.every((p) => p === '0000') && parts[7] === '0001') return true;
  if ((first & 0xfe00) === 0xfc00) return true;
  if ((first & 0xffc0) === 0xfe80) return true;
  if (first === 0 && parseInt(parts[1], 16) === 0) return true;
  if ((first & 0xff00) === 0xff00) return true;
  return false;
}

export function isValidIpAddress(value) {
  return normalizeIpAddress(value) != null;
}

/**
 * Canonical IP identity used by all enrichment caches.
 * IPv4 is emitted in dotted-decimal form and equivalent IPv6 spellings collapse
 * to the compressed lowercase representation produced by the WHATWG URL parser.
 */
export function normalizeIpAddress(value) {
  const host = String(value || '').trim().split('/')[0].trim();
  const version = isIP(host);
  if (version === 4) {
    return host.split('.').map((part) => String(Number(part))).join('.');
  }
  if (version === 6) {
    try {
      return new URL(`http://[${host}]/`).hostname.slice(1, -1).toLowerCase();
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Returns normalized IP string if public, otherwise null.
 * Private/reserved/local IPs are not eligible for external enrichment.
 */
export function validatePublicIp(value) {
  const normalized = normalizeIpAddress(value);
  if (!normalized) return null;
  if (isIP(normalized) === 4) {
    if (isPrivateOrReservedIp(normalized)) return null;
    return normalized;
  }
  if (isIP(normalized) === 6) {
    if (isPrivateOrReservedIpv6(normalized)) return null;
    return normalized;
  }
  return null;
}
