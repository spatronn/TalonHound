import { isPrivateOrReservedIp } from './feedFormatter.js';

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^([0-9a-f]{0,4}:){2,}[0-9a-f]{0,4}$/i;

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
  const host = String(value || '').trim().split('/')[0].trim();
  if (!host) return false;
  if (IPV4_RE.test(host)) return true;
  if (host.includes(':') && IPV6_RE.test(host)) return true;
  return false;
}

/**
 * Returns normalized IP string if public, otherwise null.
 * Private/reserved/local IPs are not eligible for external enrichment.
 */
export function validatePublicIp(value) {
  const host = String(value || '').trim().split('/')[0].trim();
  if (!host) return null;
  if (IPV4_RE.test(host)) {
    if (isPrivateOrReservedIp(host)) return null;
    return host;
  }
  if (host.includes(':')) {
    const normalized = host.toLowerCase();
    if (!IPV6_RE.test(normalized)) return null;
    if (isPrivateOrReservedIpv6(normalized)) return null;
    return normalized;
  }
  return null;
}
