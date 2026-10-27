/**
 * Network observable identity for IOC records: host addresses and CIDR
 * networks, IPv4 and IPv6.
 *
 * Storage contract (matches the 2,167 EmergingThreats CIDR rows already in
 * ioc_items and the published-feed STIX / MISP serializers): a CIDR network is
 * an `ip` (IPv4) or `ipv6` (IPv6) IOC whose observable keeps its prefix length.
 * The prefix is part of the identity — `198.51.100.0/24` and `198.51.100.0`
 * are different IOCs — and a network is never expanded into host IOCs nor
 * truncated to its network address.
 *
 * Canonical forms:
 *   IPv4 host  dotted quad without leading zeros
 *   IPv6 host  RFC 5952 (lowercase, longest zero run compressed)
 *   CIDR       network address (host bits cleared) + "/" + prefix length
 */
import { isIPv4, isIPv6 } from 'node:net';

const PREFIX_RE = /^\d{1,3}$/;

function ipv4ToBigInt(addr) {
  return addr.split('.').reduce((acc, part) => (acc << 8n) + BigInt(Number(part)), 0n);
}

function bigIntToIpv4(n) {
  return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join('.');
}

/** Eight 16-bit groups of a valid IPv6 address (embedded IPv4 tail included). */
function ipv6Groups(addr) {
  let a = addr.toLowerCase();
  const tail = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(a);
  if (tail) {
    const n = ipv4ToBigInt(tail[1]);
    a = `${a.slice(0, -tail[1].length)}${(n >> 16n).toString(16)}:${(n & 0xffffn).toString(16)}`;
  }
  const [head, rest] = a.split('::');
  const h = head ? head.split(':') : [];
  const r = rest !== undefined && rest !== '' ? rest.split(':') : [];
  const fill = rest !== undefined ? Array(8 - h.length - r.length).fill('0') : [];
  return [...h, ...fill, ...r].map((g) => parseInt(g, 16));
}

function ipv6ToBigInt(addr) {
  return ipv6Groups(addr).reduce((acc, g) => (acc << 16n) + BigInt(g), 0n);
}

/** RFC 5952 text form of a 128-bit value. */
function bigIntToIpv6(n) {
  const groups = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let best = { start: -1, len: 0 };
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i += 1; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > best.len) best = { start: i, len: j - i };
    i = j;
  }
  // IPv4-mapped addresses keep the dotted tail (RFC 5952 §5).
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return `::ffff:${bigIntToIpv4(n & 0xffffffffn)}`;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best.len < 2) return hex.join(':');
  const left = hex.slice(0, best.start).join(':');
  const right = hex.slice(best.start + best.len).join(':');
  return `${left}::${right}`;
}

/**
 * Parse a value as a network observable.
 * @param {string} raw
 * @returns {null | { ok: true, type: 'ip'|'ipv6', value: string, kind: 'host'|'cidr', prefix?: number }
 *   | { ok: false, error: string }}
 *   null when the value is not shaped like an IP address or network at all
 *   (callers fall back to their own inference).
 */
export function parseNetworkObservable(raw) {
  const v = String(raw ?? '').trim();
  if (!v || /\s/.test(v)) return null;
  const slash = v.indexOf('/');
  const addr = slash >= 0 ? v.slice(0, slash) : v;
  const v4 = isIPv4(addr);
  const v6 = !v4 && isIPv6(addr);
  if (!v4 && !v6) {
    // "198.51.100.0/33"-style shapes are a malformed network, not a URL.
    if (slash > 0 && /^[\d.]+$/.test(addr) && /^\d+$/.test(v.slice(slash + 1))) {
      return { ok: false, error: 'Invalid IPv4 network address' };
    }
    return null;
  }
  if (slash < 0) {
    return v4
      ? { ok: true, type: 'ip', value: bigIntToIpv4(ipv4ToBigInt(addr)), kind: 'host' }
      : { ok: true, type: 'ipv6', value: bigIntToIpv6(ipv6ToBigInt(addr)), kind: 'host' };
  }
  const prefixText = v.slice(slash + 1);
  const max = v4 ? 32 : 128;
  if (!PREFIX_RE.test(prefixText) || Number(prefixText) > max) {
    return { ok: false, error: `Invalid CIDR prefix length (expected /0–/${max})` };
  }
  const prefix = Number(prefixText);
  // A /0 network is the whole address space: never an actionable indicator.
  if (prefix === 0) return { ok: false, error: 'A /0 network covers every address and cannot be an IOC' };
  const bits = BigInt(max);
  const all = (1n << bits) - 1n;
  const mask = prefix === 0 ? 0n : (all >> BigInt(max - prefix)) << BigInt(max - prefix);
  const network = (v4 ? ipv4ToBigInt(addr) : ipv6ToBigInt(addr)) & mask;
  return {
    ok: true,
    type: v4 ? 'ip' : 'ipv6',
    value: `${v4 ? bigIntToIpv4(network) : bigIntToIpv6(network)}/${prefix}`,
    kind: 'cidr',
    prefix
  };
}

/** True when the value is a valid (canonicalizable) CIDR network. */
export function isCidrObservable(raw) {
  const p = parseNetworkObservable(raw);
  return Boolean(p && p.ok && p.kind === 'cidr');
}
