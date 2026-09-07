/**
 * Extract an IP literal from IP or URL IOC values.
 *
 * Matches production Derived Infrastructure / Spamhaus / AbuseIPDB host parsing:
 * - IP IOC → strip CIDR suffix
 * - URL IOC → hostname when it is an IPv4/IPv6 literal (no DNS resolve for domain hosts)
 * - Port and IPv6 brackets are normalized away
 *
 * Shared by enrichment routes and MCP so UI and MCP stay on one path.
 */

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/**
 * @param {string} iocValue
 * @param {string} iocType
 * @returns {string|null} normalized IP literal, or null when not applicable
 */
export function extractIpLiteralFromIoc(iocValue, iocType) {
  const type = String(iocType || '').trim().toLowerCase();
  if (type === 'ip' || type === 'ipv4' || type === 'ipv6' || type === 'ip6') {
    return String(iocValue || '').trim().split('/')[0].trim() || null;
  }
  if (type === 'url') {
    try {
      const u = new URL(String(iocValue || '').trim());
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      const host = u.hostname;
      if (!host) return null;
      const hostClean = host.replace(/^\[|\]$/g, '');
      const isIp = IPV4_RE.test(hostClean) || hostClean.includes(':');
      if (!isIp) return null;
      return hostClean;
    } catch {
      return null;
    }
  }
  return null;
}
