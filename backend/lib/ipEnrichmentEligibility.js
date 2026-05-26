import { validatePublicIp } from './publicIp.js';

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function stripHostPort(host) {
  let h = String(host || '').trim().toLowerCase();
  h = h.replace(/\.$/, '').replace(/^\[/, '').replace(/\]$/, '');
  const portIdx = h.indexOf(':');
  if (portIdx > 0 && /^\d+$/.test(h.slice(portIdx + 1))) h = h.slice(0, portIdx);
  return h;
}

/**
 * Extract public IP from IOC observable when eligible for IP enrichment.
 * @returns {{ eligible: boolean, ip: string|null, reason?: string }}
 */
export function resolveIpEnrichmentTarget(observable, observableType) {
  const raw = String(observable || '').trim();
  const type = String(observableType || '').toLowerCase();
  if (!raw) return { eligible: false, ip: null, reason: 'empty' };

  if (type === 'domain' || type === 'file_hash' || type === 'hash' || type === 'email') {
    return { eligible: false, ip: null, reason: 'unsupported_type' };
  }

  if (type === 'ip') {
    const ip = validatePublicIp(raw);
    if (!ip) return { eligible: false, ip: null, reason: 'private_or_invalid' };
    return { eligible: true, ip };
  }

  if (type === 'url') {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return { eligible: false, ip: null, reason: 'unsupported_scheme' };
      }
      const host = stripHostPort(u.hostname);
      if (!IPV4_RE.test(host) && !host.includes(':')) {
        return { eligible: false, ip: null, reason: 'domain_host' };
      }
      const ip = validatePublicIp(host);
      if (!ip) return { eligible: false, ip: null, reason: 'private_or_invalid' };
      return { eligible: true, ip };
    } catch {
      return { eligible: false, ip: null, reason: 'invalid_url' };
    }
  }

  return { eligible: false, ip: null, reason: 'unsupported_type' };
}

/** @deprecated Use resolveIpEnrichmentTarget — kept for geo table compatibility */
export function extractIpv4ForGeo(observable, observableType) {
  const r = resolveIpEnrichmentTarget(observable, observableType);
  if (!r.eligible || !r.ip) return null;
  if (!IPV4_RE.test(r.ip)) return null;
  return r.ip;
}
