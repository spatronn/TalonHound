import { isValidIpAddress } from './publicIp.js';

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^([0-9a-f:]+:+)+[0-9a-f]+$/i;
const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function stripHostPort(host) {
  let h = String(host || '').trim().toLowerCase();
  h = h.replace(/\.$/, '').replace(/^\[/, '').replace(/\]$/, '');
  const portIdx = h.indexOf(':');
  if (portIdx > 0 && /^\d+$/.test(h.slice(portIdx + 1))) {
    h = h.slice(0, portIdx);
  }
  return h;
}

function extractHostname(raw, hintType = null) {
  const hint = String(hintType || '').toLowerCase();
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith('//');
  const looksLikePath = raw.includes('/') && !raw.includes('@');

  if (hasScheme || (looksLikePath && (hint === 'url' || raw.includes('://')))) {
    try {
      const urlStr = raw.startsWith('//') ? `https:${raw}` : (hasScheme ? raw : `https://${raw}`);
      const u = new URL(urlStr);
      const hostname = stripHostPort(u.hostname);
      if (!hostname) return { ok: false, code: 'invalid', message: 'Invalid URL hostname' };
      return { ok: true, hostname, inputType: 'url' };
    } catch {
      return { ok: false, code: 'invalid', message: 'Invalid URL' };
    }
  }

  if (looksLikePath) {
    try {
      const u = new URL(`https://${raw}`);
      return { ok: true, hostname: stripHostPort(u.hostname), inputType: hint === 'url' ? 'url' : 'domain' };
    } catch {
      const hostname = stripHostPort(raw.split('/')[0].split('?')[0].split('#')[0]);
      if (!hostname) return { ok: false, code: 'invalid', message: 'Invalid domain or URL' };
      return { ok: true, hostname, inputType: hint === 'url' ? 'url' : 'domain' };
    }
  }

  const hostname = stripHostPort(raw.split('/')[0].split('?')[0].split('#')[0]);
  if (!hostname) return { ok: false, code: 'invalid', message: 'Invalid domain or URL' };
  return { ok: true, hostname, inputType: hint === 'url' ? 'url' : 'domain' };
}

function isIpHost(host) {
  const h = String(host || '').trim();
  if (!h) return false;
  if (IPV4_RE.test(h)) return true;
  if (h.includes(':') && IPV6_RE.test(h)) return true;
  return isValidIpAddress(h);
}

function isValidHostname(host) {
  const h = String(host || '').trim().toLowerCase();
  if (!h || h.length > 253) return false;
  if (h === 'localhost') return false;
  return HOSTNAME_RE.test(h);
}

/**
 * Normalize IOC value for DNSMania lookup (domain | ip).
 * @param {string|null} iocType
 * @param {string} iocValue
 */
export function normalizeDnsmaniaLookup(iocType, iocValue) {
  const original_value = String(iocValue || '').trim();
  const hint = String(iocType || '').trim().toLowerCase();

  if (!original_value) {
    return { ok: false, code: 'empty', message: 'Value is required' };
  }

  if (hint === 'hash' || hint === 'file_hash' || HASH_RE.test(original_value)) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'DNSMania enrichment supports domain, URL, and IP observables only'
    };
  }

  if (hint === 'ip' || (!hint && isIpHost(stripHostPort(original_value)))) {
    const ip = stripHostPort(original_value.split('/')[0]);
    if (!isIpHost(ip)) {
      return { ok: false, code: 'invalid', message: 'Invalid IP address' };
    }
    return {
      ok: true,
      original_value,
      ioc_type: 'ip',
      lookup_type: 'ip',
      lookup_value: ip,
      lookup_key: `ip:${ip}`,
      observable_value: ip
    };
  }

  if (hint === 'url' || hint === 'domain' || !hint) {
    const hostStep = extractHostname(original_value, hint || null);
    if (!hostStep.ok) return hostStep;

    const host = hostStep.hostname;
    if (isIpHost(host)) {
      return {
        ok: true,
        original_value,
        ioc_type: hint === 'url' || hostStep.inputType === 'url' ? 'url' : 'ip',
        lookup_type: 'ip',
        lookup_value: host,
        lookup_key: `ip:${host}`,
        observable_value: host
      };
    }

    if (!isValidHostname(host)) {
      return { ok: false, code: 'invalid', message: 'Invalid domain or URL hostname' };
    }

    return {
      ok: true,
      original_value,
      ioc_type: hint === 'url' || hostStep.inputType === 'url' ? 'url' : 'domain',
      lookup_type: 'domain',
      lookup_value: host,
      lookup_key: `domain:${host}`,
      observable_value: host
    };
  }

  return {
    ok: false,
    code: 'unsupported',
    message: 'DNSMania enrichment supports domain, URL, and IP observables only'
  };
}

export function isDnsmaniaSupportedIocType(iocType) {
  const t = String(iocType || '').trim().toLowerCase();
  return t === 'domain' || t === 'url' || t === 'ip' || t === 'ipv4' || t === 'ipv6' || t === 'ip6' || t === 'hostname';
}
