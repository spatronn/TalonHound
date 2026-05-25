import { parse as parseTld } from 'tldts';

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^([0-9a-f:]+:+)+[0-9a-f]+$/i;
const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;

/**
 * Normalize domain or URL input to hostname + eTLD+1 root domain.
 * @param {string} value
 * @param {string|null} [hintType] domain | url
 * @returns {{ ok: true, observable_value: string, root_domain: string, ioc_type: string } | { ok: false, code: string, message: string }}
 */
export function parseDomainOrUrlInput(value, hintType = null) {
  const raw = String(value || '').trim();
  if (!raw) {
    return { ok: false, code: 'empty', message: 'Value is required' };
  }

  const hint = String(hintType || '').toLowerCase();
  if (hint && hint !== 'domain' && hint !== 'url') {
    return { ok: false, code: 'unsupported', message: 'IOC type is not supported for RDAP enrichment' };
  }

  if (HASH_RE.test(raw)) {
    return { ok: false, code: 'unsupported', message: 'Hash IOCs are not supported for RDAP enrichment' };
  }

  let hostname = '';
  let iocType = hint || 'domain';

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) || raw.startsWith('//');
  const looksLikePath = raw.includes('/') && !raw.includes('@');

  if (hasScheme || (looksLikePath && (hint === 'url' || raw.includes('://')))) {
    try {
      const urlStr = raw.startsWith('//') ? `https:${raw}` : (hasScheme ? raw : `https://${raw}`);
      const u = new URL(urlStr);
      hostname = String(u.hostname || '').toLowerCase();
      iocType = 'url';
      if (!hostname) return { ok: false, code: 'invalid_url', message: 'Could not parse URL hostname' };
    } catch {
      return { ok: false, code: 'invalid_url', message: 'Invalid URL' };
    }
  } else if (looksLikePath) {
    try {
      const u = new URL(`https://${raw}`);
      hostname = String(u.hostname || '').toLowerCase();
      iocType = hint === 'url' ? 'url' : 'domain';
    } catch {
      hostname = raw.split('/')[0].split('?')[0].split('#')[0].toLowerCase();
      const portIdx = hostname.indexOf(':');
      if (portIdx > 0 && /^\d+$/.test(hostname.slice(portIdx + 1))) {
        hostname = hostname.slice(0, portIdx);
      }
    }
  } else {
    hostname = raw.split('/')[0].split('?')[0].split('#')[0].toLowerCase();
    const portIdx = hostname.indexOf(':');
    if (portIdx > 0 && /^\d+$/.test(hostname.slice(portIdx + 1))) {
      hostname = hostname.slice(0, portIdx);
    }
    if (hint === 'url') iocType = 'url';
  }

  hostname = hostname.replace(/\.$/, '').replace(/^\[/, '').replace(/\]$/, '');
  if (!hostname) {
    return { ok: false, code: 'invalid_domain', message: 'Could not parse domain' };
  }

  if (IPV4_RE.test(hostname) || IPV6_RE.test(hostname)) {
    return { ok: false, code: 'unsupported', message: 'IP addresses are not supported for RDAP enrichment' };
  }

  const parsed = parseTld(hostname, { allowPrivateDomains: true });
  const rootDomain = parsed.domain ? String(parsed.domain).toLowerCase() : null;
  if (!rootDomain) {
    return { ok: false, code: 'invalid_domain', message: 'Could not determine registrable root domain' };
  }

  return {
    ok: true,
    observable_value: hostname,
    root_domain: rootDomain,
    ioc_type: iocType === 'url' ? 'url' : 'domain'
  };
}

export function isRdapSupportedIocType(type) {
  const t = String(type || '').toLowerCase();
  return t === 'domain' || t === 'url';
}
