import { parse as parseTld } from 'tldts';

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6_RE = /^([0-9a-f:]+:+)+[0-9a-f]+$/i;
const HASH_RE = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;

/** ICANN registrable domain — private suffixes (e.g. netlify.app) are not treated as the RDAP root. */
const TLD_OPTS = { allowPrivateDomains: false, detectIp: false };

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
  let hostname = '';
  let inputType = hint === 'url' ? 'url' : 'domain';

  if (hasScheme || (looksLikePath && (hint === 'url' || raw.includes('://')))) {
    try {
      const urlStr = raw.startsWith('//') ? `https:${raw}` : (hasScheme ? raw : `https://${raw}`);
      const u = new URL(urlStr);
      hostname = stripHostPort(u.hostname);
      inputType = 'url';
      if (!hostname) return { ok: false, code: 'invalid', message: 'Invalid domain or URL' };
    } catch {
      return { ok: false, code: 'invalid', message: 'Invalid domain or URL' };
    }
  } else if (looksLikePath) {
    try {
      const u = new URL(`https://${raw}`);
      hostname = stripHostPort(u.hostname);
      inputType = hint === 'url' ? 'url' : 'domain';
    } catch {
      hostname = stripHostPort(raw.split('/')[0].split('?')[0].split('#')[0]);
    }
  } else {
    hostname = stripHostPort(raw.split('/')[0].split('?')[0].split('#')[0]);
    if (hint === 'url') inputType = 'url';
  }

  if (!hostname) {
    return { ok: false, code: 'invalid', message: 'Invalid domain or URL' };
  }

  return { ok: true, hostname, inputType };
}

/**
 * Normalize IOC value for on-demand RDAP lookup.
 * @param {string} value
 * @param {string|null} [hintType] domain | url | ip | hash
 * @returns {{ ok: true, original_value: string, normalized_host: string, rdap_domain: string, input_type: string, root_domain: string, observable_value: string, ioc_type: string } | { ok: false, code: string, message: string }}
 */
export function normalizeRdapTarget(value, hintType = null) {
  const original_value = String(value || '').trim();
  if (!original_value) {
    return { ok: false, code: 'empty', message: 'Value is required' };
  }

  const hint = String(hintType || '').toLowerCase();
  if (hint && hint !== 'domain' && hint !== 'url') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'RDAP enrichment supports domain and URL observables only'
    };
  }

  if (HASH_RE.test(original_value)) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'RDAP enrichment supports domain and URL observables only'
    };
  }

  const hostStep = extractHostname(original_value, hint);
  if (!hostStep.ok) return hostStep;

  const { hostname: normalized_host, inputType: input_type } = hostStep;

  if (IPV4_RE.test(normalized_host) || IPV6_RE.test(normalized_host)) {
    return {
      ok: false,
      code: 'unsupported',
      message: 'RDAP enrichment supports domain and URL observables only'
    };
  }

  const parsed = parseTld(normalized_host, TLD_OPTS);
  const rdap_domain = parsed.domain ? String(parsed.domain).toLowerCase() : null;
  if (!rdap_domain) {
    return { ok: false, code: 'invalid', message: 'Invalid domain or URL' };
  }

  const ioc_type = input_type === 'url' ? 'url' : 'domain';

  return {
    ok: true,
    original_value,
    normalized_host,
    rdap_domain,
    input_type,
    root_domain: rdap_domain,
    observable_value: normalized_host,
    ioc_type
  };
}

/** @deprecated Use normalizeRdapTarget — kept for legacy route handlers */
export function parseDomainOrUrlInput(value, hintType = null) {
  const r = normalizeRdapTarget(value, hintType);
  if (!r.ok) return r;
  return {
    ok: true,
    observable_value: r.observable_value,
    root_domain: r.root_domain,
    ioc_type: r.ioc_type,
    normalized_host: r.normalized_host,
    rdap_domain: r.rdap_domain,
    original_value: r.original_value,
    input_type: r.input_type
  };
}

export function isRdapSupportedIocType(type) {
  const t = String(type || '').toLowerCase();
  return t === 'domain' || t === 'url';
}
