import { parse as parseTld } from 'tldts';

const IANA_BOOTSTRAP_URL = String(process.env.RDAP_IANA_BOOTSTRAP_URL || 'https://data.iana.org/rdap/dns.json');
const BOOTSTRAP_TTL_MS = Number(process.env.RDAP_IANA_BOOTSTRAP_TTL_MS || 6 * 60 * 60 * 1000);
const DEFAULT_FALLBACK_BASE = String(process.env.RDAP_BASE_URL || 'https://rdap.org').replace(/\/$/, '');

/** @type {{ loadedAt: number, tldToBases: Map<string, string[]> }} */
let bootstrapCache = { loadedAt: 0, tldToBases: new Map() };

export function joinRdapDomainUrl(baseUrl, domain) {
  const base = String(baseUrl || '').replace(/\/$/, '');
  const name = String(domain || '').trim().toLowerCase();
  return `${base}/domain/${encodeURIComponent(name)}`;
}

export function publicSuffixForDomain(domain) {
  const parsed = parseTld(String(domain || '').trim().toLowerCase(), {
    allowPrivateDomains: false,
    detectIp: false
  });
  return parsed.publicSuffix ? String(parsed.publicSuffix).toLowerCase() : null;
}

/** @param {unknown} payload */
export function buildTldBootstrapMap(payload) {
  const map = new Map();
  for (const entry of payload?.services || []) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const tlds = entry[0];
    const bases = entry[1];
    if (!Array.isArray(tlds) || !Array.isArray(bases)) continue;
    for (const tld of tlds) {
      const key = String(tld || '').trim().toLowerCase();
      if (!key) continue;
      map.set(key, bases.map((b) => String(b || '').trim()).filter(Boolean));
    }
  }
  return map;
}

async function loadIanaBootstrapMap() {
  const now = Date.now();
  if (bootstrapCache.tldToBases.size && (now - bootstrapCache.loadedAt) < BOOTSTRAP_TTL_MS) {
    return bootstrapCache.tldToBases;
  }

  const res = await fetch(IANA_BOOTSTRAP_URL, {
    headers: { Accept: 'application/json' }
  });
  if (!res.ok) {
    throw new Error(`IANA RDAP bootstrap fetch failed (${res.status})`);
  }

  const payload = await res.json();
  const tldToBases = buildTldBootstrapMap(payload);
  bootstrapCache = { loadedAt: now, tldToBases };
  return tldToBases;
}

/**
 * Resolve authoritative RDAP domain URL via IANA bootstrap, with rdap.org fallback.
 * @param {string} rootDomain
 * @param {{ fallbackBase?: string }} [opts]
 */
export async function resolveRdapDomainUrl(rootDomain, { fallbackBase = DEFAULT_FALLBACK_BASE } = {}) {
  const domain = String(rootDomain || '').trim().toLowerCase();
  if (!domain) {
    throw new Error('RDAP domain is required');
  }

  const suffix = publicSuffixForDomain(domain);
  if (suffix) {
    try {
      const map = await loadIanaBootstrapMap();
      const bases = map.get(suffix);
      if (bases?.length) {
        return joinRdapDomainUrl(bases[0], domain);
      }
    } catch (err) {
      console.warn('[rdap] IANA bootstrap lookup failed, falling back to rdap.org:', err?.message || err);
    }
  }

  return joinRdapDomainUrl(fallbackBase, domain);
}

/** Test helper */
export function resetRdapBootstrapCacheForTests() {
  bootstrapCache = { loadedAt: 0, tldToBases: new Map() };
}
