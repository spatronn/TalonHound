import { parse as parseTld } from 'tldts';

const DEFAULT_IANA_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const DEFAULT_BOOTSTRAP_TTL_MS = 6 * 60 * 60 * 1000;
const DEFAULT_BOOTSTRAP_FETCH_TIMEOUT_MS = 15000;
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

function bootstrapUrl() {
  return String(process.env.RDAP_IANA_BOOTSTRAP_URL || DEFAULT_IANA_BOOTSTRAP_URL);
}

function bootstrapTtlMs() {
  return Number(process.env.RDAP_IANA_BOOTSTRAP_TTL_MS || DEFAULT_BOOTSTRAP_TTL_MS);
}

function bootstrapFetchTimeoutMs() {
  return Math.max(Number(process.env.RDAP_IANA_BOOTSTRAP_TIMEOUT_MS || DEFAULT_BOOTSTRAP_FETCH_TIMEOUT_MS), 1000);
}

async function loadIanaBootstrapMap() {
  const now = Date.now();
  const ttlMs = bootstrapTtlMs();
  if (bootstrapCache.tldToBases.size && (now - bootstrapCache.loadedAt) < ttlMs) {
    return bootstrapCache.tldToBases;
  }

  const timeoutMs = bootstrapFetchTimeoutMs();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(bootstrapUrl(), {
      headers: { Accept: 'application/json' },
      signal: controller.signal
    });
  } catch (err) {
    if (err?.name === 'AbortError') {
      throw new Error(`IANA RDAP bootstrap fetch timed out after ${timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    throw new Error(`IANA RDAP bootstrap fetch failed (${res.status})`);
  }

  const payload = await res.json();
  const tldToBases = buildTldBootstrapMap(payload);
  bootstrapCache = { loadedAt: now, tldToBases };
  return tldToBases;
}

/**
 * Resolve ordered RDAP domain URL candidates via IANA bootstrap, with rdap.org fallback last.
 * @param {string} rootDomain
 * @param {{ fallbackBase?: string }} [opts]
 */
export async function resolveRdapDomainUrlCandidates(rootDomain, { fallbackBase = DEFAULT_FALLBACK_BASE } = {}) {
  const domain = String(rootDomain || '').trim().toLowerCase();
  if (!domain) {
    throw new Error('RDAP domain is required');
  }

  const urls = [];
  const suffix = publicSuffixForDomain(domain);
  if (suffix) {
    try {
      const map = await loadIanaBootstrapMap();
      const bases = map.get(suffix);
      if (bases?.length) {
        for (const base of bases) urls.push(joinRdapDomainUrl(base, domain));
      }
    } catch (err) {
      console.warn('[rdap] IANA bootstrap lookup failed, falling back to rdap.org:', err?.message || err);
    }
  }

  urls.push(joinRdapDomainUrl(fallbackBase, domain));
  return [...new Set(urls)];
}

/**
 * Resolve authoritative RDAP domain URL via IANA bootstrap, with rdap.org fallback.
 * @param {string} rootDomain
 * @param {{ fallbackBase?: string }} [opts]
 */
export async function resolveRdapDomainUrl(rootDomain, { fallbackBase = DEFAULT_FALLBACK_BASE } = {}) {
  const urls = await resolveRdapDomainUrlCandidates(rootDomain, { fallbackBase });
  return urls[0];
}

/** Test helper */
export function resetRdapBootstrapCacheForTests() {
  bootstrapCache = { loadedAt: 0, tldToBases: new Map() };
}
