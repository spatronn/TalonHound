import { normalizeObservable } from './observable-normalization.js';

export const MATCH_SCOPE_HOST_ROOT_URL = 'host_root_url';

/**
 * Returns true if a normalized URL has no meaningful path/query beyond root '/'.
 * Used to guard domain-observable vs URL-IOC cross-matching against false positives:
 * a CONNECT proxy log only proves the host was contacted, not a specific path.
 */
export function isRootUrlIoc(value) {
  const v = String(value || '').trim();
  if (!v) return false;
  try {
    const u = new URL(v);
    const path = u.pathname || '/';
    return (path === '/' || path === '') && !u.search && !u.hash;
  } catch {
    return false;
  }
}

/**
 * Returns the normalized root URL forms for a domain.
 * These are the only URL-IOC values a domain observable may cross-match against.
 * Examples: 'ultimatebodyrecovery.com' -> ['https://ultimatebodyrecovery.com/', 'http://ultimatebodyrecovery.com/']
 */
export function rootUrlCandidatesFromDomain(domain) {
  const d = String(domain || '').trim().toLowerCase();
  if (!d) return [];
  return [
    normalizeObservable('url', `https://${d}`),
    normalizeObservable('url', `http://${d}`)
  ].filter(Boolean);
}

export function pickBestLookup(a, b) {
  if (!a) return b || null;
  if (!b) return a;
  const ta = new Date(a.updated_at).getTime();
  const tb = new Date(b.updated_at).getTime();
  if (Number.isNaN(ta) && Number.isNaN(tb)) return a;
  if (Number.isNaN(ta)) return b;
  if (Number.isNaN(tb)) return a;
  if (tb !== ta) return tb > ta ? b : a;
  return Number(b.confidence || 0) > Number(a.confidence || 0) ? b : a;
}

/**
 * Build ioc_lookup query tuples for a given observable.
 *
 * For domain observables, also generates normalized root URL forms
 * (https://domain/, http://domain/) to enable cross-matching against
 * root-only URL IOCs (e.g. URLhaus entries with no meaningful path).
 * Path-containing URL IOCs are never reachable from a domain tuple.
 */
export function lookupTuplesForObs(obs) {
  const t = obs.type;
  const v = String(obs.value || '').trim();
  if (!v) return [];
  if (t === 'ipv4') return [[v, 'ip']];
  if (t === 'sha256') return [[v.toLowerCase(), 'sha256']];
  if (t === 'domain') {
    const lv = v.toLowerCase();
    const rootUrls = rootUrlCandidatesFromDomain(lv);
    return [
      [lv, 'domain'],
      [lv, 'url'],                        // backward-compat: bare-domain vs url-typed IOC
      ...rootUrls.map((u) => [u, 'url'])  // root URL forms: https://domain/, http://domain/
    ];
  }
  if (t === 'url') return [[normalizeObservable('url', v), 'url']];
  return [];
}

/**
 * Find the best IOC lookup hit for an observable in the pre-fetched lookup map.
 *
 * For domain observables, also checks root URL forms in the map.
 * If the winning match came via a root URL IOC (not a domain IOC), the returned
 * object is annotated with _matchScope: MATCH_SCOPE_HOST_ROOT_URL so callers can record it
 * in match event metadata.
 */
export function matchObsToLookup(obs, lookupMap) {
  const t = obs.type;
  const v = String(obs.value || '').trim();
  if (!v) return null;

  if (t === 'ipv4') {
    return lookupMap.get(`ip\t${v}`) || null;
  }
  if (t === 'sha256') {
    return lookupMap.get(`sha256\t${v.toLowerCase()}`) || null;
  }
  if (t === 'domain') {
    const lv = v.toLowerCase();
    const byType = pickBestLookup(
      lookupMap.get(`domain\t${lv}`) || null,
      lookupMap.get(`url\t${lv}`) || null
    );
    const rootUrls = rootUrlCandidatesFromDomain(lv);
    const byRootUrl = rootUrls.reduce(
      (best, u) => pickBestLookup(best, lookupMap.get(`url\t${u}`) || null),
      null
    );
    if (!byType && !byRootUrl) return null;
    if (!byType) return { ...byRootUrl, _matchScope: MATCH_SCOPE_HOST_ROOT_URL };
    if (!byRootUrl) return byType;
    const best = pickBestLookup(byType, byRootUrl);
    if (best === byRootUrl) return { ...byRootUrl, _matchScope: MATCH_SCOPE_HOST_ROOT_URL };
    return best;
  }
  if (t === 'url') {
    const lv = v.toLowerCase();
    return pickBestLookup(lookupMap.get(`url\t${lv}`), lookupMap.get(`domain\t${lv}`)) || null;
  }
  return null;
}
