/**
 * AlienVault / LevelBlue OTX DirectConnect API — subscribed pulses feed.
 *
 * Docs: https://otx.alienvault.com/assets/static/external_api.html
 *  - Base URL: https://otx.alienvault.com
 *  - Auth header: X-OTX-API-KEY
 *  - Subscribed pulses: GET /api/v1/pulses/subscribed?modified_since=<ISO>&limit=<n>&page=<n>
 *      -> { count, next, previous, results: [ { id, name, ..., indicators: [ { indicator, type, ... } ] } ] }
 *  - Pagination: follow the absolute `next` URL until null.
 *
 * This module contains only pure/testable helpers plus the HTTP client. The
 * DB import orchestration lives in importer.js (runAlienvaultOtxImport).
 */

export const ALIENVAULT_OTX_FEED_KEY = 'alienvault-otx';
export const ALIENVAULT_OTX_SOURCE_NAME = 'AlienVault OTX';
export const ALIENVAULT_OTX_API_BASE_DEFAULT = 'https://otx.alienvault.com';
export const ALIENVAULT_OTX_SUBSCRIBED_PATH = '/api/v1/pulses/subscribed';
export const ALIENVAULT_OTX_PULSE_BASE_URL = 'https://otx.alienvault.com/pulse/';
export const ALIENVAULT_OTX_AUTH_REQUIRED_MSG =
  'AlienVault OTX API key is missing. Configure it in integration settings or ALIENVAULT_OTX_API_KEY env.';

export const OTX_PAGE_LIMIT_DEFAULT = 50;
export const OTX_PAGE_LIMIT_MAX = 100;
/** Hard cap on pages walked per run to protect the worker from runaway pagination. */
export const OTX_MAX_PAGES_DEFAULT = 200;

const OTX_API_KEY_HEADER = 'X-OTX-API-KEY';

/** OTX indicator type -> platform observable_type. Unlisted types are unsupported. */
export const OTX_SUPPORTED_TYPE_MAP = Object.freeze({
  IPv4: 'ip',
  IPv6: 'ipv6',
  domain: 'domain',
  hostname: 'domain',
  URL: 'url',
  URI: 'url',
  'FileHash-MD5': 'md5',
  'FileHash-SHA1': 'sha1',
  'FileHash-SHA256': 'sha256'
});

export function maskOtxApiKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `************${s.slice(-4)}`;
}

/** Redact the OTX API key from any error/log string. */
export function sanitizeOtxErrorMessage(message) {
  let out = String(message || '');
  out = out.replace(/\bX-OTX-API-KEY\s*[:=]\s*\S+/gi, 'X-OTX-API-KEY: ***');
  out = out.replace(/([?&]apikey=)[^&\s]+/gi, '$1***');
  out = out.replace(/("api_key"\s*:\s*)"[^"]*"/gi, '$1"***"');
  return out;
}

export function normalizeOtxApiBase(value) {
  const raw = String(value || ALIENVAULT_OTX_API_BASE_DEFAULT).trim();
  if (!raw) return ALIENVAULT_OTX_API_BASE_DEFAULT;
  return raw.replace(/\/+$/, '');
}

export function clampOtxPageLimit(value, fallback = OTX_PAGE_LIMIT_DEFAULT) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const rounded = Math.floor(n);
  if (rounded < 1) return fallback;
  if (rounded > OTX_PAGE_LIMIT_MAX) return OTX_PAGE_LIMIT_MAX;
  return rounded;
}

function isIPv4(value) {
  const m = String(value || '').match(/^(\d{1,3})(?:\.(\d{1,3})){3}$/);
  if (!m) return false;
  return String(value).split('.').every((oct) => Number(oct) >= 0 && Number(oct) <= 255);
}

function isIPv6(value) {
  const v = String(value || '').trim();
  if (!v.includes(':')) return false;
  return /^[0-9a-f:.%]+$/i.test(v);
}

const HEX_HASH_LENGTHS = { md5: 32, sha1: 40, sha256: 64 };

function isValidHashForType(value, observableType) {
  const len = HEX_HASH_LENGTHS[observableType];
  if (!len) return false;
  return new RegExp(`^[0-9a-f]{${len}}$`, 'i').test(String(value || '').trim());
}

function looksLikeUrl(value) {
  const v = String(value || '').trim();
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(v) || v.includes('/');
}

/** @returns {'supported'|'unsupported'} classification for an OTX indicator type. */
export function classifyOtxIndicatorType(type) {
  const key = String(type || '').trim();
  return Object.prototype.hasOwnProperty.call(OTX_SUPPORTED_TYPE_MAP, key)
    ? 'supported'
    : 'unsupported';
}

/**
 * Normalize a raw OTX indicator into { observable, observableType } or null.
 * Applies platform normalization: lowercase for domain/url/hash, trailing-dot
 * strip for domains, IPv4/IPv6/hash validation, and domain->url reclassification
 * when a domain/hostname value actually carries a scheme/path.
 */
export function normalizeOtxIndicator(rawType, rawValue) {
  const type = String(rawType || '').trim();
  const value = String(rawValue || '').trim();
  if (!value) return null;

  let observableType = OTX_SUPPORTED_TYPE_MAP[type];
  if (!observableType) return null;

  // domain/hostname carrying a scheme or path is really a URL.
  if (observableType === 'domain' && looksLikeUrl(value)) {
    observableType = 'url';
  }

  if (observableType === 'ip') {
    return isIPv4(value) ? { observable: value, observableType: 'ip' } : null;
  }
  if (observableType === 'ipv6') {
    return isIPv6(value) ? { observable: value.toLowerCase(), observableType: 'ipv6' } : null;
  }
  if (observableType === 'url') {
    return { observable: value.toLowerCase(), observableType: 'url' };
  }
  if (observableType === 'domain') {
    const domain = value.replace(/\.+$/, '').toLowerCase();
    if (!domain || /\s/.test(domain)) return null;
    return { observable: domain, observableType: 'domain' };
  }
  if (observableType === 'md5' || observableType === 'sha1' || observableType === 'sha256') {
    const hash = value.toLowerCase();
    return isValidHashForType(hash, observableType) ? { observable: hash, observableType } : null;
  }
  return null;
}

export function buildOtxPulseReferenceUrl(pulseId) {
  const id = String(pulseId || '').trim();
  if (!id) return null;
  return `${ALIENVAULT_OTX_PULSE_BASE_URL}${id}`;
}

export function normalizeOtxTags(raw) {
  if (Array.isArray(raw)) return raw.map((t) => String(t || '').trim()).filter(Boolean);
  const v = String(raw ?? '').trim();
  if (!v) return [];
  return v.split(',').map((t) => t.trim()).filter(Boolean);
}

export function parseOtxTimestamp(value) {
  let raw = String(value ?? '').trim();
  if (!raw) return null;
  // OTX serializes source timestamps as naive UTC without a zone designator
  // (e.g. "2026-07-30T13:03:20" or "2026-07-30T13:03:19.240000"). `new Date()` would
  // interpret a zone-less string in the worker process's local timezone, silently
  // shifting the source date when the worker is not on UTC. Pin such strings to UTC so
  // parsing is timezone-independent. Strings that already carry 'Z' or a ±HH:MM offset
  // are left untouched.
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(raw)) {
    raw = `${raw.replace(' ', 'T')}Z`;
  }
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

/** Earlier of two Dates; tolerates nulls (returns the non-null one, or null). */
export function earlierDate(a, b) {
  if (!a) return b || null;
  if (!b) return a || null;
  return a.getTime() <= b.getTime() ? a : b;
}

/**
 * Map a pulse + one of its indicators into an import entry.
 * @returns {{supported:true, entry:object} | {supported:false, rawType:string}}
 */
export function mapOtxPulseIndicator(pulse, indicator) {
  const rawType = String(indicator?.type || '').trim();
  const normalized = normalizeOtxIndicator(rawType, indicator?.indicator);
  if (!normalized) {
    return { supported: false, rawType: rawType || 'unknown' };
  }

  const pulseId = String(pulse?.id || '').trim() || null;
  const tags = normalizeOtxTags(pulse?.tags);
  const pulseModified = parseOtxTimestamp(pulse?.modified);
  const pulseCreated = parseOtxTimestamp(pulse?.created);
  const indicatorCreated = parseOtxTimestamp(indicator?.created);

  return {
    supported: true,
    entry: {
      ...normalized,
      pulseId,
      pulseName: String(pulse?.name || '').trim() || null,
      pulseAuthor: String(pulse?.author_name || '').trim() || null,
      pulseTlp: String(pulse?.tlp || '').trim() || null,
      pulseAdversary: String(pulse?.adversary || '').trim() || null,
      pulseTags: tags,
      pulseCreated,
      pulseModified,
      indicatorId: indicator?.id != null ? String(indicator.id) : null,
      indicatorCreated,
      // first_seen: when the indicator entered the pulse; last_seen: pulse freshness.
      firstSeen: indicatorCreated || pulseCreated,
      lastSeen: pulseModified || indicatorCreated,
      referenceUrl: buildOtxPulseReferenceUrl(pulseId)
    }
  };
}

/** Note string (pipe key=value) consumed by extractObservablesFromNote + evidence. */
export function buildOtxNote(entry) {
  const parts = [
    'Auto-imported from AlienVault OTX (subscribed pulses)',
    entry.pulseId ? `pulse_id=${entry.pulseId}` : null,
    entry.pulseName ? `pulse_name=${entry.pulseName}` : null,
    entry.pulseAuthor ? `pulse_author=${entry.pulseAuthor}` : null,
    entry.pulseAdversary ? `adversary=${entry.pulseAdversary}` : null,
    entry.pulseTlp ? `tlp=${entry.pulseTlp}` : null,
    entry.pulseTags?.length ? `tags=${entry.pulseTags.join(',')}` : null,
    entry.indicatorId ? `indicator_id=${entry.indicatorId}` : null,
    entry.pulseModified ? `pulse_modified=${entry.pulseModified.toISOString()}` : null,
    entry.referenceUrl ? `reference=${entry.referenceUrl}` : null
  ].filter(Boolean);
  return parts.join(' | ');
}

/** Structured source-evidence metadata for the OTX pulse context. */
export function buildOtxEvidenceMetadata(entry) {
  return {
    provider: 'alienvault_otx',
    pulse_id: entry.pulseId,
    pulse_name: entry.pulseName,
    pulse_author: entry.pulseAuthor,
    pulse_modified: entry.pulseModified ? entry.pulseModified.toISOString() : null,
    pulse_created: entry.pulseCreated ? entry.pulseCreated.toISOString() : null,
    pulse_tags: entry.pulseTags || [],
    pulse_tlp: entry.pulseTlp,
    indicator_type: entry.observableType,
    indicator_created: entry.indicatorCreated ? entry.indicatorCreated.toISOString() : null,
    otx_reference: entry.referenceUrl
  };
}

/**
 * Collapse indicators from all subscribed pulses into a deduped entry list.
 * When the same observable appears in multiple pulses, keep the entry from the
 * most recently modified pulse (latest context wins). Global (observable,type)
 * dedup on insert still prevents duplicate IOC rows; this only avoids redundant
 * work and picks the freshest pulse context for the note/evidence.
 *
 * @returns {{ entries: object[], fetchedIndicators: number,
 *   unsupportedIndicators: number, unsupportedBreakdown: Record<string, number> }}
 */
export function collectOtxEntries(pulses) {
  const byKey = new Map();
  const unsupportedBreakdown = {};
  let fetchedIndicators = 0;
  let unsupportedIndicators = 0;

  const noteUnsupported = (rawType) => {
    const key = String(rawType || 'unknown').trim() || 'unknown';
    unsupportedBreakdown[key] = (unsupportedBreakdown[key] || 0) + 1;
    unsupportedIndicators += 1;
  };

  for (const pulse of Array.isArray(pulses) ? pulses : []) {
    const indicators = Array.isArray(pulse?.indicators) ? pulse.indicators : [];
    for (const indicator of indicators) {
      fetchedIndicators += 1;
      if (classifyOtxIndicatorType(indicator?.type) === 'unsupported') {
        noteUnsupported(indicator?.type);
        continue;
      }
      const mapped = mapOtxPulseIndicator(pulse, indicator);
      if (!mapped.supported) {
        // Passed the type allow-list but failed value validation (e.g. malformed hash).
        noteUnsupported(mapped.rawType || 'invalid');
        continue;
      }
      const entry = mapped.entry;
      const key = `${entry.observableType}|${entry.observable}`;
      const prev = byKey.get(key);
      if (!prev) {
        byKey.set(key, entry);
        continue;
      }
      // Keep the freshest pulse context (note/evidence) but preserve the EARLIEST
      // source first-seen across every pulse the observable appears in — that is the
      // correct "first seen in source" for an IOC carried by multiple pulses.
      const earliestFirstSeen = earlierDate(prev.firstSeen, entry.firstSeen);
      const prevMod = prev.pulseModified ? prev.pulseModified.getTime() : 0;
      const curMod = entry.pulseModified ? entry.pulseModified.getTime() : 0;
      const winner = curMod >= prevMod ? entry : prev;
      winner.firstSeen = earliestFirstSeen;
      byKey.set(key, winner);
    }
  }

  return {
    entries: [...byKey.values()],
    fetchedIndicators,
    unsupportedIndicators,
    unsupportedBreakdown
  };
}

export function buildOtxSubscribedUrl({ apiBase, modifiedSince, page, limit } = {}) {
  const base = normalizeOtxApiBase(apiBase);
  const url = new URL(`${base}${ALIENVAULT_OTX_SUBSCRIBED_PATH}`);
  url.searchParams.set('limit', String(clampOtxPageLimit(limit)));
  if (page != null) url.searchParams.set('page', String(page));
  const since = String(modifiedSince || '').trim();
  if (since) url.searchParams.set('modified_since', since);
  return url.toString();
}

/**
 * Fetch a single subscribed-pulses page.
 * @returns {{ pulses: object[], next: string|null, count: number|null, queryUrlPath: string }}
 */
export async function fetchOtxSubscribedPage({
  apiKey,
  url,
  apiBase = ALIENVAULT_OTX_API_BASE_DEFAULT,
  modifiedSince = null,
  page = 1,
  limit = OTX_PAGE_LIMIT_DEFAULT,
  signal,
  fetchFn = fetch
}) {
  const key = String(apiKey || '').trim();
  if (!key) throw new Error(ALIENVAULT_OTX_AUTH_REQUIRED_MSG);

  const requestUrl = url || buildOtxSubscribedUrl({ apiBase, modifiedSince, page, limit });

  const res = await fetchFn(requestUrl, {
    method: 'GET',
    headers: {
      [OTX_API_KEY_HEADER]: key,
      Accept: 'application/json'
    },
    signal
  });

  if (res.status === 401 || res.status === 403) {
    const err = new Error(`AlienVault OTX API authentication failed (HTTP ${res.status})`);
    err.statusCode = res.status;
    throw err;
  }
  if (res.status === 429) {
    const err = new Error('AlienVault OTX API rate limit exceeded (HTTP 429)');
    err.statusCode = 429;
    err.retryAfter = res.headers?.get?.('retry-after') || null;
    throw err;
  }
  if (!res.ok) {
    const err = new Error(`AlienVault OTX API request failed (HTTP ${res.status})`);
    err.statusCode = res.status;
    throw err;
  }

  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`AlienVault OTX API returned invalid JSON (HTTP ${res.status})`);
  }

  const pulses = Array.isArray(json?.results) ? json.results : [];
  const next = json?.next ? String(json.next) : null;
  const count = Number.isFinite(Number(json?.count)) ? Number(json.count) : null;
  return { pulses, next, count };
}

/**
 * Walk subscribed pulses across pages (following `next`) and invoke onPulse for each.
 * Returns pagination stats. Bounded by maxPages.
 */
export async function walkOtxSubscribedPulses({
  apiKey,
  apiBase = ALIENVAULT_OTX_API_BASE_DEFAULT,
  modifiedSince = null,
  limit = OTX_PAGE_LIMIT_DEFAULT,
  maxPages = OTX_MAX_PAGES_DEFAULT,
  signal,
  fetchFn = fetch,
  onPulse
}) {
  let nextUrl = buildOtxSubscribedUrl({ apiBase, modifiedSince, page: 1, limit });
  let pages = 0;
  let fetchedPulses = 0;
  let count = null;

  while (nextUrl && pages < maxPages) {
    const { pulses, next, count: pageCount } = await fetchOtxSubscribedPage({
      apiKey,
      url: nextUrl,
      signal,
      fetchFn
    });
    pages += 1;
    if (count == null && pageCount != null) count = pageCount;
    for (const pulse of pulses) {
      fetchedPulses += 1;
      if (onPulse) await onPulse(pulse);
    }
    nextUrl = next;
  }

  return { pages, fetchedPulses, count, truncated: Boolean(nextUrl) };
}

/**
 * Resolve the OTX API key from integration_feeds.credentials, falling back to env.
 */
export async function resolveOtxApiKey(client, envApiKey = process.env.ALIENVAULT_OTX_API_KEY) {
  const res = await client.query(
    `SELECT credentials FROM integration_feeds WHERE key = $1`,
    [ALIENVAULT_OTX_FEED_KEY]
  );
  const creds = res.rows[0]?.credentials;
  const fromDb = creds && typeof creds === 'object' ? String(creds.auth_key || '').trim() : '';
  if (fromDb) return fromDb;

  const fromEnv = String(envApiKey || '').trim();
  return fromEnv || null;
}
