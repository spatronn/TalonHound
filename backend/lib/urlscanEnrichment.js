/**
 * urlscan.io passive enrichment helpers.
 *
 * READ-ONLY: this module never constructs scan-submission requests.
 * All outbound HTTP must go through urlscanAllowlistedFetch.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const URLSCAN_PROVIDER = 'urlscan';
export const URLSCAN_DISPLAY_NAME = 'urlscan.io';
export const URLSCAN_API_ORIGIN = 'https://urlscan.io';

/** Only these GET paths may be called. POST /scan and all other endpoints are rejected. */
export const URLSCAN_ALLOWED_GET_PATHS = Object.freeze([
  '/api/v1/search',
  '/api/v1/quotas',
  // Result detail: /api/v1/result/{uuid}/
  '/api/v1/result/'
]);

export const URLSCAN_RESULT_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Evidence assessments — provider observations, not TalonHound IOC verdicts. */
export const URLSCAN_ASSESSMENT = Object.freeze({
  MALICIOUS_EVIDENCE: 'malicious_evidence',
  NO_MALICIOUS_EVIDENCE: 'no_malicious_evidence',
  NO_RESULTS: 'no_results',
  INSUFFICIENT_EVIDENCE: 'insufficient_evidence',
  PRIVACY_RESTRICTED: 'privacy_restricted',
  ERROR: 'error',
  RATE_LIMITED: 'rate_limited',
  NOT_CONFIGURED: 'not_configured',
  DISABLED: 'disabled',
  UNSUPPORTED: 'unsupported'
});

export const URLSCAN_MATCH_RELATION = Object.freeze({
  EXACT_URL: 'exact_url',
  CANONICAL_URL: 'canonical_url',
  PAGE_HOSTNAME: 'page_hostname',
  TASK_HOSTNAME: 'task_hostname',
  PAGE_APEX: 'page_apex',
  SUBDOMAIN_OF_IOC: 'subdomain_of_ioc',
  IOC_SUBDOMAIN_OF_PAGE: 'ioc_subdomain_of_page',
  CONTACTED_DOMAIN: 'contacted_domain',
  PRIMARY_PAGE_IP: 'primary_page_ip',
  CONTACTED_IP: 'contacted_ip',
  RELATED: 'related'
});

const ES_RESERVED_RE = /[+\-=&|><!(){}[\]^"~*?:\\/]/g;

const SENSITIVE_QUERY_PARAM_RE =
  /^(api[_-]?key|apikey|key|token|access[_-]?token|auth[_-]?token|auth|authorization|secret|client[_-]?secret|password|passwd|pwd|session|sessionid|sid|jwt|bearer|sig|signature|x-amz-signature|x-amz-credential|x-amz-security-token|sas|st|se|sp|sv|sr)$/i;

const DEFAULT_SEARCH_SIZE = 20;
const MAX_SEARCH_SIZE = 50;
const DEFAULT_DETAIL_LIMIT = 3;
const MAX_DETAIL_LIMIT = 5;
const DEFAULT_LOOKBACK_DAYS = 30;
const MAX_LOOKBACK_DAYS = 90;
const DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_RAW_STORE_BYTES = 64 * 1024;

let cachedAppVersion = null;

export function getTalonHoundVersion() {
  if (cachedAppVersion) return cachedAppVersion;
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, '../package.json'), 'utf8'));
    cachedAppVersion = String(pkg.version || '1.0.0');
  } catch {
    cachedAppVersion = '1.0.0';
  }
  return cachedAppVersion;
}

export function urlscanUserAgent() {
  return `TalonHound/${getTalonHoundVersion()} (+urlscan-passive-enrichment; read-only)`;
}

export function maskApiKey(key) {
  const s = String(key || '').trim();
  if (!s) return null;
  if (s.length <= 4) return '****';
  return `${s.slice(0, 4)}${'*'.repeat(Math.max(8, s.length - 4))}`;
}

/** Escape Elasticsearch query-string reserved characters for safe interpolation. */
export function escapeElasticsearchQueryString(value) {
  return String(value ?? '').replace(ES_RESERVED_RE, '\\$&');
}

/**
 * Quote a value for a keyword term query. Escapes backslash and double-quote
 * inside the quoted literal (Elasticsearch query-string rules).
 */
export function quoteKeywordTerm(value) {
  const s = String(value ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  return `"${s}"`;
}

/**
 * Canonicalize a URL for exact-match comparison without stripping
 * security-relevant path/query distinctions.
 * - Lowercase scheme and host
 * - Drop default ports
 * - Decode safely once where possible
 * - Preserve path, query order, and fragment absence (fragments ignored for match)
 * - Do NOT strip query params
 */
export function canonicalizeUrlForMatch(raw) {
  const input = String(raw || '').trim();
  if (!input) return null;
  let u;
  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
    u = new URL(hasScheme ? input : `https://${input}`);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

  const protocol = u.protocol.toLowerCase();
  let hostname = u.hostname.toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1);
  }

  const isDefaultPort =
    (protocol === 'http:' && (u.port === '' || u.port === '80'))
    || (protocol === 'https:' && (u.port === '' || u.port === '443'));
  const portPart = isDefaultPort || !u.port ? '' : `:${u.port}`;

  let pathname = u.pathname || '/';
  try {
    pathname = decodeURIComponent(pathname);
  } catch {
    /* keep encoded */
  }
  // Normalize empty path to /
  if (!pathname) pathname = '/';

  // Preserve query string as-is (decoded comparison of pairs would lose distinctions);
  // compare using URL.search which keeps order.
  const search = u.search || '';

  return `${protocol}//${hostname}${portPart}${pathname}${search}`;
}

export function urlsMatchExactly(a, b) {
  const ca = canonicalizeUrlForMatch(a);
  const cb = canonicalizeUrlForMatch(b);
  if (!ca || !cb) return false;
  return ca === cb;
}

/**
 * Detect URLs that should not be sent to urlscan search because looking them
 * up would disclose credentials or session material. Does not strip components
 * and claim an exact match — skips with an explicit privacy reason instead.
 */
export function assessUrlPrivacyForLookup(rawUrl) {
  const raw = String(rawUrl || '').trim();
  if (!raw) return { ok: false, reason: 'empty' };
  let u;
  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
    u = new URL(hasScheme ? raw : `https://${raw}`);
  } catch {
    return { ok: false, reason: 'invalid_url' };
  }
  if (u.username || u.password) {
    return { ok: false, reason: 'url_userinfo', message: 'URL contains credentials; urlscan lookup skipped for privacy' };
  }
  for (const key of u.searchParams.keys()) {
    if (SENSITIVE_QUERY_PARAM_RE.test(key)) {
      return {
        ok: false,
        reason: 'sensitive_query_param',
        message: 'URL contains sensitive query parameters; urlscan lookup skipped for privacy'
      };
    }
  }
  // Heuristic: long opaque tokens in path segments (e.g. JWT-like session ids).
  // Do not flag ordinary filenames (login.html, app.js) — only high-entropy opaque segments.
  const pathParts = u.pathname.split('/').filter(Boolean);
  for (const part of pathParts) {
    if (part.includes('.')) continue;
    if (part.length >= 40 && /^[A-Za-z0-9_-]+$/.test(part)) {
      const upper = (part.match(/[A-Z]/g) || []).length;
      const lower = (part.match(/[a-z]/g) || []).length;
      const digits = (part.match(/[0-9]/g) || []).length;
      if (upper >= 4 && lower >= 4 && digits >= 4) {
        return {
          ok: false,
          reason: 'sensitive_path_token',
          message: 'URL path appears to contain a session or access token; urlscan lookup skipped for privacy'
        };
      }
    }
  }
  return { ok: true };
}

export function isSupportedUrlscanIocType(observableType) {
  const t = String(observableType || '').trim().toLowerCase();
  if (t === 'url') return 'url';
  if (t === 'domain' || t === 'hostname') return 'domain';
  if (t === 'ip' || t === 'ipv4' || t === 'ipv6' || t === 'ip6') return 'ip';
  return null;
}

export function normalizeHostname(value) {
  let h = String(value || '').trim().toLowerCase();
  if (!h) return '';
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  // Strip trailing port for host:port forms (not IPv6)
  if (h.includes(':') && !h.includes('::') && /^[\w.-]+:\d+$/.test(h)) {
    h = h.split(':')[0];
  }
  return h;
}

export function isSubdomainOf(host, parent) {
  const h = normalizeHostname(host);
  const p = normalizeHostname(parent);
  if (!h || !p || h === p) return false;
  return h.endsWith(`.${p}`);
}

/**
 * Build a bounded Search API query for the IOC. Never interpolates unescaped input.
 */
export function buildUrlscanSearchQuery(iocType, observable, { lookbackDays = DEFAULT_LOOKBACK_DAYS } = {}) {
  const category = isSupportedUrlscanIocType(iocType);
  if (!category) {
    return { ok: false, reason: 'unsupported_type' };
  }

  const days = Math.min(MAX_LOOKBACK_DAYS, Math.max(1, Number(lookbackDays) || DEFAULT_LOOKBACK_DAYS));
  const dateClause = `date:[now-${days}d TO now]`;

  if (category === 'url') {
    const privacy = assessUrlPrivacyForLookup(observable);
    if (!privacy.ok) {
      return { ok: false, reason: 'privacy_restricted', message: privacy.message, privacy_reason: privacy.reason };
    }
    const canonical = canonicalizeUrlForMatch(observable);
    if (!canonical) return { ok: false, reason: 'invalid_url' };
    const q = quoteKeywordTerm(canonical);
    // Prefer exact keyword / canonical URL fields — not broad substring text search.
    const query =
      `(page.url.keyword:${q} OR task.url.keyword:${q} OR canonical.page.url:${q} OR canonical.task.url:${q}) AND ${dateClause}`;
    return {
      ok: true,
      category: 'url',
      query,
      lookback_days: days,
      canonical_url: canonical
    };
  }

  if (category === 'domain') {
    const host = normalizeHostname(observable);
    if (!host || host.includes('/') || /\s/.test(host)) {
      return { ok: false, reason: 'invalid_domain' };
    }
    const q = quoteKeywordTerm(host);
    // Exact hostname on page/task; also retrieve contacted-domain hits for relationship labeling.
    const query =
      `(page.domain.keyword:${q} OR task.domain.keyword:${q} OR domain.keyword:${q}) AND ${dateClause}`;
    return {
      ok: true,
      category: 'domain',
      query,
      lookback_days: days,
      hostname: host
    };
  }

  // IP (v4 or v6)
  const ip = String(observable || '').trim();
  if (!ip) return { ok: false, reason: 'invalid_ip' };
  const q = quoteKeywordTerm(ip);
  const query = `(page.ip:${q} OR ip:${q}) AND ${dateClause}`;
  return {
    ok: true,
    category: 'ip',
    query,
    lookback_days: days,
    ip
  };
}

export function clampSearchSize(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return DEFAULT_SEARCH_SIZE;
  return Math.min(MAX_SEARCH_SIZE, Math.max(1, Math.round(v)));
}

export function clampDetailLimit(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return DEFAULT_DETAIL_LIMIT;
  return Math.min(MAX_DETAIL_LIMIT, Math.max(0, Math.round(v)));
}

export function clampLookbackDays(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return DEFAULT_LOOKBACK_DAYS;
  return Math.min(MAX_LOOKBACK_DAYS, Math.max(1, Math.round(v)));
}

/**
 * Validate that a URL is an allowed urlscan GET endpoint.
 * @returns {{ ok: true, url: URL, kind: 'search'|'result'|'quotas' } | { ok: false, reason: string }}
 */
export function validateUrlscanRequest(method, urlString) {
  const m = String(method || '').toUpperCase();
  if (m !== 'GET') {
    return { ok: false, reason: 'method_not_allowed', message: `urlscan provider forbids HTTP ${m}` };
  }
  let u;
  try {
    u = new URL(String(urlString || ''));
  } catch {
    return { ok: false, reason: 'invalid_url' };
  }
  if (u.protocol !== 'https:') {
    return { ok: false, reason: 'insecure_scheme' };
  }
  if (u.hostname !== 'urlscan.io') {
    return { ok: false, reason: 'host_not_allowed' };
  }
  // Reject scan submission path explicitly even if somehow presented as GET.
  if (u.pathname === '/api/v1/scan' || u.pathname.startsWith('/api/v1/scan/')) {
    return { ok: false, reason: 'scan_submission_forbidden' };
  }
  if (u.pathname === '/api/v1/search') {
    return { ok: true, url: u, kind: 'search' };
  }
  if (u.pathname === '/api/v1/quotas') {
    return { ok: true, url: u, kind: 'quotas' };
  }
  const resultMatch = u.pathname.match(/^\/api\/v1\/result\/([^/]+)\/?$/);
  if (resultMatch) {
    const id = resultMatch[1];
    if (!URLSCAN_RESULT_UUID_RE.test(id)) {
      return { ok: false, reason: 'invalid_scan_id' };
    }
    return { ok: true, url: u, kind: 'result', scanId: id };
  }
  return { ok: false, reason: 'path_not_allowed' };
}

/**
 * Allowlisted HTTPS GET client for urlscan.io.
 * Rejects POST/scan and any non-allowlisted destination before fetch is invoked.
 */
export async function urlscanAllowlistedFetch(urlString, {
  apiKey,
  timeoutMs = 12000,
  fetchImpl = fetch,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  redirect = 'manual',
  method = 'GET'
} = {}) {
  const validated = validateUrlscanRequest(method, urlString);
  if (!validated.ok) {
    const err = new Error(validated.message || `urlscan request rejected: ${validated.reason}`);
    err.code = 'request_rejected';
    err.reason = validated.reason;
    err.provider_status = 'failed';
    throw err;
  }
  if (!apiKey) {
    const err = new Error('urlscan.io API key is not configured');
    err.code = 'not_configured';
    err.provider_status = 'not_configured';
    throw err;
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Math.max(3000, Number(timeoutMs) || 12000));
  try {
    let currentUrl = validated.url.toString();
    let redirects = 0;
    let res;
    while (redirects < 3) {
      const hop = validateUrlscanRequest('GET', currentUrl);
      if (!hop.ok) {
        const err = new Error(`urlscan redirect rejected: ${hop.reason}`);
        err.code = 'redirect_rejected';
        err.provider_status = 'failed';
        throw err;
      }
      res = await fetchImpl(currentUrl, {
        method: 'GET',
        redirect,
        signal: ctrl.signal,
        headers: {
          'API-Key': apiKey,
          Accept: 'application/json',
          'User-Agent': urlscanUserAgent()
        }
      });
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const loc = res.headers.get('location');
        if (!loc) {
          const err = new Error('urlscan redirect missing Location');
          err.code = 'redirect_rejected';
          err.provider_status = 'failed';
          throw err;
        }
        currentUrl = new URL(loc, currentUrl).toString();
        redirects += 1;
        continue;
      }
      break;
    }

    const status = res.status;
    const rateHeaders = {
      scope: res.headers.get('x-rate-limit-scope'),
      action: res.headers.get('x-rate-limit-action'),
      window: res.headers.get('x-rate-limit-window'),
      limit: res.headers.get('x-rate-limit-limit'),
      remaining: res.headers.get('x-rate-limit-remaining'),
      reset: res.headers.get('x-rate-limit-reset'),
      resetAfter: res.headers.get('x-rate-limit-reset-after'),
      retryAfter: res.headers.get('retry-after')
    };

    if (!res.ok) {
      const mapped = urlscanHttpError(status);
      const err = new Error(mapped.message);
      err.code = mapped.code;
      err.provider_status = mapped.provider_status;
      err.status = status;
      err.rateHeaders = rateHeaders;
      if (rateHeaders.retryAfter) err.retryAfter = rateHeaders.retryAfter;
      else if (rateHeaders.resetAfter) err.retryAfter = rateHeaders.resetAfter;
      // Drain body without logging secrets
      try { await res.arrayBuffer(); } catch { /* ignore */ }
      throw err;
    }

    const buf = await readResponseBounded(res, maxResponseBytes);
    let json;
    try {
      json = JSON.parse(buf.toString('utf8'));
    } catch {
      const err = new Error('urlscan.io returned malformed JSON');
      err.code = 'malformed_response';
      err.provider_status = 'failed';
      throw err;
    }
    return { json, status, rateHeaders, kind: validated.kind };
  } catch (err) {
    if (err?.name === 'AbortError') {
      const timeoutErr = new Error('urlscan.io lookup timed out');
      timeoutErr.code = 'timeout';
      timeoutErr.provider_status = 'failed';
      throw timeoutErr;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function readResponseBounded(res, maxBytes) {
  if (typeof res.arrayBuffer === 'function') {
    const ab = await res.arrayBuffer();
    if (ab.byteLength > maxBytes) {
      const err = new Error('urlscan.io response exceeded size limit');
      err.code = 'response_too_large';
      err.provider_status = 'failed';
      throw err;
    }
    return Buffer.from(ab);
  }
  const text = await res.text();
  const buf = Buffer.from(text, 'utf8');
  if (buf.length > maxBytes) {
    const err = new Error('urlscan.io response exceeded size limit');
    err.code = 'response_too_large';
    err.provider_status = 'failed';
    throw err;
  }
  return buf;
}

export function urlscanHttpError(status) {
  const code = Number(status);
  if (code === 401 || code === 403) {
    return {
      provider_status: 'auth_error',
      code: 'auth',
      message: 'Invalid urlscan.io API key or unauthorized'
    };
  }
  if (code === 429) {
    return {
      provider_status: 'rate_limited',
      code: 'rate_limit',
      message: 'urlscan.io rate limit reached. Try again later.'
    };
  }
  if (code >= 500) {
    return {
      provider_status: 'provider_error',
      code: 'provider_error',
      message: 'urlscan.io service error. Try again later.'
    };
  }
  return {
    provider_status: 'failed',
    code: 'http_error',
    message: `urlscan.io lookup failed (${code})`
  };
}

export function buildUrlscanResultPageUrl(scanId) {
  if (!URLSCAN_RESULT_UUID_RE.test(String(scanId || ''))) return null;
  return `https://urlscan.io/result/${String(scanId).toLowerCase()}/`;
}

function pickHitFields(hit) {
  const src = hit?._source && typeof hit._source === 'object' ? hit._source : hit;
  const page = src?.page && typeof src.page === 'object' ? src.page : {};
  const task = src?.task && typeof src.task === 'object' ? src.task : {};
  const stats = src?.stats && typeof src.stats === 'object' ? src.stats : {};
  const verdicts = src?.verdicts && typeof src.verdicts === 'object' ? src.verdicts : null;
  const id = String(hit?._id || task.uuid || src?.uuid || '').trim();
  return { src, page, task, stats, verdicts, id };
}

/**
 * Classify how a search hit relates to the IOC under enrichment.
 */
export function classifyMatchRelation(category, observable, hit) {
  const { page, task, src, id } = pickHitFields(hit);
  const pageUrl = page.url || null;
  const taskUrl = task.url || null;
  const pageDomain = normalizeHostname(page.domain);
  const taskDomain = normalizeHostname(task.domain);
  const pageIp = String(page.ip || '').trim();
  const pageApex = normalizeHostname(page.apexDomain || '');

  if (category === 'url') {
    const canonical = canonicalizeUrlForMatch(observable);
    if (canonical && (urlsMatchExactly(pageUrl, observable) || urlsMatchExactly(taskUrl, observable))) {
      return {
        relation: URLSCAN_MATCH_RELATION.EXACT_URL,
        exact_match: true,
        scan_id: id
      };
    }
    // Canonical keyword match may hit after urlscan's own canonicalization
    if (canonical && pageUrl && canonicalizeUrlForMatch(pageUrl) === canonical) {
      return { relation: URLSCAN_MATCH_RELATION.CANONICAL_URL, exact_match: true, scan_id: id };
    }
    return { relation: URLSCAN_MATCH_RELATION.RELATED, exact_match: false, scan_id: id };
  }

  if (category === 'domain') {
    const host = normalizeHostname(observable);
    if (pageDomain && pageDomain === host) {
      return { relation: URLSCAN_MATCH_RELATION.PAGE_HOSTNAME, exact_match: true, scan_id: id };
    }
    if (taskDomain && taskDomain === host) {
      return { relation: URLSCAN_MATCH_RELATION.TASK_HOSTNAME, exact_match: true, scan_id: id };
    }
    if (pageApex && pageApex === host) {
      return { relation: URLSCAN_MATCH_RELATION.PAGE_APEX, exact_match: false, scan_id: id };
    }
    if (pageDomain && isSubdomainOf(pageDomain, host)) {
      return { relation: URLSCAN_MATCH_RELATION.SUBDOMAIN_OF_IOC, exact_match: false, scan_id: id };
    }
    if (pageDomain && isSubdomainOf(host, pageDomain)) {
      return { relation: URLSCAN_MATCH_RELATION.IOC_SUBDOMAIN_OF_PAGE, exact_match: false, scan_id: id };
    }
    // Present because domain.keyword matched as a contacted resource
    const lists = src?.lists && typeof src.lists === 'object' ? src.lists : {};
    const domains = Array.isArray(lists.domains) ? lists.domains.map(normalizeHostname) : [];
    if (domains.includes(host) || (pageDomain && pageDomain !== host)) {
      return { relation: URLSCAN_MATCH_RELATION.CONTACTED_DOMAIN, exact_match: false, scan_id: id };
    }
    return { relation: URLSCAN_MATCH_RELATION.RELATED, exact_match: false, scan_id: id };
  }

  // IP
  const ip = String(observable || '').trim();
  if (pageIp && pageIp === ip) {
    return { relation: URLSCAN_MATCH_RELATION.PRIMARY_PAGE_IP, exact_match: true, scan_id: id };
  }
  return { relation: URLSCAN_MATCH_RELATION.CONTACTED_IP, exact_match: false, scan_id: id };
}

function verdictMaliciousFlag(verdicts) {
  if (!verdicts || typeof verdicts !== 'object') return null;
  if (verdicts.malicious === true) return true;
  if (verdicts.urlscan?.malicious === true) return true;
  if (verdicts.engines?.malicious === true) return true;
  if (verdicts.community?.malicious === true) return true;
  if (verdicts.malicious === false
    && verdicts.urlscan?.malicious !== true
    && verdicts.engines?.malicious !== true
    && verdicts.community?.malicious !== true) {
    return false;
  }
  return null;
}

function extractScore(verdicts) {
  if (!verdicts || typeof verdicts !== 'object') return null;
  const s = verdicts.score ?? verdicts.urlscan?.score ?? verdicts.engines?.score;
  if (s === null || s === undefined || !Number.isFinite(Number(s))) return null;
  return Math.round(Number(s));
}

function extractCategories(verdicts) {
  const cats = verdicts?.urlscan?.categories || verdicts?.categories;
  if (!Array.isArray(cats)) return [];
  return cats.map((c) => String(c).trim()).filter(Boolean).slice(0, 20);
}

/**
 * Normalize a search API hit into a compact scan summary (no raw page content).
 */
export function normalizeSearchHit(hit, category, observable) {
  const { page, task, stats, verdicts, id } = pickHitFields(hit);
  if (!id || !URLSCAN_RESULT_UUID_RE.test(id)) return null;
  const relation = classifyMatchRelation(category, observable, hit);
  const malicious = verdictMaliciousFlag(verdicts);
  const score = extractScore(verdicts);
  const scannedAt = task.time || hit?.sort?.[0] || null;
  return {
    scan_id: id.toLowerCase(),
    scanned_at: scannedAt ? String(scannedAt) : null,
    result_url: buildUrlscanResultPageUrl(id),
    task_url: task.url ? String(task.url).slice(0, 2048) : null,
    page_url: page.url ? String(page.url).slice(0, 2048) : null,
    visibility: task.visibility ? String(task.visibility) : null,
    page_domain: page.domain ? normalizeHostname(page.domain) : null,
    page_ip: page.ip ? String(page.ip) : null,
    page_asn: page.asn ? String(page.asn) : null,
    page_country: page.country ? String(page.country).toUpperCase() : null,
    page_server: page.server ? String(page.server).slice(0, 200) : null,
    page_title: page.title ? String(page.title).slice(0, 300) : null,
    page_redirected: page.redirected ? String(page.redirected) : null,
    match_relation: relation.relation,
    exact_match: relation.exact_match === true,
    malicious,
    urlscan_score: score,
    categories: extractCategories(verdicts),
    // Score is urlscan's scale (-100..100), NOT TalonHound confidence.
    score_is_not_confidence: true,
    stats_requests: Number.isFinite(Number(stats.requests)) ? Number(stats.requests) : null
  };
}

/**
 * Select a bounded set of scan IDs for Result API detail fetch.
 * Prefer exact matches, then primary-page relationships, then recency.
 * Never select solely by highest malicious score.
 */
export function selectDetailCandidates(normalizedHits, limit = DEFAULT_DETAIL_LIMIT) {
  const n = clampDetailLimit(limit);
  if (n <= 0 || !Array.isArray(normalizedHits)) return [];

  const scored = normalizedHits
    .filter((h) => h?.scan_id && URLSCAN_RESULT_UUID_RE.test(h.scan_id))
    .map((h, idx) => {
      let rank = 0;
      if (h.exact_match) rank += 1000;
      if ([
        URLSCAN_MATCH_RELATION.EXACT_URL,
        URLSCAN_MATCH_RELATION.CANONICAL_URL,
        URLSCAN_MATCH_RELATION.PAGE_HOSTNAME,
        URLSCAN_MATCH_RELATION.PRIMARY_PAGE_IP
      ].includes(h.match_relation)) rank += 500;
      if ([
        URLSCAN_MATCH_RELATION.TASK_HOSTNAME,
        URLSCAN_MATCH_RELATION.PAGE_APEX
      ].includes(h.match_relation)) rank += 200;
      // Slight preference for having verdict data, not for high score alone
      if (h.malicious !== null) rank += 50;
      if (h.malicious === true) rank += 10;
      const ts = h.scanned_at ? Date.parse(h.scanned_at) : 0;
      return { h, rank, ts, idx };
    });

  scored.sort((a, b) => b.rank - a.rank || b.ts - a.ts || a.idx - b.idx);

  const seen = new Set();
  const out = [];
  for (const item of scored) {
    if (seen.has(item.h.scan_id)) continue;
    seen.add(item.h.scan_id);
    out.push(item.h.scan_id);
    if (out.length >= n) break;
  }
  return out;
}

/**
 * Extract safe detail fields from Result API JSON (no cookies/DOM/bodies).
 */
export function normalizeResultDetail(raw, scanId) {
  if (!raw || typeof raw !== 'object') return null;
  const task = raw.task && typeof raw.task === 'object' ? raw.task : {};
  const page = raw.page && typeof raw.page === 'object' ? raw.page : {};
  const verdicts = raw.verdicts && typeof raw.verdicts === 'object' ? raw.verdicts : {};
  const lists = raw.lists && typeof raw.lists === 'object' ? raw.lists : {};
  const id = String(task.uuid || scanId || '').toLowerCase();
  if (!URLSCAN_RESULT_UUID_RE.test(id)) return null;

  const engineVerdicts = Array.isArray(verdicts.engines?.verdicts)
    ? verdicts.engines.verdicts.slice(0, 10).map((v) => ({
      engine: v?.engine ? String(v.engine).slice(0, 80) : null,
      malicious: v?.malicious === true,
      categories: Array.isArray(v?.categories) ? v.categories.map(String).slice(0, 10) : []
    }))
    : [];

  return {
    scan_id: id,
    result_url: buildUrlscanResultPageUrl(id),
    scanned_at: task.time ? String(task.time) : null,
    visibility: task.visibility ? String(task.visibility) : null,
    task_url: task.url ? String(task.url).slice(0, 2048) : null,
    page_url: page.url ? String(page.url).slice(0, 2048) : null,
    page_domain: page.domain ? normalizeHostname(page.domain) : null,
    page_ip: page.ip ? String(page.ip) : null,
    page_asn: page.asn ? String(page.asn) : null,
    page_asnname: page.asnname ? String(page.asnname).slice(0, 200) : null,
    page_country: page.country ? String(page.country).toUpperCase() : null,
    page_city: page.city ? String(page.city).slice(0, 120) : null,
    page_server: page.server ? String(page.server).slice(0, 200) : null,
    page_title: page.title ? String(page.title).slice(0, 300) : null,
    page_status: page.status != null ? String(page.status) : null,
    page_redirected: page.redirected ? String(page.redirected) : null,
    urlscan_malicious: verdicts.urlscan?.malicious === true,
    engines_malicious: verdicts.engines?.malicious === true,
    community_malicious: verdicts.community?.malicious === true,
    overall_malicious: verdicts.malicious === true,
    urlscan_score: extractScore(verdicts),
    score_is_not_confidence: true,
    categories: extractCategories(verdicts),
    engine_verdicts: engineVerdicts,
    contacted_ips_sample: Array.isArray(lists.ips)
      ? lists.ips.map(String).slice(0, 15)
      : [],
    contacted_domains_sample: Array.isArray(lists.domains)
      ? lists.domains.map(String).slice(0, 15)
      : []
  };
}

/**
 * Build the normalized enrichment summary stored in ioc_enrichments.
 */
export function buildUrlscanNormalizedSummary({
  category,
  observable,
  searchMeta,
  hits,
  details,
  fetchedAt,
  assessment,
  lookbackDays,
  searchSize
}) {
  const normalizedHits = (hits || []).filter(Boolean);
  const exactMatches = normalizedHits.filter((h) => h.exact_match);
  const relatedMatches = normalizedHits.filter((h) => !h.exact_match);
  const maliciousHits = normalizedHits.filter((h) => h.malicious === true);
  const timestamps = normalizedHits
    .map((h) => (h.scanned_at ? Date.parse(h.scanned_at) : NaN))
    .filter(Number.isFinite)
    .sort((a, b) => a - b);

  const firstObserved = timestamps.length ? new Date(timestamps[0]).toISOString() : null;
  const lastObserved = timestamps.length ? new Date(timestamps[timestamps.length - 1]).toISOString() : null;
  const latestMalicious = maliciousHits
    .map((h) => ({ h, t: h.scanned_at ? Date.parse(h.scanned_at) : 0 }))
    .sort((a, b) => b.t - a.t)[0]?.h || null;

  const apiTotal = searchMeta?.total;
  const totalReported = Number.isFinite(Number(apiTotal)) ? Number(apiTotal) : normalizedHits.length;
  const bounded = totalReported > normalizedHits.length || searchMeta?.has_more === true;

  const assessmentLabel = assessmentDisplayLabel(assessment);

  return {
    provider: URLSCAN_PROVIDER,
    provider_display_name: URLSCAN_DISPLAY_NAME,
    evidence_assessment: assessment,
    evidence_assessment_label: assessmentLabel,
    // Explicit: absence of results is not a clean/benign verdict.
    is_authoritative_verdict: false,
    score_is_not_confidence: true,
    ioc_category: category,
    lookback_days: lookbackDays,
    search_size_requested: searchSize,
    matches_retrieved: normalizedHits.length,
    matches_retrieved_label: bounded ? 'Matches retrieved (bounded sample)' : 'Matches retrieved',
    total_reported_by_api: totalReported,
    results_are_exhaustive: !bounded && assessment !== URLSCAN_ASSESSMENT.NO_RESULTS,
    exact_match_count: exactMatches.length,
    related_match_count: relatedMatches.length,
    malicious_scan_count: maliciousHits.length,
    first_observed_scan: firstObserved,
    last_observed_scan: lastObserved,
    most_recent_scan: normalizedHits[0] || null,
    most_recent_malicious_scan: latestMalicious,
    scans: normalizedHits.slice(0, searchSize),
    detail_scans: (details || []).filter(Boolean).slice(0, MAX_DETAIL_LIMIT),
    fetched_at: fetchedAt || new Date().toISOString(),
    search_date_limit_days: searchMeta?.search_date_limit_days ?? null
  };
}

export function assessmentDisplayLabel(assessment) {
  switch (assessment) {
    case URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE:
      return 'Malicious evidence observed';
    case URLSCAN_ASSESSMENT.NO_MALICIOUS_EVIDENCE:
      return 'No malicious evidence observed';
    case URLSCAN_ASSESSMENT.NO_RESULTS:
      return 'No results';
    case URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE:
      return 'Insufficient evidence';
    case URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED:
      return 'Privacy-restricted query';
    case URLSCAN_ASSESSMENT.RATE_LIMITED:
      return 'Rate limited';
    case URLSCAN_ASSESSMENT.NOT_CONFIGURED:
      return 'Not configured';
    case URLSCAN_ASSESSMENT.DISABLED:
      return 'Disabled';
    case URLSCAN_ASSESSMENT.UNSUPPORTED:
      return 'Unsupported IOC type';
    case URLSCAN_ASSESSMENT.ERROR:
      return 'Analysis error';
    default:
      return 'Unknown';
  }
}

/**
 * Derive provider evidence assessment from normalized hits.
 * Related malicious contacted resources do NOT alone force malicious_evidence
 * for an IP/domain unless there is an exact/primary match that is malicious,
 * or a clear exact-URL malicious scan.
 */
export function deriveEvidenceAssessment(category, normalizedHits) {
  if (!Array.isArray(normalizedHits) || normalizedHits.length === 0) {
    return URLSCAN_ASSESSMENT.NO_RESULTS;
  }

  const exactMalicious = normalizedHits.some((h) => h.exact_match && h.malicious === true);
  if (exactMalicious) return URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE;

  if (category === 'ip') {
    // Primary page IP with malicious verdict is stronger than contacted-only.
    const primaryMalicious = normalizedHits.some(
      (h) => h.match_relation === URLSCAN_MATCH_RELATION.PRIMARY_PAGE_IP && h.malicious === true
    );
    if (primaryMalicious) return URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE;
    // Contacted-only malicious scans are related evidence — not authoritative for the IP.
    const contactedMalicious = normalizedHits.some(
      (h) => h.match_relation === URLSCAN_MATCH_RELATION.CONTACTED_IP && h.malicious === true
    );
    if (contactedMalicious) return URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE;
  }

  if (category === 'domain') {
    const pageHostMalicious = normalizedHits.some(
      (h) => (
        h.match_relation === URLSCAN_MATCH_RELATION.PAGE_HOSTNAME
        || h.match_relation === URLSCAN_MATCH_RELATION.TASK_HOSTNAME
      ) && h.malicious === true
    );
    if (pageHostMalicious) return URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE;
    const relatedMalicious = normalizedHits.some(
      (h) => !h.exact_match && h.malicious === true
    );
    if (relatedMalicious) return URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE;
  }

  if (category === 'url') {
    const anyMalicious = normalizedHits.some((h) => h.malicious === true);
    if (anyMalicious) {
      // Prefer exact; if only related URL hits are malicious, mark insufficient.
      return exactMalicious
        ? URLSCAN_ASSESSMENT.MALICIOUS_EVIDENCE
        : URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE;
    }
  }

  const anyMalicious = normalizedHits.some((h) => h.malicious === true);
  if (anyMalicious) return URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE;

  const hasVerdict = normalizedHits.some((h) => h.malicious === false || h.malicious === true);
  if (!hasVerdict) return URLSCAN_ASSESSMENT.INSUFFICIENT_EVIDENCE;

  return URLSCAN_ASSESSMENT.NO_MALICIOUS_EVIDENCE;
}

/** Map assessment + store status for ioc_enrichments.status */
export function storeStatusForAssessment(assessment) {
  if (assessment === URLSCAN_ASSESSMENT.NO_RESULTS) return 'not_found';
  if (assessment === URLSCAN_ASSESSMENT.PRIVACY_RESTRICTED) return 'skipped';
  if (assessment === URLSCAN_ASSESSMENT.RATE_LIMITED) return 'rate_limited';
  if (assessment === URLSCAN_ASSESSMENT.NOT_CONFIGURED) return 'api_key_missing';
  if (assessment === URLSCAN_ASSESSMENT.ERROR) return 'error';
  if (assessment === URLSCAN_ASSESSMENT.UNSUPPORTED) return 'unsupported';
  return 'success';
}

/**
 * Compact raw payload for optional storage — search totals + selected detail
 * identifiers only. Never store cookies, DOM, response bodies, or credentials.
 */
export function buildCompactRawResponse({ searchMeta, scanIds, detailIds }) {
  const payload = {
    search: {
      total: searchMeta?.total ?? null,
      took: searchMeta?.took ?? null,
      has_more: searchMeta?.has_more ?? false,
      search_date_limit_days: searchMeta?.search_date_limit_days ?? null
    },
    scan_ids: (scanIds || []).slice(0, MAX_SEARCH_SIZE),
    detail_ids: (detailIds || []).slice(0, MAX_DETAIL_LIMIT)
  };
  const json = JSON.stringify(payload);
  if (json.length > MAX_RAW_STORE_BYTES) {
    return { search: payload.search, scan_ids: payload.scan_ids.slice(0, 10), detail_ids: payload.detail_ids };
  }
  return payload;
}

export function fingerprintQuery(query) {
  return createHash('sha256').update(String(query || '')).digest('hex').slice(0, 16);
}

export {
  DEFAULT_SEARCH_SIZE,
  MAX_SEARCH_SIZE,
  DEFAULT_DETAIL_LIMIT,
  MAX_DETAIL_LIMIT,
  DEFAULT_LOOKBACK_DAYS,
  MAX_LOOKBACK_DAYS,
  DEFAULT_MAX_RESPONSE_BYTES
};
