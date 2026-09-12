/**
 * Extract provider-independent web_analysis from VirusTotal URL attributes.
 *
 * Allow-list only — never spreads raw VT attributes. Sensitive / unbounded
 * fields (cookies, javascript_variables, console_messages, full header dumps,
 * raw response blobs) are intentionally excluded.
 *
 * Pure — no DB, no HTTP. Unit-testable with `node --test`.
 */

/** @typedef {{ value: string, source: string|null }} TargetedBrand */
/** @typedef {{ status_code?: number|null, server?: string|null, content_length?: number|null }} WebHttp */
/** @typedef {{ items: string[], total_count: number, truncated: boolean }} BoundedStringList */
/** @typedef {{
 *   targeted_brand?: TargetedBrand|null,
 *   behavior_tags?: string[],
 *   http?: WebHttp,
 *   content_sha256?: string|null,
 *   redirection_chain?: BoundedStringList,
 *   outgoing_links?: BoundedStringList,
 *   times_submitted?: number|null,
 *   categories?: string[]
 * }} WebAnalysis */

export const WEB_ANALYSIS_LIMITS = Object.freeze({
  MAX_BEHAVIOR_TAGS: 40,
  MAX_REDIRECTION_CHAIN: 25,
  MAX_OUTGOING_LINKS: 20,
  MAX_CATEGORIES: 25,
  MAX_URL_CHARS: 2048,
  MAX_TAG_CHARS: 64,
  MAX_CATEGORY_CHARS: 64,
  MAX_BRAND_CHARS: 128,
  MAX_SERVER_CHARS: 256
});

const SHA256_RE = /^[a-f0-9]{64}$/;

function stripControlChars(str) {
  let out = '';
  for (const ch of str) {
    const code = ch.charCodeAt(0);
    if (code > 0x1f && code !== 0x7f) out += ch;
  }
  return out;
}

function sanitizeShortText(value, maxLen) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const s = stripControlChars(String(value)).trim();
  if (!s || s.length > maxLen) return null;
  return s;
}

function isUrlIocType(iocType) {
  return String(iocType || '').toLowerCase().trim() === 'url';
}

/**
 * True when web_analysis carries at least one useful field for UI/MCP.
 * @param {WebAnalysis|null|undefined} wa
 */
export function hasUsefulWebAnalysis(wa) {
  if (!wa || typeof wa !== 'object') return false;
  if (wa.targeted_brand?.value) return true;
  if (Array.isArray(wa.behavior_tags) && wa.behavior_tags.length) return true;
  if (wa.content_sha256) return true;
  if (wa.times_submitted != null) return true;
  if (Array.isArray(wa.categories) && wa.categories.length) return true;
  if (wa.redirection_chain?.total_count > 0) return true;
  if (wa.outgoing_links?.total_count > 0) return true;
  const http = wa.http;
  if (http && typeof http === 'object') {
    if (http.status_code != null) return true;
    if (http.server) return true;
    if (http.content_length != null) return true;
  }
  return false;
}

/**
 * @param {unknown} raw
 * @returns {TargetedBrand|null}
 */
export function normalizeTargetedBrand(raw) {
  if (raw == null) return null;
  if (typeof raw === 'string' || typeof raw === 'number') {
    const value = sanitizeShortText(raw, WEB_ANALYSIS_LIMITS.MAX_BRAND_CHARS);
    return value ? { value, source: null } : null;
  }
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;

  // VT shape: { "<engine>": "<brand>", ... }
  const entries = Object.entries(raw)
    .map(([source, brand]) => ({
      source: sanitizeShortText(source, WEB_ANALYSIS_LIMITS.MAX_BRAND_CHARS),
      value: sanitizeShortText(brand, WEB_ANALYSIS_LIMITS.MAX_BRAND_CHARS)
    }))
    .filter((e) => e.value)
    .sort((a, b) => String(a.source || '').localeCompare(String(b.source || '')));

  if (!entries.length) return null;
  const pick = entries[0];
  return { value: pick.value, source: pick.source || null };
}

/**
 * @param {unknown} tags
 * @returns {string[]}
 */
export function normalizeBehaviorTags(tags) {
  if (!Array.isArray(tags)) return [];
  const seen = new Set();
  const out = [];
  for (const raw of tags) {
    const s = sanitizeShortText(raw, WEB_ANALYSIS_LIMITS.MAX_TAG_CHARS);
    if (!s) continue;
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    // Preserve VT machine casing when already lowercase-ish; normalize to lowercase
    // for stable MCP keys while keeping hyphenated VT tags readable.
    out.push(key);
    if (out.length >= WEB_ANALYSIS_LIMITS.MAX_BEHAVIOR_TAGS) break;
  }
  return out;
}

/**
 * Ordered, deduped URL list with empty removal and length cap.
 * @param {unknown} list
 * @param {number} maxItems
 * @returns {BoundedStringList}
 */
export function normalizeBoundedUrlList(list, maxItems) {
  const max = Math.max(0, Number(maxItems) || 0);
  if (!Array.isArray(list)) {
    return { items: [], total_count: 0, truncated: false };
  }
  const seen = new Set();
  const cleaned = [];
  for (const raw of list) {
    const s = sanitizeShortText(raw, WEB_ANALYSIS_LIMITS.MAX_URL_CHARS);
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    cleaned.push(s);
  }
  const total_count = cleaned.length;
  const truncated = total_count > max;
  return {
    items: cleaned.slice(0, max),
    total_count,
    truncated
  };
}

/**
 * @param {unknown} value
 * @returns {string|null}
 */
export function normalizeContentSha256(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const s = String(value).trim().toLowerCase();
  return SHA256_RE.test(s) ? s : null;
}

/**
 * @param {unknown} headers
 * @returns {string|null}
 */
export function extractHttpServer(headers) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return null;
  for (const [key, value] of Object.entries(headers)) {
    if (String(key).toLowerCase() === 'server') {
      return sanitizeShortText(value, WEB_ANALYSIS_LIMITS.MAX_SERVER_CHARS);
    }
  }
  return null;
}

/**
 * Deduplicate vendor category values into a bounded string list.
 * @param {unknown} categories
 * @returns {string[]}
 */
export function normalizeWebCategories(categories) {
  if (!categories || typeof categories !== 'object') return [];
  const values = Array.isArray(categories)
    ? categories
    : Object.values(categories);
  const seen = new Set();
  const out = [];
  for (const raw of values) {
    const s = sanitizeShortText(raw, WEB_ANALYSIS_LIMITS.MAX_CATEGORY_CHARS);
    if (!s) continue;
    const key = s.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(key);
    if (out.length >= WEB_ANALYSIS_LIMITS.MAX_CATEGORIES) break;
  }
  return out;
}

function normalizeHttpBlock(attr) {
  const statusRaw = attr.last_http_response_code;
  const status_code = Number.isFinite(Number(statusRaw)) ? Number(statusRaw) : null;
  const lenRaw = attr.last_http_response_content_length;
  const content_length = Number.isFinite(Number(lenRaw)) && Number(lenRaw) >= 0
    ? Number(lenRaw)
    : null;
  const server = extractHttpServer(attr.last_http_response_headers);
  if (status_code == null && server == null && content_length == null) return undefined;
  return { status_code, server, content_length };
}

/**
 * Build web_analysis from VT attributes / raw response / existing summary.url block.
 * Returns null for non-URL IOCs or when nothing useful is present.
 *
 * @param {{
 *   iocType?: string|null,
 *   attributes?: object|null,
 *   rawResponse?: object|null,
 *   limits?: Partial<typeof WEB_ANALYSIS_LIMITS>
 * }} args
 * @returns {WebAnalysis|null}
 */
export function extractWebAnalysisFromVt({ iocType, attributes, rawResponse, limits } = {}) {
  if (!isUrlIocType(iocType)) return null;

  const attr = (attributes && typeof attributes === 'object')
    ? attributes
    : (rawResponse?.data?.attributes && typeof rawResponse.data.attributes === 'object'
      ? rawResponse.data.attributes
      : null);
  if (!attr) return null;

  const lim = { ...WEB_ANALYSIS_LIMITS, ...(limits || {}) };

  /** @type {WebAnalysis} */
  const wa = {};

  const brand = normalizeTargetedBrand(attr.targeted_brand);
  if (brand) wa.targeted_brand = brand;

  const tags = normalizeBehaviorTags(attr.tags);
  if (tags.length) wa.behavior_tags = tags;

  const http = normalizeHttpBlock(attr);
  if (http) wa.http = http;

  const sha = normalizeContentSha256(attr.last_http_response_content_sha256);
  if (sha) wa.content_sha256 = sha;

  const redirects = normalizeBoundedUrlList(attr.redirection_chain, lim.MAX_REDIRECTION_CHAIN);
  if (redirects.total_count > 0) wa.redirection_chain = redirects;

  const links = normalizeBoundedUrlList(attr.outgoing_links, lim.MAX_OUTGOING_LINKS);
  if (links.total_count > 0) wa.outgoing_links = links;

  if (Number.isFinite(Number(attr.times_submitted))) {
    wa.times_submitted = Number(attr.times_submitted);
  }

  const categories = normalizeWebCategories(attr.categories);
  if (categories.length) wa.categories = categories;

  return hasUsefulWebAnalysis(wa) ? wa : null;
}

/**
 * Attach / self-heal web_analysis on a normalized VT summary using optional raw.
 * Does not invent fields when neither summary nor raw carries URL web signals.
 *
 * @param {any} summary
 * @param {any} [rawResponse]
 * @returns {any}
 */
export function ensureVtWebAnalysis(summary, rawResponse = null) {
  if (!summary || typeof summary !== 'object') return summary;
  const iocType = summary.ioc_type;
  if (!isUrlIocType(iocType)) {
    if (summary.web_analysis != null) {
      const { web_analysis: _drop, ...rest } = summary;
      return rest;
    }
    return summary;
  }

  if (hasUsefulWebAnalysis(summary.web_analysis)) {
    return summary;
  }

  const derived = extractWebAnalysisFromVt({
    iocType,
    rawResponse,
    attributes: null
  });
  if (!derived) {
    if (summary.web_analysis == null) return summary;
    const { web_analysis: _drop, ...rest } = summary;
    return rest;
  }
  return { ...summary, web_analysis: derived };
}
