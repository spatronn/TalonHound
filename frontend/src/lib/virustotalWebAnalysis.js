/**
 * UI helpers for VirusTotal URL Web Analysis (provider-independent summary shape).
 * Pure — no React. Unit-testable with `node --test`.
 */

export const WEB_ANALYSIS_UI_OUTGOING_PREVIEW = 5;

/** HTTP status → short reason phrase (common codes only). */
const HTTP_STATUS_TEXT = Object.freeze({
  200: 'OK',
  201: 'Created',
  204: 'No Content',
  301: 'Moved Permanently',
  302: 'Found',
  303: 'See Other',
  307: 'Temporary Redirect',
  308: 'Permanent Redirect',
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  500: 'Internal Server Error',
  502: 'Bad Gateway',
  503: 'Service Unavailable'
});

/**
 * @param {any} wa
 * @returns {boolean}
 */
export function hasUsefulWebAnalysis(wa) {
  if (!wa || typeof wa !== 'object') return false;
  if (wa.targeted_brand?.value) return true;
  if (Array.isArray(wa.behavior_tags) && wa.behavior_tags.length) return true;
  if (wa.content_sha256) return true;
  if (wa.times_submitted != null) return true;
  if (Array.isArray(wa.categories) && wa.categories.length) return true;
  if (wa.redirection_chain?.total_count > 0) return true;
  if (Array.isArray(wa.redirection_chain) && wa.redirection_chain.length) return true;
  if (wa.outgoing_links?.total_count > 0) return true;
  const http = wa.http;
  if (http && typeof http === 'object') {
    if (http.status_code != null) return true;
    if (http.server) return true;
    if (http.content_length != null) return true;
  }
  return false;
}

/** password-input → Password Input */
export function formatBehaviorTagLabel(tag) {
  return String(tag || '')
    .split(/[-_]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');
}

/** Shorten SHA-256 for display; full value remains available for copy/tooltip. */
export function shortenContentSha256(hash, head = 8, tail = 8) {
  const s = String(hash || '').trim().toLowerCase();
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

export function formatHttpStatusLabel(code) {
  if (code == null || !Number.isFinite(Number(code))) return null;
  const n = Number(code);
  const phrase = HTTP_STATUS_TEXT[n];
  return phrase ? `${n} ${phrase}` : String(n);
}

export function formatContentLengthLabel(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return null;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Normalize redirection_chain whether stored as bounded object or plain array.
 * @param {any} chain
 * @returns {{ items: string[], total_count: number, truncated: boolean }}
 */
export function normalizeRedirectChainView(chain) {
  if (Array.isArray(chain)) {
    return { items: chain.filter(Boolean).map(String), total_count: chain.length, truncated: false };
  }
  if (chain && typeof chain === 'object') {
    const items = Array.isArray(chain.items) ? chain.items.map(String) : [];
    const total_count = Number.isFinite(Number(chain.total_count)) ? Number(chain.total_count) : items.length;
    return { items, total_count, truncated: Boolean(chain.truncated) };
  }
  return { items: [], total_count: 0, truncated: false };
}

/**
 * @param {any} outgoing
 * @param {number} [previewLimit]
 */
export function normalizeOutgoingLinksView(outgoing, previewLimit = WEB_ANALYSIS_UI_OUTGOING_PREVIEW) {
  const limit = Math.max(0, Number(previewLimit) || 0);
  let items = [];
  let total_count = 0;
  let truncated = false;
  if (Array.isArray(outgoing)) {
    items = outgoing.filter(Boolean).map(String);
    total_count = items.length;
    truncated = total_count > limit;
  } else if (outgoing && typeof outgoing === 'object') {
    items = Array.isArray(outgoing.items) ? outgoing.items.map(String) : [];
    total_count = Number.isFinite(Number(outgoing.total_count)) ? Number(outgoing.total_count) : items.length;
    truncated = Boolean(outgoing.truncated) || total_count > limit;
  }
  const preview = items.slice(0, limit);
  const remaining = Math.max(0, total_count - preview.length);
  return { preview, total_count, remaining, truncated: truncated || remaining > 0 };
}

/** Compact display host/path for redirect chain rows. */
export function compactUrlForDisplay(url, maxLen = 72) {
  const s = String(url || '').trim();
  if (!s) return '';
  try {
    const u = new URL(s);
    const path = `${u.pathname || ''}${u.search || ''}`;
    const shown = `${u.host}${path}`;
    if (shown.length <= maxLen) return shown;
    return `${shown.slice(0, maxLen - 1)}…`;
  } catch {
    if (s.length <= maxLen) return s;
    return `${s.slice(0, maxLen - 1)}…`;
  }
}

/**
 * Untrusted Web Analysis URL rows (redirect chain / outgoing links) must NEVER
 * be rendered as navigable anchors. Analysts need readable, selectable text —
 * not accidental browser navigation to phishing/payload URLs.
 *
 * @param {string} url
 * @param {{ maxLen?: number }} [opts]
 * @returns {{
 *   element: 'span',
 *   text: string,
 *   title: string,
 *   href: null,
 *   onClick: null,
 *   role: null,
 *   tabIndex: null,
 *   style: Record<string, string|number>
 * }}
 */
export function webAnalysisUntrustedUrlDisplay(url, { maxLen = 72 } = {}) {
  const full = String(url ?? '').trim();
  return {
    element: 'span',
    text: compactUrlForDisplay(full, maxLen),
    title: full,
    href: null,
    onClick: null,
    role: null,
    tabIndex: null,
    style: {
      color: '#cbd5e1',
      fontSize: 13,
      fontFamily: "'JetBrains Mono', monospace",
      overflowWrap: 'anywhere',
      wordBreak: 'break-word',
      cursor: 'text',
      userSelect: 'text',
      display: 'inline-block',
      maxWidth: '100%'
    }
  };
}

/** True when a Web Analysis URL display model is non-navigable (no href/click). */
export function isNonNavigableWebAnalysisUrlDisplay(model) {
  if (!model || typeof model !== 'object') return false;
  return model.element === 'span'
    && model.href == null
    && model.onClick == null
    && model.role !== 'link'
    && model.tabIndex == null;
}
