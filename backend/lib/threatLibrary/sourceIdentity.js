/**
 * Publisher source identity of a fetched Threat Library URL report — the
 * evidence that turns "two different URLs" into "one logical article".
 *
 * Pure: no network, no database. Input is what the worker already has after a
 * fetch (submitted URL, final URL after redirects, raw HTML); output is a set
 * of identity keys plus the evidence that supports each one, and the signals
 * that were looked at and REJECTED (with a reason) so an analyst can see why
 * two reports were or were not treated as the same article.
 *
 * Identity keys (stored in threat_report_identity_keys, unique per key):
 *   url:<canonical www-insensitive URL>       — see importIdentity.js
 *   wp:<bare host><site path>:<post id>       — WordPress post identity
 *
 * Evidence policy (publisher metadata is evidence, never an instruction):
 *   submitted   the URL the analyst imported. Always a key.
 *   redirect    the URL the server actually delivered after HTTP redirects.
 *               A key unless it is a site root (a removed article that
 *               redirects to the home page is not that home page).
 *   canonical / og_url / json_ld
 *               publisher-declared URLs of the page. Accepted only when
 *               same-site as the delivered document (www-insensitive host),
 *               not a site root, not an ancestor path of the document (a
 *               listing/category page), AND either equal to the submitted /
 *               delivered URL or corroborated by a second, independent signal
 *               kind. A lone, uncorroborated declaration is recorded and
 *               rejected — a single meta tag must not merge two reports.
 *   wp_post     WordPress core's REST alternate link
 *               (<link rel="alternate" type="application/json"
 *               href="<site>/wp-json/wp/v2/<type>/<id>">) and/or shortlink
 *               (<site>/?p=<id>), same-site only, post types only (no
 *               taxonomy/user/media routes). Disagreeing ids reject both.
 *               The site path is part of the key, so subdirectory multisites
 *               (example.com/de/…) never share a post-id space.
 *   hreflang    alternates are NOT keys. They are recorded so a translation
 *               can be linked when BOTH documents list each other (reciprocal
 *               hreflang); one-sided claims never merge.
 *
 * Titles, publication dates, IOC sets and content similarity are never
 * identity evidence here.
 */

import { canonicalizeReportUrl, urlKeyOfCanonical } from './importIdentity.js';

export const SOURCE_IDENTITY_VERSION = 'tl-source-identity-v1';

const MAX_SIGNALS_PER_KIND = 8;
const HEAD_SCAN_LIMIT = 400_000;
const NON_POST_WP_ROUTES = new Set([
  'categories', 'tags', 'users', 'comments', 'media', 'taxonomies', 'types', 'statuses',
  'settings', 'themes', 'plugins', 'search', 'block-types', 'blocks', 'menus', 'menu-items',
  'navigation', 'templates', 'template-parts', 'sidebars', 'widgets', 'widget-types'
]);
const ARTICLE_LIKE_TYPES = new Set([
  'article', 'newsarticle', 'blogposting', 'techarticle', 'scholarlyarticle', 'report',
  'analysisnewsarticle', 'reportagenewsarticle', 'webpage', 'itempage'
]);

function decodeAttr(v) {
  return String(v ?? '')
    .replace(/&amp;/gi, '&')
    .replace(/&#0*38;/g, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#0*39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#x2f;|&#0*47;/gi, '/')
    .trim();
}

/** @param {string} tag one `<link …>` / `<meta …>` start tag */
export function parseTagAttributes(tag) {
  const attrs = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
  let m;
  while ((m = re.exec(tag)) !== null) {
    const name = m[1].toLowerCase();
    if (!(name in attrs)) attrs[name] = decodeAttr(m[2] ?? m[3] ?? m[4] ?? '');
  }
  return attrs;
}

function headOf(html) {
  const s = String(html || '').slice(0, HEAD_SCAN_LIMIT);
  const end = s.search(/<\/head\s*>/i);
  return end >= 0 ? s.slice(0, end) : s;
}

function absolute(raw, base) {
  const v = String(raw || '').trim();
  if (!v) return null;
  try {
    const u = new URL(v, base || undefined);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}

function relTokens(rel) {
  return String(rel || '').toLowerCase().split(/\s+/).filter(Boolean);
}

function jsonLdNodes(html) {
  const out = [];
  const re = /<script\b[^>]*type\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi;
  const s = String(html || '');
  let m;
  while ((m = re.exec(s)) !== null) {
    const body = m[1].trim().replace(/^\s*<!--/, '').replace(/-->\s*$/, '').trim();
    if (!body) continue;
    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      continue;
    }
    const walk = (node, depth) => {
      if (!node || depth > 6) return;
      if (Array.isArray(node)) {
        for (const n of node) walk(n, depth + 1);
        return;
      }
      if (typeof node !== 'object') return;
      out.push(node);
      if (Array.isArray(node['@graph'])) walk(node['@graph'], depth + 1);
    };
    walk(parsed, 0);
  }
  return out;
}

function typesOf(node) {
  const t = node?.['@type'];
  return (Array.isArray(t) ? t : t ? [t] : []).map((x) => String(x).toLowerCase());
}

function idOf(v) {
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object' && typeof v['@id'] === 'string') return v['@id'];
  return null;
}

/**
 * Raw publisher identity signals of an HTML document (no validation).
 * @param {string} html
 * @param {string} baseUrl URL the document was delivered from (resolves relative hrefs)
 */
export function extractPublisherIdentitySignals(html, baseUrl) {
  const head = headOf(html);
  /** @type {{ canonical: string[], og_url: string[], json_ld: string[], wp_rest: string[], shortlink: string[], hreflang: { lang: string, url: string }[] }} */
  const signals = { canonical: [], og_url: [], json_ld: [], wp_rest: [], shortlink: [], hreflang: [] };
  const push = (list, value) => {
    if (value && !list.includes(value) && list.length < MAX_SIGNALS_PER_KIND) list.push(value);
  };
  for (const m of head.matchAll(/<link\b[^>]*>/gi)) {
    const a = parseTagAttributes(m[0]);
    const rels = relTokens(a.rel);
    const href = absolute(a.href, baseUrl);
    if (!href) continue;
    if (rels.includes('canonical')) push(signals.canonical, href);
    if (rels.includes('shortlink')) push(signals.shortlink, href);
    if (rels.includes('alternate')) {
      const type = String(a.type || '').toLowerCase();
      if (a.hreflang) {
        if (signals.hreflang.length < 32) signals.hreflang.push({ lang: String(a.hreflang).toLowerCase(), url: href });
      } else if (type === 'application/json' && /\/wp-json\/wp\/v2\//.test(href)) {
        push(signals.wp_rest, href);
      }
    }
  }
  for (const m of head.matchAll(/<meta\b[^>]*>/gi)) {
    const a = parseTagAttributes(m[0]);
    const prop = String(a.property || a.name || '').toLowerCase();
    if (prop === 'og:url') push(signals.og_url, absolute(a.content, baseUrl));
  }
  for (const node of jsonLdNodes(html)) {
    if (!typesOf(node).some((t) => ARTICLE_LIKE_TYPES.has(t))) continue;
    for (const v of [idOf(node['@id']), idOf(node.url), idOf(node.mainEntityOfPage)]) {
      const abs = absolute(v, baseUrl);
      // "#/schema/…" style @ids name graph nodes, not documents.
      if (abs && !/#./.test(String(v))) push(signals.json_ld, abs);
    }
  }
  return signals;
}

function bareHost(href) {
  try {
    const h = new URL(href).hostname.toLowerCase();
    return h.startsWith('www.') ? h.slice(4) : h;
  } catch {
    return null;
  }
}

function pathSegments(href) {
  try {
    return new URL(href).pathname.split('/').filter(Boolean);
  } catch {
    return [];
  }
}

function isRootPath(href) {
  try {
    const u = new URL(href);
    return pathSegments(href).length === 0 && !u.search;
  } catch {
    return true;
  }
}

/** `a` names a strict ancestor directory of `b` (listing / category of the document). */
function isAncestorPath(a, b) {
  const sa = pathSegments(a);
  const sb = pathSegments(b);
  if (sa.length >= sb.length) return false;
  try {
    if (new URL(a).search) return false;
  } catch {
    return false;
  }
  return sa.every((seg, i) => seg === sb[i]);
}

/**
 * `url:` identity key of a raw URL, or null.
 * @param {unknown} raw
 */
export function urlIdentityKey(raw) {
  const canonical = canonicalizeReportUrl(raw);
  return canonical ? urlKeyOfCanonical(canonical) : null;
}

/**
 * WordPress post identity from REST alternate / shortlink signals.
 * @returns {{ key: string|null, values: string[], rejected: { kind: string, value: string, reason: string }[] }}
 */
function wordpressPostIdentity(signals, documentUrl) {
  const rejected = [];
  const found = new Map(); // key -> [values]
  const docHost = bareHost(documentUrl);
  const add = (base, id, value) => {
    const key = `wp:${base}:${id}`;
    if (!found.has(key)) found.set(key, []);
    found.get(key).push(value);
  };
  for (const href of signals.wp_rest) {
    const u = new URL(href);
    const m = u.pathname.match(/^(.*?)\/wp-json\/wp\/v2\/([a-z0-9_-]+)\/(\d+)\/?$/i);
    if (!m) continue;
    if (bareHost(href) !== docHost) {
      rejected.push({ kind: 'wp_post', value: href, reason: 'cross_site' });
      continue;
    }
    if (NON_POST_WP_ROUTES.has(m[2].toLowerCase())) {
      rejected.push({ kind: 'wp_post', value: href, reason: 'not_a_post_route' });
      continue;
    }
    add(`${bareHost(href)}${m[1].replace(/\/+$/, '')}`, m[3], href);
  }
  for (const href of signals.shortlink) {
    const u = new URL(href);
    const p = u.searchParams.get('p');
    if (!p || !/^\d+$/.test(p) || [...u.searchParams.keys()].length !== 1) continue;
    if (bareHost(href) !== docHost) {
      rejected.push({ kind: 'wp_post', value: href, reason: 'cross_site' });
      continue;
    }
    add(`${bareHost(href)}${u.pathname.replace(/\/+$/, '')}`, p, href);
  }
  if (found.size > 1) {
    for (const values of found.values()) for (const v of values) rejected.push({ kind: 'wp_post', value: v, reason: 'conflicting_post_ids' });
    return { key: null, values: [], rejected };
  }
  const [entry] = [...found.entries()];
  return entry ? { key: entry[0], values: entry[1], rejected } : { key: null, values: [], rejected };
}

/**
 * Resolve the identity keys of one fetched URL report.
 * @param {{ submittedUrl: string, finalUrl?: string|null, html?: string|null }} input
 * @returns {{
 *   version: string,
 *   submitted_url: string,
 *   final_url: string|null,
 *   keys: { key: string, evidence: string[], values: string[] }[],
 *   rejected: { kind: string, value: string, reason: string }[],
 *   hreflang: { lang: string, key: string }[]
 * }}
 */
export function resolveSourceIdentity({ submittedUrl, finalUrl = null, html = null }) {
  const keys = new Map();
  const rejected = [];
  const addKey = (key, kind, value) => {
    if (!key) return;
    if (!keys.has(key)) keys.set(key, { key, evidence: [], values: [] });
    const entry = keys.get(key);
    if (!entry.evidence.includes(kind)) entry.evidence.push(kind);
    if (value && !entry.values.includes(value)) entry.values.push(value);
  };

  const submittedKey = urlIdentityKey(submittedUrl);
  addKey(submittedKey, 'submitted', submittedUrl);

  const delivered = canonicalizeReportUrl(finalUrl) ? String(finalUrl) : String(submittedUrl);
  const deliveredKey = urlIdentityKey(delivered);
  if (finalUrl && deliveredKey && deliveredKey !== submittedKey) {
    if (isRootPath(delivered)) rejected.push({ kind: 'redirect', value: delivered, reason: 'root_path' });
    else addKey(deliveredKey, 'redirect', delivered);
  }

  const out = {
    version: SOURCE_IDENTITY_VERSION,
    submitted_url: String(submittedUrl),
    final_url: finalUrl ? String(finalUrl) : null,
    keys: [],
    rejected,
    hreflang: []
  };
  if (!html) {
    out.keys = [...keys.values()];
    return out;
  }

  const signals = extractPublisherIdentitySignals(html, delivered);
  const docHost = bareHost(delivered);
  const knownKeys = new Set([submittedKey, deliveredKey].filter(Boolean));
  /** key -> { kinds:Set, values:[] } of declared URLs that passed the per-signal checks */
  const declared = new Map();
  for (const kind of ['canonical', 'og_url', 'json_ld']) {
    for (const href of signals[kind]) {
      const key = urlIdentityKey(href);
      if (!key) continue;
      let reason = null;
      if (bareHost(href) !== docHost) reason = 'cross_site';
      else if (isRootPath(href)) reason = 'root_path';
      else if (isAncestorPath(href, delivered)) reason = 'ancestor_of_document';
      if (reason) {
        rejected.push({ kind, value: href, reason });
        continue;
      }
      if (!declared.has(key)) declared.set(key, { kinds: new Set(), values: [] });
      const d = declared.get(key);
      d.kinds.add(kind);
      if (!d.values.includes(href)) d.values.push(href);
    }
  }
  for (const [key, d] of declared) {
    if (knownKeys.has(key) || d.kinds.size >= 2) {
      for (const kind of d.kinds) addKey(key, kind, null);
      for (const v of d.values) keys.get(key).values.includes(v) || keys.get(key).values.push(v);
    } else {
      for (const kind of d.kinds) for (const v of d.values) rejected.push({ kind, value: v, reason: 'uncorroborated' });
    }
  }

  if (!isRootPath(delivered)) {
    const wp = wordpressPostIdentity(signals, delivered);
    rejected.push(...wp.rejected);
    if (wp.key) for (const v of wp.values) addKey(wp.key, 'wp_post', v);
  }

  const ownKeys = new Set(keys.keys());
  const seen = new Set();
  for (const alt of signals.hreflang) {
    const key = urlIdentityKey(alt.url);
    if (!key || ownKeys.has(key) || seen.has(key)) continue;
    seen.add(key);
    out.hreflang.push({ lang: alt.lang, key });
  }
  out.keys = [...keys.values()];
  return out;
}
