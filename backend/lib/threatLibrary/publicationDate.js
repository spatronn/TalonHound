/**
 * Threat Library publication date: one canonical extractor + one write policy.
 *
 * `threat_reports.published_at` means "when the ORIGINAL source / report was
 * published". It is never the ingestion time (`created_at` = Imported), never
 * a campaign / activity / first-seen date, never a PDF CreationDate and never
 * a "last updated" stamp. Every value carries:
 *
 *   published_at_source     how it was obtained (provenance, ranked below)
 *   published_at_raw        the exact string it was parsed from
 *   published_at_precision  'date'     = the source stated a calendar day only
 *                                        (stored as 00:00:00 UTC of that day;
 *                                        consumers must not render a time)
 *                           'datetime' = the source stated a real instant
 *                                        (time + explicit UTC offset)
 *
 * Deterministic sources, strongest first:
 *   URL   json_ld   > og_article > meta > html_time > visible_date
 *   PDF   pdf_visible_date (explicit cover / front-matter date only)
 * `manual` / `thib` values are assertions from a person or a sharing party
 * and are never overwritten by extraction. `ai` is the weakest rank and is
 * only accepted through `verifyAiPublicationDateHint` (the evidence block
 * must literally contain the date) — the analysis prompt does not emit it
 * today, so nothing produces an `ai` value.
 */

import { annotateDocumentZones } from './documentZones.js';
import { hostnameFromUrl } from './candidateTyping.js';
import { parseHtml, findElements, textOf, decodeEntities } from './extract/htmlBlocks.js';

export const PUBLICATION_DATE_SOURCES = Object.freeze([
  'manual',
  'thib',
  'json_ld',
  'og_article',
  'meta',
  'html_time',
  'visible_date',
  'pdf_visible_date',
  'ai'
]);

/** Higher wins. An existing value is only replaced by a strictly higher rank. */
export const PUBLICATION_DATE_SOURCE_RANK = Object.freeze({
  manual: 100,
  thib: 90,
  json_ld: 80,
  og_article: 70,
  meta: 60,
  html_time: 50,
  visible_date: 40,
  pdf_visible_date: 40,
  ai: 10
});

export const PUBLICATION_DATE_PRECISIONS = Object.freeze(['date', 'datetime']);

/** Bump when detection rules change (recorded next to every detection). */
export const PUBLICATION_DATE_EXTRACTOR_VERSION = 'tl-published-at-v1';

export function isValidPublicationDateSource(value) {
  return PUBLICATION_DATE_SOURCES.includes(String(value || '').toLowerCase());
}

export function isValidPublicationDatePrecision(value) {
  return PUBLICATION_DATE_PRECISIONS.includes(String(value || '').toLowerCase());
}

// ---------------------------------------------------------------------------
// Value parsing
// ---------------------------------------------------------------------------

const MONTHS = Object.freeze({
  jan: 1, january: 1,
  feb: 2, february: 2,
  mar: 3, march: 3,
  apr: 4, april: 4,
  may: 5,
  jun: 6, june: 6,
  jul: 7, july: 7,
  aug: 8, august: 8,
  sep: 9, sept: 9, september: 9,
  oct: 10, october: 10,
  nov: 11, november: 11,
  dec: 12, december: 12
});
const MONTH_NAME_RE = 'jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?';
const OFFSET_RE = '(Z|UTC|GMT|[+-]\\d{2}:?\\d{2})';

const MIN_YEAR = 1995;
const RAW_MAX_CHARS = 80;

function daysInMonth(y, m) {
  return new Date(Date.UTC(y, m, 0)).getUTCDate();
}

function validYmd(y, m, d, now) {
  const maxYear = (now || new Date()).getUTCFullYear() + 1;
  if (!Number.isInteger(y) || !Number.isInteger(m) || !Number.isInteger(d)) return false;
  if (y < MIN_YEAR || y > maxYear) return false;
  if (m < 1 || m > 12) return false;
  if (d < 1 || d > daysInMonth(y, m)) return false;
  return true;
}

function offsetMinutes(token) {
  if (!token) return null;
  const t = String(token).toUpperCase();
  if (t === 'Z' || t === 'UTC' || t === 'GMT') return 0;
  const m = t.match(/^([+-])(\d{2}):?(\d{2})$/);
  if (!m) return null;
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (Number(m[2]) * 60 + Number(m[3]));
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

/**
 * Build the parse result from components. A value is an instant only when it
 * carries a time AND an explicit UTC offset; a bare time (or none) yields a
 * calendar-day value stored at 00:00:00 UTC of that day.
 */
function buildParsed(raw, y, m, d, time, offset, now) {
  if (!validYmd(y, m, d, now)) return null;
  const date = `${y}-${pad2(m)}-${pad2(d)}`;
  const hasTime = Boolean(time);
  const off = hasTime ? offsetMinutes(offset) : null;
  if (hasTime && off != null) {
    const { h, mi, s } = time;
    if (h > 23 || mi > 59 || s > 60) return null;
    const instant = new Date(Date.UTC(y, m - 1, d, h, mi, s) - off * 60_000);
    return { ok: true, raw, instant, precision: 'datetime', date, has_time: true, has_offset: true };
  }
  return {
    ok: true,
    raw,
    instant: new Date(Date.UTC(y, m - 1, d)),
    precision: 'date',
    date,
    has_time: hasTime,
    has_offset: false
  };
}

function timeParts(h, mi, s, ampm) {
  if (h == null) return null;
  let hour = Number(h);
  if (ampm) {
    const p = String(ampm).toUpperCase();
    if (hour === 12) hour = p === 'AM' ? 0 : 12;
    else if (p === 'PM') hour += 12;
  }
  return { h: hour, mi: Number(mi || 0), s: Number(s || 0) };
}

const ISO_RE = new RegExp(
  `^(\\d{4})[-/](\\d{2})[-/](\\d{2})(?:[T ](\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.\\d+)?)?\\s*${OFFSET_RE}?)?$`,
  'i'
);
// 15 September 2026 / 15 Sep 2026 / Mon, 15 Sep 2026 15:00:00 GMT
const DMY_RE = new RegExp(
  `^(?:[a-z]{3,9},?\\s+)?(\\d{1,2})(?:st|nd|rd|th)?\\.?\\s+(${MONTH_NAME_RE})\\.?,?\\s+(\\d{4})(?:,?\\s+(?:at\\s+)?(\\d{1,2}):(\\d{2})(?::(\\d{2}))?\\s*(AM|PM)?\\s*${OFFSET_RE}?)?$`,
  'i'
);
// September 15, 2026 / Sep 08, 2026 / Sept. 8, 2026 / Sep 10, 2026, 12:30 PM
const MDY_RE = new RegExp(
  `^(?:[a-z]{3,9},?\\s+)?(${MONTH_NAME_RE})\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})(?:,?\\s+(?:at\\s+)?(\\d{1,2}):(\\d{2})(?::(\\d{2}))?\\s*(AM|PM)?\\s*${OFFSET_RE}?)?$`,
  'i'
);
// 2026年9月10日
const CJK_RE = /^(\d{4})年(\d{1,2})月(\d{1,2})日(?:\s*(\d{1,2}):(\d{2}))?$/;

/**
 * Parse one publication-date string deterministically. Supported: ISO 8601
 * (date, or date-time with/without offset), RFC 2822-style and English
 * "15 September 2026" / "September 15, 2026" forms (optional time), and
 * CJK 年月日. Ambiguous numeric forms (9/12/26, 12.09.2026) are rejected on
 * purpose: they cannot be read without knowing the locale.
 *
 * @param {unknown} value
 * @param {{ now?: Date }} [opts]
 * @returns {{ ok: true, raw: string, instant: Date, precision: 'date'|'datetime', date: string, has_time: boolean, has_offset: boolean }|null}
 */
export function parsePublicationDateValue(value, opts = {}) {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return null;
    return parsePublicationDateValue(value.toISOString(), opts);
  }
  const raw = String(value ?? '').replace(/\s+/g, ' ').trim();
  if (!raw || raw.length > RAW_MAX_CHARS) return null;
  const now = opts.now || new Date();

  let m = raw.match(ISO_RE);
  if (m) {
    return buildParsed(raw, Number(m[1]), Number(m[2]), Number(m[3]), timeParts(m[4], m[5], m[6], null), m[7], now);
  }
  m = raw.match(DMY_RE);
  if (m) {
    const month = MONTHS[m[2].toLowerCase()];
    return buildParsed(raw, Number(m[3]), month, Number(m[1]), timeParts(m[4], m[5], m[6], m[7]), m[8], now);
  }
  m = raw.match(MDY_RE);
  if (m) {
    const month = MONTHS[m[1].toLowerCase()];
    return buildParsed(raw, Number(m[3]), month, Number(m[2]), timeParts(m[4], m[5], m[6], m[7]), m[8], now);
  }
  m = raw.match(CJK_RE);
  if (m) {
    return buildParsed(raw, Number(m[1]), Number(m[2]), Number(m[3]), timeParts(m[4], m[5], null, null), null, now);
  }
  return null;
}

/**
 * Date mentions inside free text (document order). Only unambiguous forms:
 * "September 15, 2026", "15 September 2026", "2026-09-15", "2026年9月10日".
 * @param {string} text
 * @returns {{ raw: string, index: number, parsed: object }[]}
 */
export function findDateMentions(text, opts = {}) {
  const src = String(text || '');
  const out = [];
  const patterns = [
    // The year ends at a non-digit rather than \b: PDF cover layouts merge
    // lines without spaces ("January 21, 2026that combines").
    new RegExp(`\\b(${MONTH_NAME_RE})\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?,?\\s+(\\d{4})(?!\\d)`, 'gi'),
    new RegExp(`\\b(\\d{1,2})(?:st|nd|rd|th)?\\s+(${MONTH_NAME_RE})\\.?,?\\s+(\\d{4})(?!\\d)`, 'gi'),
    /\b(\d{4})-(\d{2})-(\d{2})\b/g,
    /(\d{4})年(\d{1,2})月(\d{1,2})日/g
  ];
  for (const re of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(src)) !== null) {
      const parsed = parsePublicationDateValue(m[0], opts);
      if (parsed) out.push({ raw: m[0], index: m.index, parsed });
    }
  }
  out.sort((a, b) => a.index - b.index);
  // A mention that overlaps an earlier one (same characters) is the same date.
  const dedup = [];
  for (const mention of out) {
    const last = dedup[dedup.length - 1];
    if (last && mention.index < last.index + last.raw.length) continue;
    dedup.push(mention);
  }
  return dedup;
}

// ---------------------------------------------------------------------------
// Detection result helpers
// ---------------------------------------------------------------------------

/**
 * @typedef {{
 *   published_at: string|null,          // ISO instant (UTC) or null
 *   published_date: string|null,        // YYYY-MM-DD as stated by the source
 *   precision: 'date'|'datetime'|null,
 *   source: string|null,                // PUBLICATION_DATE_SOURCES member
 *   raw_value: string|null,
 *   evidence: object|null,              // where it was found (selector / block id / label)
 *   reason: string|null,                // why nothing was accepted
 *   modified_at: string|null,           // last-modified stamp seen next to it (never persisted as published_at)
 *   considered: object[],               // bounded trail of what was looked at
 *   extractor: string
 * }} PublicationDateDetection
 */

function emptyDetection(reason, considered = []) {
  return {
    published_at: null,
    published_date: null,
    precision: null,
    source: null,
    raw_value: null,
    evidence: null,
    reason,
    modified_at: null,
    considered: considered.slice(0, 20),
    extractor: PUBLICATION_DATE_EXTRACTOR_VERSION
  };
}

function detectionFrom(parsed, source, evidence, considered = [], extra = {}) {
  return {
    published_at: parsed.instant.toISOString(),
    published_date: parsed.date,
    precision: parsed.precision,
    source,
    raw_value: parsed.raw,
    evidence: evidence || null,
    reason: null,
    modified_at: extra.modified_at || null,
    considered: considered.slice(0, 20),
    extractor: PUBLICATION_DATE_EXTRACTOR_VERSION
  };
}

// ---------------------------------------------------------------------------
// URL / HTML extraction
// ---------------------------------------------------------------------------

const ARTICLE_TYPES = new Set([
  'article', 'newsarticle', 'blogposting', 'techarticle', 'scholarlyarticle', 'report',
  'analysisnewsarticle', 'reportagenewsarticle', 'advertisercontentarticle', 'socialmediaposting',
  'liveblogposting', 'creativework'
]);
const PAGE_TYPES = new Set(['webpage', 'itempage', 'collectionpage']);

function typesOf(node) {
  const t = node?.['@type'];
  const list = Array.isArray(t) ? t : t ? [t] : [];
  return list.map((x) => String(x).toLowerCase());
}

function walkJsonLd(node, visit, depth = 0) {
  if (!node || depth > 8) return;
  if (Array.isArray(node)) {
    for (const item of node) walkJsonLd(item, visit, depth + 1);
    return;
  }
  if (typeof node !== 'object') return;
  visit(node);
  if (Array.isArray(node['@graph'])) walkJsonLd(node['@graph'], visit, depth + 1);
  if (node.mainEntity && typeof node.mainEntity === 'object') walkJsonLd(node.mainEntity, visit, depth + 1);
}

function jsonLdBlocks(html) {
  const out = [];
  const re = /<script\b[^>]*type\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const body = m[1].trim();
    if (!body) continue;
    try {
      out.push(JSON.parse(body));
    } catch {
      // A CDATA wrapper or stray HTML comment around the JSON is common.
      const cleaned = body.replace(/^\s*<!--/, '').replace(/-->\s*$/, '').replace(/^\s*\/\/<!\[CDATA\[/, '').replace(/\/\/\]\]>\s*$/, '').trim();
      try {
        out.push(JSON.parse(cleaned));
      } catch {
        /* ignore unparsable block */
      }
    }
  }
  return out;
}

function firstString(v) {
  if (Array.isArray(v)) return firstString(v[0]);
  if (v && typeof v === 'object' && typeof v['@value'] === 'string') return v['@value'];
  return typeof v === 'string' ? v : null;
}

/**
 * JSON-LD `datePublished` from Article-like objects (arrays and @graph
 * supported). A WebPage node is only used when no article-like node has one.
 */
export function extractJsonLdPublicationDate(html, opts = {}) {
  const considered = [];
  const articleHits = [];
  const pageHits = [];
  for (const root of jsonLdBlocks(String(html || ''))) {
    walkJsonLd(root, (node) => {
      const raw = firstString(node.datePublished);
      if (!raw) return;
      const types = typesOf(node);
      const isArticle = types.some((t) => ARTICLE_TYPES.has(t));
      const isPage = types.some((t) => PAGE_TYPES.has(t));
      if (!isArticle && !isPage) {
        considered.push({ where: 'json_ld', type: types.join(',') || '(untyped)', raw, skipped: 'not_article' });
        return;
      }
      const parsed = parsePublicationDateValue(raw, opts);
      considered.push({ where: 'json_ld', type: types.join(','), raw, parsed: parsed ? parsed.date : null });
      if (!parsed) return;
      const hit = { parsed, type: types.join(','), modified: firstString(node.dateModified) };
      (isArticle ? articleHits : pageHits).push(hit);
    });
  }
  const pick = articleHits[0] || pageHits[0];
  if (!pick) return emptyDetection(considered.length ? 'json_ld_unparsable' : 'json_ld_absent', considered);
  return detectionFrom(pick.parsed, 'json_ld', { selector: `application/ld+json ${pick.type}.datePublished` }, considered, {
    modified_at: pick.modified || null
  });
}

/** `<meta … content>` values keyed by lower-cased property / name / itemprop. */
function metaValues(dom) {
  const out = new Map();
  for (const el of findElements(dom, (e) => String(e.name || '').toLowerCase() === 'meta')) {
    const a = el.attribs || {};
    const key = String(a.property || a.name || a.itemprop || '').trim().toLowerCase();
    const content = a.content != null ? decodeEntities(String(a.content)).trim() : '';
    if (!key || !content) continue;
    if (!out.has(key)) out.set(key, []);
    out.get(key).push(content);
  }
  return out;
}

const OG_PUBLISHED_KEYS = Object.freeze(['article:published_time', 'og:article:published_time']);
const OG_MODIFIED_KEYS = Object.freeze(['article:modified_time', 'og:article:modified_time', 'og:updated_time']);
/** Publication-oriented metadata names only; nothing "modified" / "updated" / "created" is listed. */
const META_PUBLISHED_KEYS = Object.freeze([
  'datepublished',
  'article.published',
  'publish-date',
  'publish_date',
  'publishdate',
  'pubdate',
  'publication_date',
  'publication-date',
  'publicationdate',
  'sailthru.date',
  'parsely-pub-date',
  'dc.date.issued',
  'dcterms.issued',
  'citation_publication_date',
  'citation_date',
  'dc.date',
  'dcterms.date',
  'date'
]);

/**
 * OpenGraph / article metadata and the common publication-oriented meta
 * variants. `opts.dom` lets a caller reuse a parsed document.
 */
export function extractMetaPublicationDate(html, opts = {}) {
  const dom = opts.dom || parseHtml(String(html || ''));
  const metas = metaValues(dom);
  const considered = [];
  const modified = OG_MODIFIED_KEYS.map((k) => metas.get(k)?.[0]).find(Boolean) || null;

  for (const key of OG_PUBLISHED_KEYS) {
    for (const raw of metas.get(key) || []) {
      const parsed = parsePublicationDateValue(raw, opts);
      considered.push({ where: 'meta', key, raw, parsed: parsed ? parsed.date : null });
      if (parsed) {
        return detectionFrom(parsed, 'og_article', { selector: `meta[property="${key}"]` }, considered, { modified_at: modified });
      }
    }
  }
  for (const key of META_PUBLISHED_KEYS) {
    for (const raw of metas.get(key) || []) {
      const parsed = parsePublicationDateValue(raw, opts);
      considered.push({ where: 'meta', key, raw, parsed: parsed ? parsed.date : null });
      if (parsed) {
        return detectionFrom(parsed, 'meta', { selector: `meta[name="${key}"]` }, considered, { modified_at: modified });
      }
    }
  }
  const d = emptyDetection(considered.length ? 'meta_unparsable' : 'meta_absent', considered);
  d.modified_at = modified;
  return d;
}

const NEGATIVE_CONTEXT_RE = /\b(updated|modified|last reviewed|reviewed|revised|edited|last edited|expires?|expired|comment(?:ed)?|event|webinar|deadline|register|due)\b/i;
const PUBLISHED_LABEL_RE = /\b(published(?:\s+on)?|posted(?:\s+on)?|publication date|date published|published date|release date|released(?:\s+on)?|report date|date of publication|dated?)\s*[:\-–—]?\s*$/i;
const PUBLISHED_CLASS_RE = /(publish|pubdate|pub-date|pub_date|posted|entry-date|entry-time|post-date|postdate|article-date|article__date|byline|dateline|date-published|datePublished|published-date|release-date)/i;
// Class / id tokens that mark a container as "not this article": related /
// recent post lists, sidebars, widgets, comments, footers. Matched per token
// (prefix) so a layout wrapper such as `content-sidebar-wrap` is not noise.
const NOISE_TOKEN_RE = /^(related|recent|latest|sidebar|widget|comments?|recommend|popular|trending|carousel|teaser|archive|more-posts|similar)/i;
const NOISE_TAGS = new Set(['aside', 'nav', 'footer']);
const NOISE_ROLES = new Set(['complementary', 'navigation', 'contentinfo']);

function isNoiseContainer(el) {
  const tag = String(el.name || '').toLowerCase();
  const a = el.attribs || {};
  if (NOISE_TAGS.has(tag) || NOISE_ROLES.has(String(a.role || '').toLowerCase())) return true;
  const tokens = `${a.class || ''} ${a.id || ''}`.split(/\s+/).filter(Boolean);
  return tokens.some((t) => NOISE_TOKEN_RE.test(t));
}

/**
 * Walks up to the nearest <article> / <main>; noise is only looked for below
 * that boundary (a page's global sidebar wrapper never disqualifies the
 * article's own byline).
 */
function ancestorInfo(el) {
  let inArticle = false;
  let inNoise = false;
  for (let p = el.parent; p; p = p.parent) {
    if (p.type !== 'tag') continue;
    const tag = String(p.name || '').toLowerCase();
    const a = p.attribs || {};
    if (tag === 'article' || tag === 'main' || String(a.role || '').toLowerCase() === 'main') {
      inArticle = true;
      break;
    }
    if (isNoiseContainer(p)) inNoise = true;
  }
  return { inArticle, inNoise };
}

/** Text of the nearest preceding siblings (label lookup), bounded. */
function precedingText(el, maxChars = 160) {
  const parts = [];
  let node = el;
  let hops = 0;
  while (node && hops < 12 && parts.join(' ').length < maxChars) {
    let sib = node.prev;
    while (sib && parts.join(' ').length < maxChars) {
      if (sib.type === 'text') parts.unshift(String(sib.data || ''));
      else if (sib.type === 'tag') parts.unshift(textOf(sib));
      sib = sib.prev;
    }
    node = node.parent;
    hops += 1;
    if (node && node.type === 'tag' && ['article', 'main', 'body', 'html'].includes(String(node.name || '').toLowerCase())) break;
  }
  return parts.join(' ').replace(/\s+/g, ' ').trim().slice(-maxChars);
}

/**
 * `<time datetime="…">` restricted to publication context: itemprop
 * datePublished, a pubdate attribute, a publish/posted/entry-date/byline
 * class on the element or its parent, or a "Published:" label right before
 * it. Sidebar / related / footer / comment containers and any "updated /
 * modified" context are excluded.
 */
export function extractHtmlTimePublicationDate(html, opts = {}) {
  const dom = opts.dom || parseHtml(String(html || ''));
  const considered = [];
  const hits = [];
  for (const el of findElements(dom, (e) => String(e.name || '').toLowerCase() === 'time')) {
    const a = el.attribs || {};
    const raw = String(a.datetime || '').trim() || textOf(el);
    if (!raw) continue;
    const parentAttrs = el.parent?.attribs || {};
    const ownHint = `${a.class || ''} ${a.id || ''} ${a.itemprop || ''}`;
    const parentHint = `${parentAttrs.class || ''} ${parentAttrs.id || ''} ${parentAttrs.itemprop || ''}`;
    const before = precedingText(el);
    const { inArticle, inNoise } = ancestorInfo(el);
    let signal = null;
    if (/datepublished/i.test(String(a.itemprop || ''))) signal = 'itemprop';
    else if (a.pubdate != null) signal = 'pubdate';
    else if (PUBLISHED_CLASS_RE.test(ownHint) || PUBLISHED_CLASS_RE.test(parentHint)) signal = 'class';
    else if (PUBLISHED_LABEL_RE.test(before)) signal = 'label';
    const negative = NEGATIVE_CONTEXT_RE.test(`${ownHint} ${parentHint}`) || NEGATIVE_CONTEXT_RE.test(before.slice(-60));
    const parsed = signal && !negative && !inNoise ? parsePublicationDateValue(raw, opts) : null;
    considered.push({ where: 'time', raw, signal, negative, in_noise: inNoise, in_article: inArticle, parsed: parsed ? parsed.date : null });
    if (parsed) hits.push({ parsed, signal, inArticle, raw });
  }
  if (!hits.length) return emptyDetection(considered.length ? 'html_time_no_publication_context' : 'html_time_absent', considered);
  const order = { itemprop: 0, pubdate: 1, label: 2, class: 3 };
  hits.sort((x, y) => (order[x.signal] - order[y.signal]) || (Number(y.inArticle) - Number(x.inArticle)));
  const best = hits[0];
  // Distinct dates with the same strength and no article scoping → ambiguous.
  const peers = hits.filter((h) => h.signal === best.signal && h.inArticle === best.inArticle);
  const distinct = new Set(peers.map((h) => h.parsed.date));
  if (distinct.size > 1) return emptyDetection('html_time_ambiguous', considered);
  return detectionFrom(best.parsed, 'html_time', { selector: `time[${best.signal}]`, in_article: best.inArticle }, considered);
}

/**
 * Visible article date: a short element whose text is "Published: <date>" /
 * "Posted on <date>" (label required) or whose class marks it as the post
 * date and whose text is exactly a date. Body prose, copyright lines,
 * comments and list widgets never qualify.
 */
export function extractVisiblePublicationDate(html, opts = {}) {
  const dom = opts.dom || parseHtml(String(html || ''));
  const considered = [];
  const hits = [];
  const candidates = findElements(dom, (e) => {
    const tag = String(e.name || '').toLowerCase();
    return ['p', 'span', 'div', 'li', 'small', 'em', 'strong', 'b', 'i', 'dd', 'dt', 'td', 'th', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'a', 'label', 'time', 'cite'].includes(tag);
  });
  for (const el of candidates) {
    const text = textOf(el);
    if (!text || text.length > 120) continue;
    const a = el.attribs || {};
    const { inNoise, inArticle } = ancestorInfo(el);
    if (inNoise) continue;
    const mentions = findDateMentions(text, opts);
    if (mentions.length !== 1) continue;
    const mention = mentions[0];
    const before = text.slice(0, mention.index);
    const after = text.slice(mention.index + mention.raw.length);
    if (NEGATIVE_CONTEXT_RE.test(text) || /©|copyright/i.test(text)) {
      considered.push({ where: 'visible', text, skipped: 'negative_context' });
      continue;
    }
    let signal = null;
    if (PUBLISHED_LABEL_RE.test(before)) signal = 'label';
    else if (PUBLISHED_CLASS_RE.test(`${a.class || ''} ${a.id || ''}`) && before.trim() === '' && after.trim() === '') signal = 'class';
    else if (PUBLISHED_LABEL_RE.test(precedingText(el, 40)) && before.trim() === '' && after.trim().length <= 3) signal = 'label';
    if (!signal) continue;
    considered.push({ where: 'visible', text, signal, in_article: inArticle, parsed: mention.parsed.date });
    hits.push({ parsed: mention.parsed, signal, inArticle, text });
  }
  if (!hits.length) return emptyDetection('visible_date_absent', considered);
  hits.sort((x, y) => (x.signal === y.signal ? Number(y.inArticle) - Number(x.inArticle) : x.signal === 'label' ? -1 : 1));
  const best = hits[0];
  const peers = hits.filter((h) => h.signal === best.signal && h.inArticle === best.inArticle);
  if (new Set(peers.map((h) => h.parsed.date)).size > 1) return emptyDetection('visible_date_ambiguous', considered);
  return detectionFrom(best.parsed, 'visible_date', { text: best.text.slice(0, 120), signal: best.signal, in_article: best.inArticle }, considered);
}

/**
 * Canonical URL / HTML path: JSON-LD → article:published_time → meta
 * variants → <time datetime> → visible labelled date. The first source that
 * yields a parseable value wins; weaker sources are not consulted after that.
 * @param {string} html
 * @param {{ url?: string|null, now?: Date }} [opts]
 * @returns {PublicationDateDetection}
 */
export function extractHtmlPublicationDate(html, opts = {}) {
  const raw = String(html || '');
  if (!raw.trim()) return emptyDetection('html_empty');
  const trail = [];
  const jsonLd = extractJsonLdPublicationDate(raw, opts);
  trail.push(...jsonLd.considered);
  if (jsonLd.published_at) return { ...jsonLd, considered: trail.slice(0, 20) };

  const dom = parseHtml(raw);
  const meta = extractMetaPublicationDate(raw, { ...opts, dom });
  trail.push(...meta.considered);
  if (meta.published_at) return { ...meta, considered: trail.slice(0, 20) };

  const time = extractHtmlTimePublicationDate(raw, { ...opts, dom });
  trail.push(...time.considered);
  if (time.published_at) return { ...time, modified_at: meta.modified_at, considered: trail.slice(0, 20) };

  const visible = extractVisiblePublicationDate(raw, { ...opts, dom });
  trail.push(...visible.considered);
  if (visible.published_at) return { ...visible, modified_at: meta.modified_at, considered: trail.slice(0, 20) };

  const none = emptyDetection('no_publication_date_in_html', trail);
  none.modified_at = meta.modified_at;
  return none;
}

// ---------------------------------------------------------------------------
// Canonical document (PDF cover / front matter) extraction
// ---------------------------------------------------------------------------

const DOC_NEGATIVE_RE = /\b(as of|updated|modified|revised|reviewed|printed|downloaded|accessed|retrieved|copyright|first seen|last seen|observed|since|between|from|until|through|effective|expires?|valid|campaign|attack|incident|compromise|breach|exploited|detected|discovered|version|v\d|deadline|event|webinar)\b|©/i;
const DOC_LABEL_RE = /\b(published(?:\s+on)?|posted(?:\s+on)?|publication date|date published|published date|release date|released(?:\s+on)?|report date|date of publication|dated?|issued(?:\s+on)?)\s*[:\-–—]?\s*$/i;
const BROWSER_PRINT_HEADER_RE = /^\s*\d{1,2}\/\d{1,2}\/\d{2,4},?\s+\d{1,2}:\d{2}\s*(AM|PM)?/i;
const EXCLUDED_ZONES = new Set(['header_footer', 'navigation', 'source_metadata']);
const FRONT_MATTER_PAGES = 2;
const FRONT_MATTER_BLOCKS = 30;
const SHORT_BLOCK_CHARS = 200;

function normalizeTitle(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9一-鿿]+/g, '').slice(0, 60);
}

/**
 * Explicit visible publication date in a canonical document's cover / front
 * matter. Conservative on purpose:
 *   - only the first two pages (PDF) / first 30 blocks (other) are read
 *   - repeated running headers, page-edge lines, navigation and source
 *     metadata zones are skipped; a browser print stamp ("9/12/26, 9:05 PM")
 *     is never a publication date
 *   - a date next to a negative word (as of / updated / observed / from …)
 *     never qualifies
 *   - a labelled date ("Published: …", "Report date …") wins; otherwise an
 *     unlabelled date is accepted only from a byline-sized block (≤200 chars)
 *     or the cover block, and only when it is the single distinct date in
 *     the front matter — two different dates means null, not a guess
 * PDF CreationDate / ModDate metadata is deliberately not an input.
 *
 * @param {import('./canonicalDocument.js').CanonicalDocument|null|undefined} document
 * @param {{ sourceType?: string|null, sourceUrl?: string|null, now?: Date }} [opts]
 * @returns {PublicationDateDetection}
 */
export function extractDocumentPublicationDate(document, opts = {}) {
  if (!document || !Array.isArray(document.blocks) || !document.blocks.length) return emptyDetection('document_empty');
  const sourceType = String(opts.sourceType || (document.meta?.adapter === 'pdf' ? 'pdf' : '')).toLowerCase();
  const source = sourceType === 'pdf' ? 'pdf_visible_date' : 'visible_date';
  const sourceUrl = opts.sourceUrl || document.meta?.source_url || null;
  let sourceHost = null;
  if (sourceUrl) {
    try {
      sourceHost = hostnameFromUrl(sourceUrl);
    } catch {
      sourceHost = null;
    }
  }
  const annotated = annotateDocumentZones(document, { sourceUrl, sourceHost });
  const blocks = annotated.blocks || [];
  const titleNorm = normalizeTitle(document.title);

  const front = [];
  let firstPageFirstBlockId = null;
  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    const page = Number.isInteger(b.page) ? b.page : null;
    if (page != null ? page > FRONT_MATTER_PAGES : i >= FRONT_MATTER_BLOCKS) break;
    if (page === 1 && firstPageFirstBlockId == null) firstPageFirstBlockId = b.id;
    front.push(b);
  }

  const considered = [];
  const labelled = [];
  const unlabelled = [];
  /** Every distinct front-matter date outside chrome zones, whatever its context. */
  const allFrontDates = new Set();
  for (const b of front) {
    const text = String(b.text || '').replace(/\s+/g, ' ').trim();
    if (!text) continue;
    if (EXCLUDED_ZONES.has(b.zone) || b.layout === 'page_edge') {
      if (findDateMentions(text, opts).length) considered.push({ block_id: b.id, skipped: b.zone || b.layout, text: text.slice(0, 80) });
      continue;
    }
    if (BROWSER_PRINT_HEADER_RE.test(text)) {
      considered.push({ block_id: b.id, skipped: 'browser_print_stamp', text: text.slice(0, 80) });
      continue;
    }
    const mentions = findDateMentions(text, opts);
    if (!mentions.length) continue;
    const isCover = b.page === 1 && (b.id === firstPageFirstBlockId || (titleNorm && normalizeTitle(text).includes(titleNorm)));
    const shortBlock = text.length <= SHORT_BLOCK_CHARS;
    for (const m of mentions) {
      allFrontDates.add(m.parsed.date);
      const before = text.slice(Math.max(0, m.index - 40), m.index);
      const after = text.slice(m.index + m.raw.length, m.index + m.raw.length + 24);
      if (DOC_NEGATIVE_RE.test(before) || DOC_NEGATIVE_RE.test(after)) {
        considered.push({ block_id: b.id, raw: m.raw, skipped: 'negative_context', context: `${before}${m.raw}${after}`.slice(0, 100) });
        continue;
      }
      const label = DOC_LABEL_RE.test(before);
      if (label) {
        labelled.push({ block: b, mention: m, context: `${before}${m.raw}`.trim() });
        considered.push({ block_id: b.id, raw: m.raw, signal: 'label', page: b.page ?? null });
      } else if (shortBlock || isCover) {
        unlabelled.push({ block: b, mention: m, context: `${before}${m.raw}${after}`.trim(), cover: isCover });
        considered.push({ block_id: b.id, raw: m.raw, signal: isCover ? 'cover' : 'byline', page: b.page ?? null });
      } else {
        considered.push({ block_id: b.id, raw: m.raw, skipped: 'body_prose', page: b.page ?? null });
      }
    }
  }

  const pickFrom = (list, signal) => {
    const distinct = new Set(list.map((x) => x.mention.parsed.date));
    if (distinct.size !== 1) return emptyDetection(`${source}_ambiguous`, considered);
    const best = list[0];
    return detectionFrom(best.mention.parsed, source, {
      block_id: best.block.id,
      page: best.block.page ?? null,
      zone: best.block.zone || null,
      signal,
      context: best.context.slice(0, 120)
    }, considered);
  };
  if (labelled.length) return pickFrom(labelled, 'label');
  // An unlabelled date is only trusted when it is the ONLY date in the front
  // matter: a second date anywhere there (even one rejected for context)
  // means the byline cannot be told apart from a timeline entry.
  if (unlabelled.length && allFrontDates.size === 1) return pickFrom(unlabelled, unlabelled[0].cover ? 'cover' : 'byline');
  if (unlabelled.length) return emptyDetection(`${source}_ambiguous`, considered);
  return emptyDetection(considered.length ? `${source}_rejected` : 'no_date_in_front_matter', considered);
}

/**
 * Canonical entry point for a report: raw HTML first (URL reports), then the
 * canonical document (PDF cover rules, or a URL fallback when no HTML is
 * available). Never throws.
 * @param {{ sourceType: string, sourceUrl?: string|null, html?: string|null, document?: object|null, now?: Date }} input
 * @returns {PublicationDateDetection}
 */
export function detectReportPublicationDate(input) {
  const sourceType = String(input?.sourceType || '').toLowerCase();
  const opts = { url: input?.sourceUrl || null, now: input?.now };
  try {
    if (sourceType === 'url' && input?.html) {
      const fromHtml = extractHtmlPublicationDate(input.html, opts);
      if (fromHtml.published_at) return fromHtml;
      const fromDoc = extractDocumentPublicationDate(input.document, { sourceType, sourceUrl: input.sourceUrl, now: input.now });
      if (fromDoc.published_at) return { ...fromDoc, modified_at: fromHtml.modified_at, considered: [...fromHtml.considered, ...fromDoc.considered].slice(0, 20) };
      return { ...fromHtml, considered: [...fromHtml.considered, ...fromDoc.considered].slice(0, 20) };
    }
    return extractDocumentPublicationDate(input?.document, { sourceType, sourceUrl: input?.sourceUrl, now: input?.now });
  } catch (err) {
    return emptyDetection(`extractor_error:${err?.message || 'unknown'}`);
  }
}

// ---------------------------------------------------------------------------
// AI hint gate (not wired into the analysis prompt — see file header)
// ---------------------------------------------------------------------------

/**
 * Accept a model-proposed publication date only when a referenced evidence
 * block literally contains that calendar date outside a negative context.
 * The model never becomes a source of truth: it can only point at text the
 * deterministic parser can read back.
 * @param {{ value?: string|null, evidence_block_ids?: string[] }} hint
 * @param {import('./canonicalDocument.js').CanonicalDocument|null} document
 * @returns {PublicationDateDetection}
 */
export function verifyAiPublicationDateHint(hint, document, opts = {}) {
  const parsed = parsePublicationDateValue(hint?.value, opts);
  if (!parsed) return emptyDetection('ai_hint_unparsable');
  const ids = Array.isArray(hint?.evidence_block_ids) ? hint.evidence_block_ids.map(String) : [];
  if (!ids.length) return emptyDetection('ai_hint_without_evidence');
  const byId = new Map((document?.blocks || []).map((b) => [String(b.id), b]));
  for (const id of ids) {
    const b = byId.get(id);
    if (!b) continue;
    const text = String(b.text || '');
    for (const m of findDateMentions(text, opts)) {
      if (m.parsed.date !== parsed.date) continue;
      const before = text.slice(Math.max(0, m.index - 40), m.index);
      const after = text.slice(m.index + m.raw.length, m.index + m.raw.length + 24);
      if (DOC_NEGATIVE_RE.test(before) || DOC_NEGATIVE_RE.test(after)) continue;
      return detectionFrom(m.parsed, 'ai', { block_id: b.id, page: b.page ?? null, context: `${before}${m.raw}${after}`.slice(0, 100) });
    }
  }
  return emptyDetection('ai_hint_not_in_evidence');
}

// ---------------------------------------------------------------------------
// Write policy + persistence shape
// ---------------------------------------------------------------------------

function rankOf(source) {
  return PUBLICATION_DATE_SOURCE_RANK[String(source || '').toLowerCase()] ?? null;
}

/**
 * Decide whether a detection may be written over the report's current value.
 *
 *   no detection            → keep (a retry never nulls a good value)
 *   no existing value       → write
 *   existing manual / thib  → keep (assertions by a person / sharing party)
 *   existing unknown source → keep (cannot prove the new value is stronger)
 *   same date, stronger src → write (provenance upgrade only)
 *   stronger source         → write (replaces a weaker extraction)
 *   otherwise               → keep
 *
 * @param {{ published_at?: Date|string|null, published_at_source?: string|null, published_at_precision?: string|null }} report
 * @param {PublicationDateDetection|null} detection
 * @returns {{ action: 'write'|'keep', reason: string, fields: object|null }}
 */
export function resolvePublicationDateUpdate(report, detection) {
  if (!detection || !detection.published_at || !detection.source) {
    return { action: 'keep', reason: report?.published_at ? 'no_detection_keep_existing' : (detection?.reason || 'no_detection'), fields: null };
  }
  const fields = publicationDateFieldsFromDetection(detection);
  if (!report?.published_at) return { action: 'write', reason: 'was_null', fields };
  const existingSource = String(report.published_at_source || '').toLowerCase();
  if (existingSource === 'manual' || existingSource === 'thib') return { action: 'keep', reason: `existing_${existingSource}`, fields: null };
  const existingRank = rankOf(existingSource);
  if (existingRank == null) return { action: 'keep', reason: 'existing_unknown_provenance', fields: null };
  const newRank = rankOf(detection.source);
  if (newRank > existingRank) {
    const existingDate = publishedDateOf(report);
    return {
      action: 'write',
      reason: existingDate === detection.published_date ? 'provenance_upgrade' : 'stronger_source',
      fields
    };
  }
  return { action: 'keep', reason: 'existing_not_weaker', fields: null };
}

/** Column values for a detection (store.updateReportPublicationDate / createThreatReport). */
export function publicationDateFieldsFromDetection(detection) {
  if (!detection?.published_at) return null;
  return {
    published_at: detection.published_at,
    published_at_source: detection.source,
    published_at_precision: detection.precision,
    published_at_raw: detection.raw_value
  };
}

/**
 * Normalise an externally supplied value (THIB bundle, manual input) into the
 * persisted shape. Returns null when the value cannot be read.
 * @param {unknown} value
 * @param {'thib'|'manual'} source
 */
export function normalizeSuppliedPublicationDate(value, source, opts = {}) {
  const parsed = parsePublicationDateValue(value, opts);
  if (!parsed) return null;
  return {
    published_at: parsed.instant.toISOString(),
    published_at_source: source,
    published_at_precision: parsed.precision,
    published_at_raw: parsed.raw
  };
}

function utcDateOf(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 10);
}

/**
 * Calendar day of publication as the source stated it. For a 'date' value
 * that is the stored day; for an instant the day written in the raw value
 * (its own offset), falling back to the UTC day of the instant.
 */
export function publishedDateOf(row) {
  if (!row?.published_at) return null;
  const precision = String(row.published_at_precision || '').toLowerCase();
  if (precision !== 'date' && row.published_at_raw) {
    const parsed = parsePublicationDateValue(row.published_at_raw);
    if (parsed && parsed.instant.getTime() === new Date(row.published_at).getTime()) return parsed.date;
  }
  return utcDateOf(row.published_at);
}

/**
 * Public API / MCP shape. `published_at` stays the raw instant (existing
 * contract); `published_date` + `published_at_precision` let a consumer show
 * a calendar day without inventing a time.
 * @param {object} row threat_reports row (or a join carrying the same columns)
 */
export function serializePublicationDate(row) {
  if (!row?.published_at) {
    return { published_at: null, published_date: null, published_at_precision: null, published_at_source: null };
  }
  const precision = isValidPublicationDatePrecision(row.published_at_precision) ? String(row.published_at_precision).toLowerCase() : null;
  return {
    published_at: row.published_at,
    published_date: publishedDateOf(row),
    published_at_precision: precision,
    published_at_source: isValidPublicationDateSource(row.published_at_source) ? String(row.published_at_source).toLowerCase() : null
  };
}

/**
 * THIB export value: a calendar-day value travels as YYYY-MM-DD so a
 * re-import keeps its precision; an instant travels as ISO 8601 UTC.
 */
export function publicationDateForExport(row) {
  if (!row?.published_at) return null;
  if (String(row.published_at_precision || '').toLowerCase() === 'date') return utcDateOf(row.published_at);
  const d = row.published_at instanceof Date ? row.published_at : new Date(row.published_at);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
