/**
 * Report title selection for HTML sources.
 *
 * Candidates, in order of preference:
 *   1. JSON-LD headline of an Article / BlogPosting / NewsArticle / Report
 *   2. og:title
 *   3. twitter:title
 *   4. <title>
 *   5. the article heading (first <h1> inside <article> / <main>)
 *
 * The first candidate wins unless it is a site-wide brand title. Some sites
 * put one og:title / twitter:title on every page, such as
 * "Vendor - Automated malware analysis solutions" or plain "Vendor Blog". A
 * metadata candidate counts as site-wide brand text only when both hold:
 *   - it is brand-led: one of its " - " / " | " segments is the publisher
 *     brand, or the whole value is the brand (optionally with Blog / News /
 *     Home / Research / Labs);
 *   - an article-specific candidate (<title>, article <h1>, JSON-LD headline;
 *     its own brand segment removed) exists, and none of them repeats at
 *     least 60% of the meaningful words of the non-brand part.
 * A brand-led title that agrees with the article title ("Vendor - Analysis of
 * X" next to "Analysis of X | Vendor") is article-specific and is kept. With
 * no article-specific evidence to compare against, nothing is rejected.
 * Deterministic, no network, no model; every decision is recorded.
 */

import { decodeEntities, findElement, findElements, parseHtml, stripTags } from './htmlBlocks.js';

export const TITLE_SELECTION_VERSION = 'tl-title-v1';

const SEPARATOR_RE = /\s+(?:\||-|–|—|·|::|»)\s+/;
const GENERIC_BRAND_SUFFIXES = new Set(['blog', 'news', 'home', 'homepage', 'research', 'labs', 'lab', 'insights', 'official site', 'website']);
const STOPWORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'of', 'for', 'to', 'in', 'on', 'with', 'by', 'at', 'from', 'is', 'are', 'how', 'our', 'your', 'new'
]);
const ARTICLE_EVIDENCE_SOURCES = new Set(['title_tag', 'article_h1', 'json_ld']);
/** Share of the brand-led title's own words an article title must repeat. */
const AGREEMENT_RATIO = 0.6;
const JSONLD_ARTICLE_TYPES = /^(?:article|blogposting|newsarticle|techarticle|report|scholarlyarticle|analysisnewsarticle|reportagenewsarticle)$/i;

/** Comments never carry page metadata ("<title>" inside a comment is text). */
function withoutComments(html) {
  return String(html || '').replace(/<!--[\s\S]*?-->/g, ' ');
}

function clean(text) {
  return decodeEntities(stripTags(String(text || ''))).replace(/\s+/g, ' ').trim();
}

function norm(text) {
  return String(text || '').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, '');
}

function words(text) {
  return (String(text || '').toLowerCase().match(/[\p{L}\p{N}]+/gu) || []).filter((w) => w.length > 1 && !STOPWORDS.has(w));
}

function metaContent(raw, attr, name) {
  const a = new RegExp(`${attr}=["']${name}["'][^>]*content=["']([^"']+)["']`, 'i');
  const b = new RegExp(`content=["']([^"']+)["'][^>]*${attr}=["']${name}["']`, 'i');
  const m = raw.match(a) || raw.match(b);
  return m?.[1] ? clean(m[1]) : '';
}

function tagText(node) {
  if (!node) return '';
  if (node.type === 'text') return String(node.data || '');
  if (!Array.isArray(node.children)) return '';
  return node.children.map(tagText).join('');
}

/** Registrable label of a host: "blog.talosintelligence.com" -> "talosintelligence". */
export function hostBrandLabel(url) {
  let host = '';
  try {
    host = new URL(String(url || '')).hostname.toLowerCase().replace(/\.+$/, '');
  } catch {
    host = String(url || '').toLowerCase().replace(/^https?:\/\//, '').split(/[/:]/)[0];
  }
  const labels = host.split('.').filter(Boolean);
  if (labels.length < 2) return labels[0] || '';
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  // Two-level public suffixes such as co.uk / com.au / co.jp.
  if (labels.length >= 3 && tld.length === 2 && ['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'or', 'ne'].includes(sld)) {
    return labels[labels.length - 3];
  }
  return sld;
}

function jsonLdItems(raw) {
  const out = [];
  const re = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  for (const m of raw.matchAll(re)) {
    let data;
    try {
      data = JSON.parse(m[1].trim());
    } catch {
      continue;
    }
    const stack = [data];
    while (stack.length) {
      const item = stack.pop();
      if (Array.isArray(item)) stack.push(...item);
      else if (item && typeof item === 'object') {
        out.push(item);
        if (Array.isArray(item['@graph'])) stack.push(...item['@graph']);
      }
    }
  }
  return out;
}

function jsonLdTypeMatches(item) {
  const types = Array.isArray(item['@type']) ? item['@type'] : [item['@type']];
  return types.some((t) => JSONLD_ARTICLE_TYPES.test(String(t || '')));
}

/**
 * Publisher brand names the page declares, plus the host's registrable label.
 * @param {string} raw
 * @param {string} [url]
 */
export function siteBrandNames(html, url) {
  const raw = withoutComments(html);
  const names = [];
  const add = (v) => {
    const c = clean(v);
    if (c && c.length <= 80 && !names.some((n) => norm(n) === norm(c))) names.push(c);
  };
  add(metaContent(raw, 'property', 'og:site_name'));
  add(metaContent(raw, 'name', 'application-name'));
  for (const item of jsonLdItems(raw)) {
    const publisher = item.publisher;
    if (publisher && typeof publisher === 'object' && typeof publisher.name === 'string') add(publisher.name);
    const types = Array.isArray(item['@type']) ? item['@type'] : [item['@type']];
    if (types.some((t) => /^(?:organization|website)$/i.test(String(t || ''))) && typeof item.name === 'string') add(item.name);
  }
  const label = hostBrandLabel(url);
  if (label) add(label);
  return names;
}

function articleHeading(raw) {
  const dom = parseHtml(raw);
  const tag = (el) => String(el?.name || '').toLowerCase();
  const roots = findElements(dom, (el) => tag(el) === 'article' || tag(el) === 'main');
  for (const root of roots) {
    const h1 = findElement(root, (el) => tag(el) === 'h1');
    const text = clean(tagText(h1));
    if (text) return text;
  }
  return '';
}

/**
 * Brand-led: some separator segment (or the whole value) is a site brand,
 * optionally followed by a generic word ("Vendor Blog").
 * @returns {{ brandLed: boolean, rest: string }}
 */
function brandAnalysis(title, brands) {
  const brandKeys = brands.map(norm).filter(Boolean);
  const isBrand = (segment) => {
    const n = norm(segment);
    if (!n) return false;
    if (brandKeys.includes(n)) return true;
    const ws = segment.toLowerCase().trim();
    for (const suffix of GENERIC_BRAND_SUFFIXES) {
      if (ws.endsWith(` ${suffix}`) && brandKeys.includes(norm(ws.slice(0, -suffix.length)))) return true;
    }
    return false;
  };
  const segments = title.split(SEPARATOR_RE).map((s) => s.trim()).filter(Boolean);
  if (segments.length === 1) return { brandLed: isBrand(segments[0]), rest: isBrand(segments[0]) ? '' : title };
  const nonBrand = segments.filter((s) => !isBrand(s));
  return { brandLed: nonBrand.length < segments.length, rest: nonBrand.join(' ') };
}

/**
 * @param {string} html
 * @param {{ url?: string, hint?: string }} [opts]
 * @returns {{ title: string, source: string|null, site_names: string[], rejected: Array<{ source: string, value: string, reason: string }>, version: string }}
 */
export function selectHtmlTitle(html, opts = {}) {
  const raw = withoutComments(html);
  const base = { site_names: [], rejected: [], version: TITLE_SELECTION_VERSION };
  if (opts.hint) return { ...base, title: clean(opts.hint), source: 'hint' };

  const brands = siteBrandNames(raw, opts.url);
  const jsonLdHeadline = (() => {
    for (const item of jsonLdItems(raw)) {
      if (jsonLdTypeMatches(item) && typeof item.headline === 'string' && clean(item.headline)) return clean(item.headline);
    }
    return '';
  })();
  const titleTag = (() => {
    const m = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    return m ? clean(m[1]) : '';
  })();
  const heading = articleHeading(raw);

  const candidates = [
    { source: 'json_ld', value: jsonLdHeadline },
    { source: 'og_title', value: metaContent(raw, 'property', 'og:title') },
    { source: 'twitter_title', value: metaContent(raw, 'name', 'twitter:title') },
    { source: 'title_tag', value: titleTag },
    { source: 'article_h1', value: heading }
  ].filter((c) => c.value);

  const rejected = [];
  for (const candidate of candidates) {
    const { brandLed, rest } = brandAnalysis(candidate.value, brands);
    if (brandLed) {
      // Article-specific evidence: the non-brand part of the other page titles.
      const evidence = candidates
        .filter((c) => c !== candidate && c.value !== candidate.value && ARTICLE_EVIDENCE_SOURCES.has(c.source))
        .map((c) => new Set(words(brandAnalysis(c.value, brands).rest)))
        .filter((set) => set.size > 0);
      const restWords = words(rest);
      const agrees = evidence.some((set) => {
        if (!restWords.length) return false;
        const shared = restWords.filter((w) => set.has(w)).length;
        return shared / restWords.length >= AGREEMENT_RATIO;
      });
      if (evidence.length && !agrees) {
        rejected.push({ source: candidate.source, value: candidate.value, reason: 'site_wide_brand_title' });
        continue;
      }
    }
    return {
      ...base,
      title: candidate.value,
      source: candidate.source,
      site_names: brands.filter((b) => norm(b) !== norm(hostBrandLabel(opts.url))),
      rejected
    };
  }
  // Every candidate was brand-led and contradicted: keep the strongest one.
  const fallback = candidates[0];
  return {
    ...base,
    title: fallback ? fallback.value : '',
    source: fallback ? fallback.source : null,
    site_names: brands.filter((b) => norm(b) !== norm(hostBrandLabel(opts.url))),
    rejected
  };
}

/**
 * Selected report title (string) for an HTML source.
 * @param {string} html
 * @param {string} [hint]
 * @param {{ url?: string }} [opts]
 */
export function extractHtmlTitle(html, hint = '', opts = {}) {
  return selectHtmlTitle(html, { ...opts, hint }).title;
}
