/**
 * Layered HTML → canonical document extraction for Threat Library.
 *
 * Flow:
 *   classify page
 *   → Weixin adapter (when host matches)
 *   → generic article/main/body extractor (DOM)
 *   → structured content-root fallback (DOM)
 *   → quality gate
 */

import { createCanonicalDocument, blockId } from '../canonicalDocument.js';
import {
  classifyFetchedHtmlPage,
  hostnameOf,
  isWeixinHost
} from './classifySourcePage.js';
import { assessDocumentQuality, meaningfulCharCount } from './quality.js';
import {
  extractBlocksFromNode,
  extractHtmlLanguage,
  findElement,
  findElements,
  parseHtml
} from './htmlBlocks.js';
import { extractWeixinDocument, WEIXIN_EXTRACTOR_VERSION } from './adapters/weixin.js';
import { selectHtmlTitle } from './titleSelection.js';

/**
 * Document-level HTML extractor contract. Bumped independently of
 * htmlBlocks.HTML_BLOCKS_VERSION when content-root selection / layered
 * fallback policy changes so Refresh rebuilds retained URL HTML under the
 * new rules.
 * v6: score article/main roots; prefer denser main over thin card articles;
 * always compare structured content-root fallback against thin incumbents.
 */
// v7: structured block.links from htmlBlocks v7 (destination-only href anchors).
// v8: tables nested behind inline wrappers inside <p> stay table blocks (htmlBlocks v8).
// v9: tables nested behind inline wrappers inside a heading stay table blocks (htmlBlocks v9).
export const THREAT_LIBRARY_HTML_EXTRACTOR_VERSION = 'threat_library_html_v9';
export const THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION = 'threat_library_html_fallback_v4';

/** Every extractor id a stored URL-sourced canonical document may carry and still be current. */
export const CURRENT_HTML_EXTRACTOR_VERSIONS = Object.freeze([
  THREAT_LIBRARY_HTML_EXTRACTOR_VERSION,
  THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION,
  WEIXIN_EXTRACTOR_VERSION,
  'threat_library_text_v2'
]);

const tagOf = (el) => String(el?.name || '').toLowerCase();

/**
 * Non-whitespace character mass of extracted blocks — used to pick among
 * competing article/main/content-root candidates.
 * @param {import('../canonicalDocument.js').CanonicalBlock[]} blocks
 */
function blockCharMass(blocks) {
  return (blocks || [])
    .map((b) => String(b.text || '').replace(/\s+/g, ''))
    .join('').length;
}

/**
 * Prefer a denser content root when the first `<article>` is a thin card /
 * teaser (common on modern blog themes that reuse `<article>` for related
 * posts) while the real body lives under `<main>` or an entry-content div.
 *
 * Use main / denser sibling when it is at least 2× the thin candidate and at
 * least `minDelta` characters larger — enough to reject chrome-only cards
 * without displacing a real article that happens to sit inside a slightly
 * larger main wrapper.
 */
const THIN_ROOT_MIN_RATIO = 2;
const THIN_ROOT_MIN_DELTA = 200;

/**
 * @param {{ score: number, blocks: object[], kind: string }[]} scored
 * @returns {{ score: number, blocks: object[], kind: string }|null}
 */
export function pickBestContentRoot(scored) {
  if (!scored?.length) return null;
  const ranked = [...scored].sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    // Tie-break: prefer semantic article → main → other
    const rank = { article: 0, main: 1, content_hint: 2, body: 3 };
    return (rank[a.kind] ?? 9) - (rank[b.kind] ?? 9);
  });
  const best = ranked[0];
  const mainAlt = ranked.find((c) => c.kind === 'main');
  const articleAlt = ranked.find((c) => c.kind === 'article');

  // Thin card/teaser <article> under a much denser <main>: use main.
  if (
    best.kind === 'article'
    && mainAlt
    && mainAlt.score >= best.score * THIN_ROOT_MIN_RATIO
    && mainAlt.score >= best.score + THIN_ROOT_MIN_DELTA
  ) {
    return mainAlt;
  }

  // Dense <main> that only slightly outscores a real <article>: keep article
  // to avoid sidebar/TOC chrome that rides along with <main>.
  if (
    best.kind === 'main'
    && articleAlt
    && !(
      best.score >= articleAlt.score * THIN_ROOT_MIN_RATIO
      && best.score >= articleAlt.score + THIN_ROOT_MIN_DELTA
    )
  ) {
    return articleAlt;
  }

  return best;
}

/**
 * Whether a competing extraction is substantially denser than the current one
 * (thin chrome / card vs real article body).
 * @param {number} challengerChars
 * @param {number} incumbentChars
 */
export function isSubstantiallyDenser(challengerChars, incumbentChars) {
  const c = Number(challengerChars) || 0;
  const i = Number(incumbentChars) || 0;
  return c >= i * THIN_ROOT_MIN_RATIO && c >= i + THIN_ROOT_MIN_DELTA;
}

/**
 * Provenance of the selected title, recorded only when it carries information
 * (a declared site name, or a rejected site-wide brand title).
 * @param {ReturnType<typeof selectHtmlTitle>} selection
 */
export function titleMeta(selection) {
  const out = {};
  if (selection.site_names?.length) out.site_names = selection.site_names.slice(0, 5);
  if (selection.rejected?.length) {
    out.title_selection = {
      version: selection.version,
      source: selection.source,
      rejected: selection.rejected.slice(0, 4)
    };
  }
  return out;
}

/**
 * Primary generic extractor (article → main → body).
 * Scores every `<article>` and `<main>` and picks the densest root so thin
 * card/teaser `<article>` elements (related posts, hero cards) do not eclipse
 * the real post body under `<main>`.
 * @param {string} html
 * @param {{ url?: string, titleHint?: string }} [meta]
 */
export function extractGenericArticleDocument(html, meta = {}) {
  const raw = String(html || '');
  const selection = selectHtmlTitle(raw, { url: meta.url, hint: meta.titleHint });
  const title = selection.title;
  const dom = parseHtml(raw);

  /** @type {{ score: number, blocks: object[], kind: string }[]} */
  const scored = [];
  const blockOpts = { baseUrl: meta.url || null };
  for (const el of findElements(dom, (n) => tagOf(n) === 'article')) {
    const blocks = extractBlocksFromNode(el, { blockId }, blockOpts);
    scored.push({ score: blockCharMass(blocks), blocks, kind: 'article' });
  }
  for (const el of findElements(dom, (n) => tagOf(n) === 'main')) {
    const blocks = extractBlocksFromNode(el, { blockId }, blockOpts);
    scored.push({ score: blockCharMass(blocks), blocks, kind: 'main' });
  }

  let chosen = pickBestContentRoot(scored);
  let skipTags;
  if (!chosen || chosen.score < 40) {
    const body = findElement(dom, (el) => tagOf(el) === 'body') || dom;
    // Strip site chrome headers when falling back to full body
    skipTags = new Set(['header']);
    const blocks = extractBlocksFromNode(body, { blockId }, { ...blockOpts, skipTags });
    chosen = { score: blockCharMass(blocks), blocks, kind: 'body' };
  }

  return createCanonicalDocument({
    title: title || 'Untitled',
    language: extractHtmlLanguage(raw),
    blocks: chosen.blocks,
    meta: {
      source_url: meta.url || null,
      extractor: THREAT_LIBRARY_HTML_EXTRACTOR_VERSION,
      adapter: 'generic_html',
      content_root: chosen.kind,
      ...titleMeta(selection)
    }
  });
}

const CONTENT_ROOT_HINT_RE = /(article-body|post-content|entry-content|article_content|content-body|story-body|main-content|wp-block-post-content)/i;

/**
 * Structured DOM fallback: content-like containers when article/main empty.
 * @param {string} html
 * @param {{ url?: string, titleHint?: string }} [meta]
 */
export function extractStructuredFallbackDocument(html, meta = {}) {
  const raw = String(html || '');
  const selection = selectHtmlTitle(raw, { url: meta.url, hint: meta.titleHint });
  const title = selection.title;
  const dom = parseHtml(raw);

  const candidates = findElements(dom, (el) => {
    const tag = tagOf(el);
    if (tag !== 'div' && tag !== 'section') return false;
    const a = el.attribs || {};
    return (
      CONTENT_ROOT_HINT_RE.test(String(a.id || '')) ||
      CONTENT_ROOT_HINT_RE.test(String(a.class || '')) ||
      String(a.itemprop || '').toLowerCase() === 'articlebody' ||
      String(a.role || '').toLowerCase() === 'main'
    );
  });

  let bestBlocks = [];
  let bestScore = 0;
  const blockOpts = { baseUrl: meta.url || null };
  for (const el of candidates) {
    const blocks = extractBlocksFromNode(el, { blockId }, blockOpts);
    const score = blocks.map((b) => (b.text || '').replace(/\s+/g, '').length).reduce((a, b) => a + b, 0);
    if (score > bestScore) {
      bestScore = score;
      bestBlocks = blocks;
    }
  }

  // Last resort: cleaned body text density — only if substantial
  if (bestBlocks.length === 0) {
    const body = findElement(dom, (el) => tagOf(el) === 'body') || dom;
    bestBlocks = extractBlocksFromNode(body, { blockId }, { ...blockOpts, skipTags: new Set(['header', 'aside']) });
  }

  return createCanonicalDocument({
    title: title || 'Untitled',
    language: extractHtmlLanguage(raw),
    blocks: bestBlocks,
    meta: {
      source_url: meta.url || null,
      extractor: THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION,
      adapter: 'structured_fallback',
      ...titleMeta(selection)
    }
  });
}

/**
 * Full layered extraction after a safe fetch.
 *
 * @param {string} html
 * @param {{
 *   url?: string,
 *   finalUrl?: string,
 *   httpStatus?: number,
 *   titleHint?: string
 * }} [ctx]
 * @returns {{
 *   ok: boolean,
 *   document?: import('../canonicalDocument.js').CanonicalDocument,
 *   code?: string,
 *   message?: string,
 *   classification?: object,
 *   path?: string[],
 *   quality?: object
 * }}
 */
export function extractCanonicalDocumentFromHtml(html, ctx = {}) {
  const path = [];
  const classification = classifyFetchedHtmlPage({
    finalUrl: ctx.finalUrl || ctx.url,
    bodyText: html,
    httpStatus: ctx.httpStatus
  });

  if (classification.kind === 'verification_required'
    || classification.kind === 'access_denied'
    || classification.kind === 'blocked') {
    return {
      ok: false,
      code: classification.code,
      message: classification.message,
      classification,
      path: ['classify']
    };
  }

  const host = hostnameOf(ctx.finalUrl || ctx.url);
  let document = null;

  if (isWeixinHost(host) || /mp\.weixin\.qq\.com/i.test(String(ctx.finalUrl || ctx.url || ''))) {
    path.push('weixin_adapter');
    const wx = extractWeixinDocument(html, { url: ctx.url || ctx.finalUrl });
    if (wx.ok) {
      document = wx.document;
      path.push('weixin_ok');
    } else {
      path.push(`weixin_${wx.reason || 'miss'}`);
    }
  }

  if (!document || meaningfulCharCount(document) < 40) {
    path.push('generic_html');
    const generic = extractGenericArticleDocument(html, {
      url: ctx.url || ctx.finalUrl,
      titleHint: ctx.titleHint
    });
    if (!document || meaningfulCharCount(generic) > meaningfulCharCount(document)) {
      document = generic;
    }
  }

  // Always score structured content-root fallback against the incumbent.
  // Thin card/teaser `<article>` nodes often clear the 40-char gate while the
  // real body lives in entry-content / post-content containers — without this
  // comparison those pages silently succeed with chrome-only documents.
  {
    path.push('structured_fallback');
    const fallback = extractStructuredFallbackDocument(html, {
      url: ctx.url || ctx.finalUrl,
      titleHint: ctx.titleHint
    });
    const incumbentChars = meaningfulCharCount(document);
    const fallbackChars = meaningfulCharCount(fallback);
    const preferFallback =
      !document
      || incumbentChars < 40
      || isSubstantiallyDenser(fallbackChars, incumbentChars);
    if (preferFallback && fallbackChars > incumbentChars) {
      document = fallback;
      path.push('structured_fallback_preferred');
    }
  }

  // JS shell after failed extraction
  if (classification.kind === 'js_shell' && meaningfulCharCount(document) < 40) {
    return {
      ok: false,
      code: classification.code,
      message: classification.message,
      classification,
      path,
      document
    };
  }

  const quality = assessDocumentQuality(document);
  path.push(quality.ok ? 'quality_ok' : `quality_${quality.code}`);

  if (!quality.ok) {
    // Prefer more precise empty vs quality codes; keep legacy alias for callers
    return {
      ok: false,
      code: quality.code,
      message: quality.message,
      classification,
      path,
      quality,
      document
    };
  }

  return {
    ok: true,
    document,
    classification,
    path,
    quality
  };
}

// Back-compat export used by existing tests/call sites
export { extractGenericArticleDocument as htmlToCanonicalDocumentLegacy };
