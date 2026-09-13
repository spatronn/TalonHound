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
  extractHtmlTitle,
  findElement,
  findElements,
  parseHtml,
  HTML_BLOCKS_VERSION
} from './htmlBlocks.js';
import { extractWeixinDocument, WEIXIN_EXTRACTOR_VERSION } from './adapters/weixin.js';

export const THREAT_LIBRARY_HTML_EXTRACTOR_VERSION = HTML_BLOCKS_VERSION;
export const THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION = 'threat_library_html_fallback_v2';

/** Every extractor id a stored URL-sourced canonical document may carry and still be current. */
export const CURRENT_HTML_EXTRACTOR_VERSIONS = Object.freeze([
  THREAT_LIBRARY_HTML_EXTRACTOR_VERSION,
  THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION,
  WEIXIN_EXTRACTOR_VERSION,
  'threat_library_text_v2'
]);

const tagOf = (el) => String(el?.name || '').toLowerCase();

/**
 * Primary generic extractor (article → main → body).
 * @param {string} html
 * @param {{ url?: string, titleHint?: string }} [meta]
 */
export function extractGenericArticleDocument(html, meta = {}) {
  const raw = String(html || '');
  const title = extractHtmlTitle(raw, meta.titleHint);
  const dom = parseHtml(raw);
  const article = findElement(dom, (el) => tagOf(el) === 'article');
  const main = article ? null : findElement(dom, (el) => tagOf(el) === 'main');
  let root = article || main;
  let skipTags;
  if (!root) {
    root = findElement(dom, (el) => tagOf(el) === 'body') || dom;
    // Strip site chrome headers when falling back to full body
    skipTags = new Set(['header']);
  }

  const blocks = extractBlocksFromNode(root, { blockId }, { skipTags });
  return createCanonicalDocument({
    title: title || 'Untitled',
    language: extractHtmlLanguage(raw),
    blocks,
    meta: {
      source_url: meta.url || null,
      extractor: THREAT_LIBRARY_HTML_EXTRACTOR_VERSION,
      adapter: 'generic_html'
    }
  });
}

const CONTENT_ROOT_HINT_RE = /(article-body|post-content|entry-content|article_content|content-body|story-body|main-content)/i;

/**
 * Structured DOM fallback: content-like containers when article/main empty.
 * @param {string} html
 * @param {{ url?: string, titleHint?: string }} [meta]
 */
export function extractStructuredFallbackDocument(html, meta = {}) {
  const raw = String(html || '');
  const title = extractHtmlTitle(raw, meta.titleHint);
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
  for (const el of candidates) {
    const blocks = extractBlocksFromNode(el, { blockId });
    const score = blocks.map((b) => (b.text || '').replace(/\s+/g, '').length).reduce((a, b) => a + b, 0);
    if (score > bestScore) {
      bestScore = score;
      bestBlocks = blocks;
    }
  }

  // Last resort: cleaned body text density — only if substantial
  if (bestBlocks.length === 0) {
    const body = findElement(dom, (el) => tagOf(el) === 'body') || dom;
    bestBlocks = extractBlocksFromNode(body, { blockId }, { skipTags: new Set(['header', 'aside']) });
  }

  return createCanonicalDocument({
    title: title || 'Untitled',
    language: extractHtmlLanguage(raw),
    blocks: bestBlocks,
    meta: {
      source_url: meta.url || null,
      extractor: THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION,
      adapter: 'structured_fallback'
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

  if (!document || meaningfulCharCount(document) < 40) {
    path.push('structured_fallback');
    const fallback = extractStructuredFallbackDocument(html, {
      url: ctx.url || ctx.finalUrl,
      titleHint: ctx.titleHint
    });
    if (!document || meaningfulCharCount(fallback) > meaningfulCharCount(document)) {
      document = fallback;
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
