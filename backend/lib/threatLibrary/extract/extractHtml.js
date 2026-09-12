/**
 * Layered HTML → canonical document extraction for Threat Library.
 *
 * Flow:
 *   classify page
 *   → Weixin adapter (when host matches)
 *   → generic article/main/body extractor
 *   → structured content-root fallback
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
  cleanNoiseHtml,
  extractBlocksFromHtmlFragment,
  extractHtmlLanguage,
  extractHtmlTitle
} from './htmlBlocks.js';
import { extractWeixinDocument } from './adapters/weixin.js';

/**
 * Primary generic extractor (article → main → body).
 * @param {string} html
 * @param {{ url?: string, titleHint?: string }} [meta]
 */
export function extractGenericArticleDocument(html, meta = {}) {
  const raw = String(html || '');
  const title = extractHtmlTitle(raw, meta.titleHint);
  let body = raw;
  const articleMatch = raw.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i);
  const mainMatch = raw.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i);
  if (articleMatch) body = articleMatch[1];
  else if (mainMatch) body = mainMatch[1];
  else {
    const bodyMatch = raw.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
    if (bodyMatch) body = bodyMatch[1];
    // Strip site chrome headers when falling back to full body
    body = body.replace(/<header\b[\s\S]*?<\/header>/gi, ' ');
  }

  const blocks = extractBlocksFromHtmlFragment(body, { blockId });
  return createCanonicalDocument({
    title: title || 'Untitled',
    language: extractHtmlLanguage(raw),
    blocks,
    meta: {
      source_url: meta.url || null,
      extractor: 'threat_library_html_v1',
      adapter: 'generic_html'
    }
  });
}

/**
 * Structured DOM fallback: content-like containers when article/main empty.
 * @param {string} html
 * @param {{ url?: string, titleHint?: string }} [meta]
 */
export function extractStructuredFallbackDocument(html, meta = {}) {
  const raw = String(html || '');
  const title = extractHtmlTitle(raw, meta.titleHint);
  const candidates = [];

  const patterns = [
    /<(?:div|section)\b[^>]*(?:id|class)=["'][^"']*(?:article-body|post-content|entry-content|article_content|content-body|story-body|main-content)[^"']*["'][^>]*>([\s\S]*?)<\/(?:div|section)>/i,
    /<(?:div|section)\b[^>]*itemprop=["']articleBody["'][^>]*>([\s\S]*?)<\/(?:div|section)>/i,
    /<(?:div|section)\b[^>]*role=["']main["'][^>]*>([\s\S]*?)<\/(?:div|section)>/i
  ];

  for (const re of patterns) {
    const m = raw.match(re);
    if (m?.[1]) candidates.push(m[1]);
  }

  let bestBlocks = [];
  let bestScore = 0;
  for (const frag of candidates) {
    const blocks = extractBlocksFromHtmlFragment(frag, { blockId });
    const score = blocks.map((b) => (b.text || '').replace(/\s+/g, '').length).reduce((a, b) => a + b, 0);
    if (score > bestScore) {
      bestScore = score;
      bestBlocks = blocks;
    }
  }

  // Last resort: cleaned body text density — only if substantial
  if (bestBlocks.length === 0) {
    const bodyMatch = raw.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
    const body = cleanNoiseHtml(bodyMatch ? bodyMatch[1] : raw)
      .replace(/<header\b[\s\S]*?<\/header>/gi, ' ')
      .replace(/<aside\b[\s\S]*?<\/aside>/gi, ' ');
    bestBlocks = extractBlocksFromHtmlFragment(body, { blockId });
  }

  return createCanonicalDocument({
    title: title || 'Untitled',
    language: extractHtmlLanguage(raw),
    blocks: bestBlocks,
    meta: {
      source_url: meta.url || null,
      extractor: 'threat_library_html_fallback_v1',
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
