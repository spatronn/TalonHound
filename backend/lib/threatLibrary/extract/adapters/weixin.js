/**
 * Weixin (mp.weixin.qq.com) HTML adapter — static article HTML only.
 * No network, no cookies, no CAPTCHA bypass.
 */

import { createCanonicalDocument, blockId } from '../../canonicalDocument.js';
import {
  decodeEntities,
  extractBlocksFromHtmlFragment,
  extractHtmlLanguage,
  stripTags
} from '../htmlBlocks.js';
import { meaningfulCharCount } from '../quality.js';

/**
 * @param {string} html
 * @returns {string|null} inner HTML of #js_content / rich_media_content
 */
export function findWeixinContentHtml(html) {
  const raw = String(html || '');
  // id="js_content" ... > ... </div> — non-greedy until matching close is hard with regex;
  // Weixin pages typically nest content without nested same-id divs. Use a bounded scan.
  const startRe = /<div\b[^>]*\bid=["']js_content["'][^>]*>/i;
  const start = startRe.exec(raw);
  if (start) {
    const from = start.index + start[0].length;
    const inner = sliceBalancedDivInner(raw, from);
    if (inner && inner.replace(/\s+/g, '').length > 40) return inner;
  }

  const richRe = /<div\b[^>]*\bclass=["'][^"']*rich_media_content[^"']*["'][^>]*>/i;
  const rich = richRe.exec(raw);
  if (rich) {
    const from = rich.index + rich[0].length;
    const inner = sliceBalancedDivInner(raw, from);
    if (inner && inner.replace(/\s+/g, '').length > 40) return inner;
  }

  return null;
}

/**
 * Rough balanced </div> slice starting after an opening div's '>'.
 * @param {string} html
 * @param {number} from
 */
function sliceBalancedDivInner(html, from) {
  let depth = 1;
  let i = from;
  while (i < html.length && depth > 0) {
    const nextOpen = html.toLowerCase().indexOf('<div', i);
    const nextClose = html.toLowerCase().indexOf('</div>', i);
    if (nextClose === -1) return html.slice(from);
    if (nextOpen !== -1 && nextOpen < nextClose) {
      depth += 1;
      i = nextOpen + 4;
      continue;
    }
    depth -= 1;
    if (depth === 0) return html.slice(from, nextClose);
    i = nextClose + 6;
  }
  return html.slice(from);
}

/**
 * @param {string} html
 */
export function extractWeixinTitle(html) {
  const raw = String(html || '');
  const activity =
    raw.match(/id=["']activity-name["'][^>]*>([\s\S]*?)<\//i)
    || raw.match(/<h1\b[^>]*id=["']activity-name["'][^>]*>([\s\S]*?)<\/h1>/i);
  if (activity?.[1]) {
    const t = decodeEntities(stripTags(activity[1])).trim();
    if (t) return t;
  }
  const richTitle = raw.match(/class=["'][^"']*rich_media_title[^"']*["'][^>]*>([\s\S]*?)<\//i);
  if (richTitle?.[1]) {
    const t = decodeEntities(stripTags(richTitle[1])).trim();
    if (t) return t;
  }
  const og =
    raw.match(/property=["']og:title["'][^>]*content=["']([^"']+)["']/i)
    || raw.match(/content=["']([^"']+)["'][^>]*property=["']og:title["']/i);
  if (og?.[1]) return decodeEntities(og[1]).trim();
  const titleMatch = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleMatch) {
    let t = decodeEntities(stripTags(titleMatch[1])).trim();
    // Weixin titles often append " - 微信公众平台"
    t = t.replace(/\s*[-|].*微信.*/u, '').trim();
    if (t) return t;
  }
  return '';
}

/**
 * @param {string} html
 * @param {{ url?: string }} [meta]
 */
export function extractWeixinDocument(html, meta = {}) {
  const contentHtml = findWeixinContentHtml(html);
  if (!contentHtml) {
    return {
      ok: false,
      document: null,
      reason: 'weixin_content_missing'
    };
  }

  const blocks = extractBlocksFromHtmlFragment(contentHtml, { blockId });
  const imgAltRe = /<img\b[^>]*\balt=["']([^"']{3,200})["'][^>]*>/gi;
  let m;
  while ((m = imgAltRe.exec(contentHtml)) !== null) {
    const alt = decodeEntities(m[1]).replace(/\s+/g, ' ').trim();
    if (alt && !blocks.some((b) => b.text === alt)) {
      blocks.push({
        id: blockId('b', blocks.length + 1),
        type: 'caption',
        text: alt,
        page: null,
        section: null
      });
    }
  }

  const title = extractWeixinTitle(html) || 'Untitled';
  let language = extractHtmlLanguage(html);
  if (!language) {
    // Heuristic: CJK density in content
    const sample = blocks.map((b) => b.text).join('').slice(0, 400);
    const cjk = (sample.match(/[\u4e00-\u9fff]/g) || []).length;
    if (cjk >= 8) language = 'zh';
  }

  const document = createCanonicalDocument({
    title,
    language,
    blocks,
    meta: {
      source_url: meta.url || null,
      extractor: 'threat_library_weixin_v1',
      adapter: 'weixin'
    }
  });

  if (meaningfulCharCount(document) < 40 || blocks.length === 0) {
    return { ok: false, document, reason: 'weixin_content_too_thin' };
  }

  return { ok: true, document, reason: null };
}
