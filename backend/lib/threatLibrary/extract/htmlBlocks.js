/**
 * Shared HTML → ordered canonical blocks (headings, paragraphs, lists, code,
 * tables) built from a real DOM (htmlparser2), in document order.
 *
 * v2: tables survive as structured `table` blocks (headers / rows / cells with
 * rendered cell text in DOM order) instead of one flat block per <td>; text
 * that sits directly inside containers (<div>text<br>text</div>) is kept; a
 * nested element is emitted once (the regex extractor duplicated <p> inside
 * <section>).
 */

import { parseDocument } from 'htmlparser2';
import { createTableBlock } from '../canonicalDocument.js';

export const HTML_BLOCKS_VERSION = 'threat_library_html_v2';

export function stripTags(s) {
  return String(s || '').replace(/<[^>]+>/g, ' ');
}

export function decodeEntities(s) {
  return String(s || '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/** Kept for callers that pre-clean raw HTML strings (adapters, tests). */
export function cleanNoiseHtml(html) {
  return String(html || '')
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg\b[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<nav\b[\s\S]*?<\/nav>/gi, ' ')
    .replace(/<footer\b[\s\S]*?<\/footer>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');
}

/** Elements whose subtree is never content. */
const NOISE_TAGS = new Set(['script', 'style', 'noscript', 'svg', 'nav', 'footer', 'template', 'iframe', 'head', 'canvas', 'video', 'audio', 'object', 'embed', 'select', 'option', 'button', 'input', 'textarea']);
const HEADING_TAGS = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
const PARAGRAPH_TAGS = new Set(['p', 'blockquote', 'dd', 'dt', 'address', 'summary']);
const CAPTION_TAGS = new Set(['caption', 'figcaption']);
/** Containers we descend into; direct text inside them forms paragraphs. */
const CONTAINER_TAGS = new Set(['div', 'section', 'article', 'main', 'body', 'html', 'aside', 'header', 'details', 'figure', 'form', 'fieldset', 'center', 'font', 'span', 'label', 'legend', 'hgroup', 'ul', 'ol', 'dl', 'menu', 'li', 'tbody', 'thead', 'tfoot', 'tr', 'td', 'th']);

/**
 * @param {string} html
 */
export function parseHtml(html) {
  return parseDocument(String(html || ''), { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true });
}

function isElement(node) {
  return node && node.type === 'tag';
}

function tagOf(node) {
  return isElement(node) ? String(node.name || '').toLowerCase() : '';
}

function attr(node, name) {
  return node && node.attribs ? node.attribs[name] : undefined;
}

/**
 * Depth-first search for the first element matching `pred`.
 * @param {object} node
 * @param {(el: object) => boolean} pred
 */
export function findElement(node, pred) {
  if (!node) return null;
  if (isElement(node) && pred(node)) return node;
  for (const child of node.children || []) {
    const hit = findElement(child, pred);
    if (hit) return hit;
  }
  return null;
}

/**
 * All elements matching `pred` (document order).
 * @param {object} node
 * @param {(el: object) => boolean} pred
 * @param {object[]} [out]
 */
export function findElements(node, pred, out = []) {
  if (!node) return out;
  if (isElement(node) && pred(node)) out.push(node);
  for (const child of node.children || []) findElements(child, pred, out);
  return out;
}

/**
 * Rendered text of a node (inline order, <br> → space, noise skipped).
 * @param {object} node
 */
export function textOf(node) {
  const parts = [];
  const walk = (n) => {
    if (!n) return;
    if (n.type === 'text') {
      parts.push(String(n.data || ''));
      return;
    }
    if (!isElement(n)) return;
    const tag = tagOf(n);
    if (NOISE_TAGS.has(tag)) return;
    if (tag === 'br') {
      parts.push(' ');
      return;
    }
    if (tag === 'img') return;
    const block = HEADING_TAGS.has(tag) || PARAGRAPH_TAGS.has(tag) || tag === 'li' || tag === 'tr' || tag === 'div' || tag === 'pre';
    if (block) parts.push(' ');
    for (const c of n.children || []) walk(c);
    if (block || tag === 'td' || tag === 'th') parts.push(' ');
  };
  walk(node);
  return parts.join('').replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Rows of a <table> as cell text (DOM order). Nested tables flatten into their cell.
 * @param {object} tableEl
 * @returns {{ headers: string[]|null, rows: string[][], caption: string|null }}
 */
export function tableToRows(tableEl) {
  const rows = [];
  let headers = null;
  let caption = null;
  const trs = [];
  const collectRows = (n, inHead) => {
    for (const child of n.children || []) {
      if (!isElement(child)) continue;
      const tag = tagOf(child);
      if (tag === 'caption') {
        caption = textOf(child) || caption;
      } else if (tag === 'thead') {
        collectRows(child, true);
      } else if (tag === 'tbody' || tag === 'tfoot') {
        collectRows(child, inHead);
      } else if (tag === 'tr') {
        trs.push({ el: child, inHead });
      } else if (tag !== 'table' && tag !== 'colgroup' && tag !== 'col') {
        collectRows(child, inHead);
      }
    }
  };
  collectRows(tableEl, false);
  for (const { el, inHead } of trs) {
    const cells = [];
    let allTh = true;
    for (const child of el.children || []) {
      if (!isElement(child)) continue;
      const tag = tagOf(child);
      if (tag !== 'td' && tag !== 'th') continue;
      if (tag !== 'th') allTh = false;
      cells.push(textOf(child));
    }
    if (!cells.length) continue;
    if (!headers && !rows.length && (inHead || allTh) && cells.some((c) => c)) {
      headers = cells;
      continue;
    }
    rows.push(cells);
  }
  return { headers, rows, caption };
}

/**
 * Extract ordered blocks from an HTML fragment (or full document).
 * @param {string} fragmentHtml
 * @param {{ blockId: (prefix: string, index: number) => string }} ids
 * @param {{ skipTags?: Set<string> }} [opts]
 */
export function extractBlocksFromHtmlFragment(fragmentHtml, ids, opts = {}) {
  const dom = parseHtml(fragmentHtml);
  return extractBlocksFromNode(dom, ids, opts);
}

/**
 * @param {object} root parsed node (document or element)
 * @param {{ blockId: (prefix: string, index: number) => string }} ids
 * @param {{ skipTags?: Set<string> }} [opts]
 */
export function extractBlocksFromNode(root, ids, opts = {}) {
  const blocks = [];
  const skip = opts.skipTags || new Set();
  let idx = 1;
  let currentSection = null;
  const push = (type, text, extra = {}) => {
    const t = String(text || '').replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim();
    if (!t || t.length < 2) return null;
    const block = {
      id: ids.blockId('b', idx++),
      type,
      text: t,
      page: null,
      section: currentSection,
      ...extra
    };
    blocks.push(block);
    return block;
  };

  /** Pending inline text collected directly inside a container. */
  let pending = [];
  const flushPending = () => {
    if (!pending.length) return;
    const text = pending.join('');
    pending = [];
    push('paragraph', text);
  };

  const walk = (node) => {
    if (!node) return;
    if (node.type === 'text') {
      pending.push(String(node.data || ''));
      return;
    }
    if (!isElement(node)) {
      if (node.type === 'root') for (const c of node.children || []) walk(c);
      return;
    }
    const tag = tagOf(node);
    if (NOISE_TAGS.has(tag) || skip.has(tag)) return;

    if (HEADING_TAGS.has(tag)) {
      flushPending();
      const text = textOf(node);
      currentSection = text.slice(0, 200) || currentSection;
      // DOM hierarchy (h1–h6) lets zone scoping tell a nested sub-label from a sibling section.
      push('heading', text, { level: Number(tag.slice(1)) });
      return;
    }
    if (PARAGRAPH_TAGS.has(tag)) {
      flushPending();
      // A paragraph may still wrap block children (lists, tables inside <blockquote>).
      const hasBlockChild = (node.children || []).some((c) => isElement(c) && (tagOf(c) === 'table' || tagOf(c) === 'ul' || tagOf(c) === 'ol' || tagOf(c) === 'pre'));
      if (!hasBlockChild) {
        push('paragraph', textOf(node));
        return;
      }
      for (const c of node.children || []) walk(c);
      flushPending();
      return;
    }
    if (tag === 'pre' || (tag === 'code' && !pending.join('').trim())) {
      flushPending();
      push('code', textOf(node));
      return;
    }
    if (CAPTION_TAGS.has(tag)) {
      flushPending();
      push('caption', textOf(node));
      return;
    }
    if (tag === 'table') {
      flushPending();
      const t = tableToRows(node);
      if (t.caption) push('caption', t.caption);
      const width = Math.max(t.headers ? t.headers.length : 0, ...t.rows.map((r) => r.length), 0);
      if (width >= 2) {
        const block = createTableBlock({
          id: ids.blockId('b', idx),
          headers: t.headers,
          rows: t.rows,
          caption: t.caption,
          section: currentSection,
          source: 'html_dom'
        });
        if (block) {
          blocks.push(block);
          idx += 1;
        }
      } else {
        // Single-column table: each row is an indicator-list style row.
        if (t.headers) push('table', t.headers.join(' '));
        for (const r of t.rows) push('table', r.join(' '));
      }
      return;
    }
    if (tag === 'li') {
      flushPending();
      // Own inline text first, then nested lists / blocks as their own blocks.
      const inline = [];
      const nested = [];
      for (const c of node.children || []) {
        if (isElement(c) && ['ul', 'ol', 'table', 'pre', 'p', 'div', 'blockquote'].includes(tagOf(c))) nested.push(c);
        else inline.push(c);
      }
      push('list', textOf({ type: 'tag', name: 'span', children: inline }));
      for (const c of nested) walk(c);
      flushPending();
      return;
    }
    if (tag === 'br') {
      pending.push(' ');
      return;
    }
    if (tag === 'img') return;
    if (tag === 'hr') {
      flushPending();
      return;
    }
    // Inline element: its children join the pending run verbatim (author
    // whitespace preserved, so a value split across <span>s stays intact).
    if (!CONTAINER_TAGS.has(tag) && tag !== 'table' && tag !== 'tr' && tag !== 'td' && tag !== 'th') {
      for (const c of node.children || []) walk(c);
      return;
    }
    // Container: text directly inside forms paragraphs between block children.
    flushPending();
    for (const c of node.children || []) walk(c);
    flushPending();
  };

  walk(root);
  flushPending();

  if (blocks.length === 0) {
    const fallback = textOf(root);
    if (fallback) {
      for (let i = 0; i < fallback.length; i += 800) {
        push('paragraph', fallback.slice(i, i + 800));
      }
    }
  }
  return blocks;
}

/**
 * Pick best title from HTML meta / tags.
 * @param {string} html
 * @param {string} [hint]
 */
export function extractHtmlTitle(html, hint = '') {
  const raw = String(html || '');
  if (hint) return decodeEntities(stripTags(hint)).trim();
  const og =
    raw.match(/property=["']og:title["'][^>]*content=["']([^"']+)["']/i)
    || raw.match(/content=["']([^"']+)["'][^>]*property=["']og:title["']/i);
  if (og?.[1]) return decodeEntities(og[1]).trim();
  const tw =
    raw.match(/name=["']twitter:title["'][^>]*content=["']([^"']+)["']/i)
    || raw.match(/content=["']([^"']+)["'][^>]*name=["']twitter:title["']/i);
  if (tw?.[1]) return decodeEntities(tw[1]).trim();
  const titleMatch = raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (titleMatch) return decodeEntities(stripTags(titleMatch[1])).trim();
  return '';
}

/**
 * @param {string} html
 */
export function extractHtmlLanguage(html) {
  const raw = String(html || '');
  const htmlLang = raw.match(/<html[^>]*\slang=["']?([a-zA-Z-]{2,10})/i);
  if (htmlLang) return htmlLang[1].toLowerCase().slice(0, 16);
  const ogLocale = raw.match(/property=["']og:locale["'][^>]*content=["']([^"']+)["']/i);
  if (ogLocale?.[1]) return String(ogLocale[1]).toLowerCase().replace('_', '-').slice(0, 16);
  return null;
}
