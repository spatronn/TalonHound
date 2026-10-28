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

/**
 * v3: `<br>` is a line boundary — a paragraph / container run / list item
 * with several visual lines becomes one block per line (shared `line_group`),
 * so row and list detection read each line as the publisher laid it out.
 * v4: `<pre>` / standalone `<code>` keep author newlines (and `<br>`) as line
 * boundaries. Flattening them to one whitespace-collapsed line destroyed
 * publisher IOC appendices written as "filename HASH" rows inside fenced
 * code blocks.
 * v5: real heading elements nested inside list items (`<ul><li><h3>…`)
 * emit as `heading` blocks with their DOM level instead of flattening into
 * list text — appendix subgroup labels such as "C2" keep heading semantics.
 * v6: Cloudflare-obfuscated addresses (`data-cfemail`, rendered "[email
 * protected]") are decoded to the publisher's text before parsing.
 * v7: hyperlinks inside content blocks are preserved as structured
 * `links: [{ href, text }]` so destination-only anchors ("can be found here")
 * remain available to section-tree authority and IOC Source discovery.
 * v8: a table / list / pre nested behind inline wrappers inside a paragraph
 * (`<p><span style><table>`) is emitted as its own block instead of being
 * flattened into paragraph text (the rows lost their cell boundaries).
 * v9: the same nesting behind a heading element (`<h3><span><table>`) emits
 * the heading's own inline text (if any) and the table as its own block; the
 * table rows were flattened into one heading block.
 * Document extractor contract is threat_library_html_v9 so Refresh rebuilds
 * retained HTML under the nested-table contract.
 */
export const HTML_BLOCKS_VERSION = 'threat_library_html_v9';

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

/** Cloudflare email obfuscation: `<a|span … data-cfemail="HEX">[email protected]</a|span>`. */
const CF_EMAIL_ELEMENT_RE = /<(a|span)\b([^>]*?)\bdata-cfemail\s*=\s*["']([0-9a-f]+)["']([^>]*)>[\s\S]*?<\/\1\s*>/gi;
const EMAIL_SHAPE_RE = /^[^\s@<>"'&]+@[^\s@<>"'&]+$/;

/**
 * Decode one Cloudflare `data-cfemail` payload: the first byte is the XOR key
 * of the remaining bytes. Returns null when the result is not an address.
 * @param {string} hex
 */
export function decodeCloudflareEmail(hex) {
  const h = String(hex || '');
  if (h.length < 4 || h.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(h)) return null;
  const key = parseInt(h.slice(0, 2), 16);
  let out = '';
  for (let i = 2; i < h.length; i += 2) out += String.fromCharCode(parseInt(h.slice(i, i + 2), 16) ^ key);
  return EMAIL_SHAPE_RE.test(out) ? out : null;
}

/**
 * Restore the publisher's text where Cloudflare replaced an address with
 * "[email protected]" (the real value is only in `data-cfemail`). Anything
 * that does not decode to an address is left untouched.
 * @param {string} html
 */
export function decodeCloudflareEmails(html) {
  const s = String(html || '');
  if (!/data-cfemail/i.test(s)) return s;
  return s.replace(CF_EMAIL_ELEMENT_RE, (whole, _tag, _a, hex) => {
    const email = decodeCloudflareEmail(hex);
    return email ? email.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') : whole;
  });
}

/**
 * @param {string} html
 */
export function parseHtml(html) {
  return parseDocument(decodeCloudflareEmails(html), { decodeEntities: true, lowerCaseTags: true, lowerCaseAttributeNames: true });
}

function isElement(node) {
  return node && node.type === 'tag';
}

function tagOf(node) {
  return isElement(node) ? String(node.name || '').toLowerCase() : '';
}

const NESTED_BLOCK_TAGS = new Set(['table', 'ul', 'ol', 'pre']);
// Inline wrappers a publisher CMS may put between a paragraph and a block
// element; a nested <p> / heading is not descended (it walks on its own).
const INLINE_WRAPPER_TAGS = new Set(['span', 'font', 'strong', 'b', 'em', 'i', 'u', 'small', 'big', 'mark', 'a', 'sub', 'sup', 'div', 'center', 'section']);

/**
 * Whether a paragraph-level node wraps a block element (directly or behind
 * inline wrappers, bounded depth).
 * @param {object} node
 * @param {number} [depth]
 */
function hasNestedBlockElement(node, depth = 0) {
  if (depth > 6) return false;
  for (const c of node?.children || []) {
    if (!isElement(c)) continue;
    const t = tagOf(c);
    if (NESTED_BLOCK_TAGS.has(t)) return true;
    if (INLINE_WRAPPER_TAGS.has(t) && hasNestedBlockElement(c, depth + 1)) return true;
  }
  return false;
}

/**
 * Separate a node's inline content from the block elements nested in it
 * (directly or behind inline wrappers, bounded depth), in document order.
 * @param {object} node
 * @returns {{ inline: object[], nested: object[] }}
 */
function splitNestedBlocks(node, depth = 0, out = { inline: [], nested: [] }) {
  for (const c of node?.children || []) {
    const t = tagOf(c);
    if (isElement(c) && NESTED_BLOCK_TAGS.has(t)) out.nested.push(c);
    else if (isElement(c) && depth < 6 && INLINE_WRAPPER_TAGS.has(t) && hasNestedBlockElement(c)) splitNestedBlocks(c, depth + 1, out);
    else out.inline.push(c);
  }
  return out;
}

function attr(node, name) {
  return node && node.attribs ? node.attribs[name] : undefined;
}

/**
 * Collect `<a href>` pairs under a content node (absolute when baseUrl given).
 * Noise subtrees are skipped. Nested anchors are not double-counted.
 * @param {object} node
 * @param {string|null} [baseUrl]
 * @returns {{ href: string, text: string }[]}
 */
export function collectHyperlinks(node, baseUrl = null) {
  const out = [];
  const walk = (n) => {
    if (!n) return;
    if (!isElement(n)) {
      if (n.type === 'root') for (const c of n.children || []) walk(c);
      return;
    }
    const tag = tagOf(n);
    if (NOISE_TAGS.has(tag)) return;
    if (tag === 'a') {
      const hrefRaw = String(attr(n, 'href') || '').trim();
      if (hrefRaw && !hrefRaw.startsWith('#') && !hrefRaw.startsWith('mailto:') && !hrefRaw.startsWith('javascript:')) {
        let href = hrefRaw;
        try {
          href = baseUrl ? new URL(hrefRaw, baseUrl).href : new URL(hrefRaw).href;
        } catch {
          // Keep relative unresolved when no usable base — callers may resolve later.
          href = hrefRaw;
        }
        out.push({ href, text: textOf(n).trim().slice(0, 240) });
      }
      return;
    }
    for (const c of n.children || []) walk(c);
  };
  walk(node);
  return out;
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

/** Line boundary marker produced by <br> while collecting inline text. */
const LINE_BREAK = '\n';

/**
 * Split inline text on <br> boundaries into trimmed, whitespace-collapsed,
 * non-empty lines.
 * @param {string} raw
 */
export function splitRenderedLines(raw) {
  return String(raw || '')
    .split(LINE_BREAK)
    .map((l) => l.replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

/**
 * Rendered text of a node as one line (inline order, <br> → space, noise
 * skipped). Use textLinesOf to keep <br> line boundaries.
 * @param {object} node
 */
export function textOf(node) {
  return renderedText(node, false).replace(/\u00a0/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Visual lines of a node: `<br>` is a line boundary. Publishers write IOC
 * appendices as "<p><b>Hashes</b><br>H1 (a.exe)<br>H2 (b.exe)</p>"; keeping
 * the lines lets row / list detection read each value on its own, exactly as
 * it would a <li> or a one-value <p>.
 * @param {object} node
 */
export function textLinesOf(node) {
  return splitRenderedLines(renderedText(node, true));
}

/**
 * Visual lines of a `<pre>` / `<code>` node. Author newlines are line
 * boundaries (fenced markdown IOC lists), and `<br>` is too. Intra-line
 * whitespace is collapsed so "file\\t\\thash" stays one row.
 * @param {object} node
 */
export function preTextLinesOf(node) {
  return splitRenderedLines(renderedPreText(node));
}

function renderedText(node, lineBreaks) {
  const parts = [];
  const walk = (n) => {
    if (!n) return;
    if (n.type === 'text') {
      // Author newlines are whitespace; only <br> is a line boundary.
      parts.push(String(n.data || '').replace(/[\r\n]+/g, ' '));
      return;
    }
    if (!isElement(n)) return;
    const tag = tagOf(n);
    if (NOISE_TAGS.has(tag)) return;
    if (tag === 'br') {
      parts.push(lineBreaks ? LINE_BREAK : ' ');
      return;
    }
    if (tag === 'img') return;
    const block = HEADING_TAGS.has(tag) || PARAGRAPH_TAGS.has(tag) || tag === 'li' || tag === 'tr' || tag === 'div' || tag === 'pre';
    if (block) parts.push(' ');
    for (const c of n.children || []) walk(c);
    if (block || tag === 'td' || tag === 'th') parts.push(' ');
  };
  walk(node);
  return parts.join('');
}

/**
 * `<pre>` / fenced-code rendering: keep author newlines (and `<br>`) so
 * publisher IOC rows written one-per-line survive HTML extraction.
 * @param {object} node
 */
function renderedPreText(node) {
  const parts = [];
  const walk = (n) => {
    if (!n) return;
    if (n.type === 'text') {
      // Keep newlines; collapse other whitespace runs to a single space.
      parts.push(String(n.data || '').replace(/[^\S\n]+/g, ' '));
      return;
    }
    if (!isElement(n)) return;
    const tag = tagOf(n);
    if (NOISE_TAGS.has(tag)) return;
    if (tag === 'br') {
      parts.push(LINE_BREAK);
      return;
    }
    if (tag === 'img') return;
    for (const c of n.children || []) walk(c);
  };
  walk(node);
  return parts.join('');
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
  const baseUrl = opts.baseUrl || null;
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

  const withLinks = (extra, links) => {
    if (!links || !links.length) return extra || {};
    return { ...(extra || {}), links };
  };

  /**
   * One block per visual line. A single line is an ordinary block; several
   * lines (<br>-separated) share `line_group` = the first line's block id so
   * provenance can reassemble the paragraph. Hyperlinks from the source node
   * are attached to every line of the group (authority / discovery read any).
   */
  const pushLines = (type, lines, links = null) => {
    if (lines.length <= 1) return push(type, lines[0] || '', withLinks({}, links));
    let group = null;
    for (const line of lines) {
      const block = push(type, line, withLinks(group ? { line_group: group } : {}, links));
      if (block && !group) {
        group = block.id;
        block.line_group = group;
      }
    }
    return null;
  };

  /** Pending inline text collected directly inside a container. */
  let pending = [];
  /** @type {{ href: string, text: string }[]} */
  let pendingLinks = [];
  const flushPending = () => {
    if (!pending.length) return;
    const text = pending.join('');
    const links = pendingLinks.length ? pendingLinks.slice() : null;
    pending = [];
    pendingLinks = [];
    pushLines('paragraph', splitRenderedLines(text), links);
  };

  const recordAnchor = (anchorNode) => {
    const hrefRaw = String(attr(anchorNode, 'href') || '').trim();
    if (!hrefRaw || hrefRaw.startsWith('#') || hrefRaw.startsWith('mailto:') || hrefRaw.startsWith('javascript:')) {
      return;
    }
    let href = hrefRaw;
    try {
      href = baseUrl ? new URL(hrefRaw, baseUrl).href : new URL(hrefRaw).href;
    } catch {
      href = hrefRaw;
    }
    pendingLinks.push({ href, text: textOf(anchorNode).trim().slice(0, 240) });
  };

  const walk = (node) => {
    if (!node) return;
    if (node.type === 'text') {
      pending.push(String(node.data || '').replace(/[\r\n]+/g, ' '));
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
      // A heading element wrapping a block behind inline wrappers
      // (`<h3><span style><table>`, v9) is CMS markup damage: the heading is
      // only its own inline text, and the table / list keeps its rows.
      if (hasNestedBlockElement(node)) {
        const { inline, nested } = splitNestedBlocks(node);
        const own = textOf({ type: 'tag', name: 'span', children: inline }).replace(/\s+/g, ' ').trim();
        if (own) {
          currentSection = own.slice(0, 200);
          push('heading', own, { level: Number(tag.slice(1)) });
        }
        for (const c of nested) walk(c);
        flushPending();
        return;
      }
      const text = textOf(node);
      currentSection = text.slice(0, 200) || currentSection;
      // DOM hierarchy (h1–h6) lets zone scoping tell a nested sub-label from a sibling section.
      push('heading', text, { level: Number(tag.slice(1)) });
      return;
    }
    if (PARAGRAPH_TAGS.has(tag)) {
      flushPending();
      // A paragraph may still wrap block children (lists, tables inside <blockquote>),
      // also behind inline wrappers (`<p><span style><table>`, v8): a table
      // flattened into paragraph text loses its rows and cell boundaries.
      if (!hasNestedBlockElement(node)) {
        pushLines('paragraph', textLinesOf(node), collectHyperlinks(node, baseUrl));
        return;
      }
      for (const c of node.children || []) walk(c);
      flushPending();
      return;
    }
    if (tag === 'pre' || (tag === 'code' && !pending.join('').trim())) {
      flushPending();
      // One block per visual line (shared line_group), matching <br>-split
      // paragraphs: "filename HASH" and host/URL lists in fenced code keep
      // their publisher row structure instead of collapsing into one line.
      pushLines('code', preTextLinesOf(node));
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
      // Own inline text first, then nested lists / blocks / headings as their
      // own blocks. Publishers put section labels inside list chrome
      // (`<ul><li><h3>C2</h3></li></ul>`); those must keep heading semantics.
      const inline = [];
      const nested = [];
      for (const c of node.children || []) {
        const childTag = isElement(c) ? tagOf(c) : '';
        if (
          isElement(c) &&
          (['ul', 'ol', 'table', 'pre', 'p', 'div', 'blockquote'].includes(childTag) || HEADING_TAGS.has(childTag))
        ) {
          nested.push(c);
        } else {
          inline.push(c);
        }
      }
      const inlineNode = { type: 'tag', name: 'span', children: inline };
      pushLines('list', textLinesOf(inlineNode), collectHyperlinks(inlineNode, baseUrl));
      for (const c of nested) walk(c);
      flushPending();
      return;
    }
    if (tag === 'br') {
      pending.push(LINE_BREAK);
      return;
    }
    if (tag === 'img') return;
    if (tag === 'hr') {
      flushPending();
      return;
    }
    if (tag === 'a') {
      recordAnchor(node);
      for (const c of node.children || []) walk(c);
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
