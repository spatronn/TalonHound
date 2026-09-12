/**
 * Geometry-based PDF layout reconstruction (pdf.js text items → lines → blocks).
 *
 * pdf-parse's default pagerender joins every text item with a space, which
 * collapses a whole page into one paragraph and destroys headings, IOC list
 * rows and printed header/footer lines. This module rebuilds that structure
 * from item coordinates only (language-agnostic — no keyword lists here).
 */

import { refangTextForExtraction } from './defang.js';

export const PDF_LAYOUT_VERSION = 'threat_library_pdf_v2';

/** Fraction of page height (top/bottom) treated as printed header/footer band. */
const PAGE_EDGE_FRACTION = 0.055;
const MAX_HEADING_CHARS = 72;
const MAX_PARAGRAPH_CHARS = 600;

/**
 * @typedef {{ str: string, width?: number, height?: number, transform?: number[], fontName?: string }} PdfTextItem
 * @typedef {{
 *   text: string, x: number, y: number, height: number, fontName: string|null,
 *   pageEdge: boolean, itemCount: number
 * }} PdfLine
 */

/**
 * Collapse letter-spaced runs ("I O C", "C & C :", "A P T - C - 5 5") into
 * compact tokens. Only runs of >= 3 single-character tokens are collapsed so
 * ordinary prose is untouched.
 * @param {string} text
 */
export function collapseLetterSpacing(text) {
  const s = String(text || '');
  if (!s.includes(' ')) return s;
  return s.replace(/(?:^|(?<=\s))(?:\S ){2,}\S(?=\s|$)/g, (run) => run.replace(/ /g, ''));
}

/**
 * Group pdf.js text items into visual lines using y proximity, then order by x.
 * @param {PdfTextItem[]} items
 * @param {{ pageHeight?: number }} [opts]
 * @returns {PdfLine[]}
 */
export function itemsToLines(items, opts = {}) {
  const pageHeight = Number(opts.pageHeight) || 0;
  const usable = [];
  for (const it of items || []) {
    if (!it || typeof it.str !== 'string') continue;
    const t = it.transform || [];
    const x = Number(t[4]);
    const y = Number(t[5]);
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
    const height = Math.max(Number(it.height) || Math.abs(Number(t[3])) || 0, 1);
    usable.push({
      str: it.str,
      x,
      y,
      width: Number(it.width) || 0,
      height,
      fontName: it.fontName || null
    });
  }
  if (!usable.length) return [];

  // Top of page first (pdf.js y grows upward), then left to right.
  usable.sort((a, b) => b.y - a.y || a.x - b.x);

  /** @type {{ y: number, height: number, items: typeof usable }[]} */
  const groups = [];
  for (const it of usable) {
    const last = groups[groups.length - 1];
    const tolerance = Math.max(3, 0.9 * Math.max(it.height, last?.height || 0));
    if (last && Math.abs(last.y - it.y) <= tolerance) {
      last.items.push(it);
      // Keep the baseline at the dominant (largest) item height
      if (it.height > last.height) last.height = it.height;
    } else {
      groups.push({ y: it.y, height: it.height, items: [it] });
    }
  }

  const lines = [];
  for (const g of groups) {
    g.items.sort((a, b) => a.x - b.x);
    let text = '';
    let prevEnd = null;
    const fontChars = new Map();
    for (const it of g.items) {
      const piece = it.str;
      if (!piece) continue;
      if (prevEnd != null && text) {
        const gap = it.x - prevEnd;
        const needsSpace =
          gap > 0.25 * Math.max(it.height, 4) && !text.endsWith(' ') && !piece.startsWith(' ');
        if (needsSpace) text += ' ';
      }
      text += piece;
      prevEnd = it.x + it.width;
      if (it.fontName && piece.trim()) {
        fontChars.set(it.fontName, (fontChars.get(it.fontName) || 0) + piece.trim().length);
      }
    }
    const clean = collapseLetterSpacing(text.replace(/\s+/g, ' ').trim());
    if (!clean) continue;
    let fontName = null;
    let best = -1;
    for (const [f, n] of fontChars) {
      if (n > best) {
        best = n;
        fontName = f;
      }
    }
    const pageEdge =
      pageHeight > 0 &&
      (g.y >= pageHeight * (1 - PAGE_EDGE_FRACTION) || g.y <= pageHeight * PAGE_EDGE_FRACTION);
    lines.push({
      text: clean,
      x: g.items[0].x,
      y: g.y,
      height: g.height,
      fontName,
      pageEdge,
      itemCount: g.items.length
    });
  }
  return lines;
}

const OBSERVABLE_LINE_RE =
  /^(?:[\[(]?\d{1,3}[\])]?[.、)]?\s*|[-•*·]\s*)?(?:https?:\/\/\S+|(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\s*$/i;

/**
 * True when a line is a single indicator value (optionally with a bullet or
 * citation marker) — the shape of an IOC appendix row or a reference row.
 * @param {string} text
 */
export function isObservableOnlyLine(text) {
  const t = refangTextForExtraction(String(text || '').trim());
  if (!t || t.length > 400) return false;
  return OBSERVABLE_LINE_RE.test(t);
}

/**
 * @param {string} text
 */
export function hasCitationMarker(text) {
  return /^\s*[\[(]\d{1,3}[\])]/.test(String(text || ''));
}

function containsObservableLike(text) {
  const t = refangTextForExtraction(text);
  return /https?:\/\//i.test(t) || /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(t) || /\b[a-f0-9]{32,64}\b/i.test(t) || /@/.test(t);
}

/**
 * Body fonts by character volume across all lines. Mixed-script documents use
 * one font per script (CJK + Latin), so every font carrying >= 12% of the text
 * counts as body.
 * @param {PdfLine[]} lines
 * @returns {Set<string>}
 */
export function bodyFonts(lines) {
  const counts = new Map();
  let total = 0;
  for (const l of lines || []) {
    if (!l.fontName || l.pageEdge) continue;
    counts.set(l.fontName, (counts.get(l.fontName) || 0) + l.text.length);
    total += l.text.length;
  }
  const out = new Set();
  let best = null;
  let bestN = -1;
  for (const [f, n] of counts) {
    if (n > bestN) {
      bestN = n;
      best = f;
    }
    if (total > 0 && n / total >= 0.12) out.add(f);
  }
  if (best) out.add(best);
  return out;
}

/**
 * Median body line height (font size proxy).
 * @param {PdfLine[]} lines
 */
export function medianLineHeight(lines) {
  const hs = (lines || []).filter((l) => !l.pageEdge).map((l) => l.height).sort((a, b) => a - b);
  if (!hs.length) return 0;
  return hs[Math.floor(hs.length / 2)];
}

/**
 * Structural heading test (no keyword lists): short, no indicator, and either a
 * non-body font, a visibly larger font, or a numbered section prefix.
 * @param {PdfLine} line
 * @param {{ bodyFonts?: Set<string>, bodyHeight: number }} ctx
 */
export function isStructuralHeading(line, ctx) {
  const text = line.text;
  if (!text || line.pageEdge) return false;
  if (text.length > MAX_HEADING_CHARS) return false;
  if (containsObservableLike(text)) return false;
  if (/[。.!?;；]$/.test(text) && text.length > 24) return false;
  const fonts = ctx.bodyFonts || new Set();
  const differentFont = Boolean(fonts.size && line.fontName && !fonts.has(line.fontName));
  const larger = ctx.bodyHeight > 0 && line.height >= ctx.bodyHeight * 1.15;
  const numbered = /^(?:[一二三四五六七八九十]+[、.．]|\d{1,2}(?:\.\d{1,2})*[.、)．]?\s*\S)/.test(text) && text.length <= 40;
  const labelLike = /^[A-Za-z0-9&/ ._-]{2,24}\s*[:：]?$/.test(text) && line.itemCount <= 8;
  if (!fonts.size && !(ctx.bodyHeight > 0)) {
    // Plain-text fallback (no geometry): short label / numbered lines are headings.
    return numbered || labelLike || (text.length <= 24 && !/[。.!?;；,，]$/.test(text));
  }
  return larger || (differentFont && (numbered || labelLike || text.length <= 40)) || (numbered && line.itemCount <= 6);
}

/**
 * Join a URL wrapped across two visual lines (browser print output).
 * @param {string} current
 * @param {string} next
 */
export function joinWrappedUrl(current, next) {
  const cur = String(current || '');
  const nxt = String(next || '').trim();
  if (!nxt || /\s/.test(nxt)) return null;
  if (!/https?:\/\/\S+$/i.test(refangTextForExtraction(cur))) return null;
  if (/^(?:https?:\/\/|hxxps?:\/\/)/i.test(nxt)) return null;
  if (!/^[A-Za-z0-9._~%/\-?=&#+]+$/.test(nxt)) return null;
  if (isObservableOnlyLine(nxt)) return null;
  // Require a visible wrap signal: URL cut at a path/query separator, or a path-like tail.
  if (!/[-/=&?_%]$/.test(cur) && !/[/=?&]/.test(nxt)) return null;
  return `${cur}${nxt}`;
}

/**
 * Convert one page of lines into canonical blocks.
 * @param {PdfLine[]} lines
 * @param {{ pageNum: number, startIdx: number, bodyFonts?: Set<string>, bodyHeight: number }} ctx
 */
export function linesToBlocks(lines, ctx) {
  const blocks = [];
  let idx = ctx.startIdx;
  const mk = (type, text, extra = {}) => {
    const t = String(text || '').replace(/\s+/g, ' ').trim();
    if (!t) return;
    blocks.push({
      id: `p${ctx.pageNum}-b${String(idx).padStart(2, '0')}`,
      type,
      text: t,
      page: ctx.pageNum,
      section: null,
      ...extra
    });
    idx += 1;
  };

  /** @type {string[]} */
  let para = [];
  let paraLastY = null;
  const flushPara = () => {
    if (!para.length) return;
    mk('paragraph', para.join(' '));
    para = [];
    paraLastY = null;
  };

  const src = (lines || []).slice();
  // Merge wrapped URLs before block assembly
  for (let i = 0; i < src.length - 1; i += 1) {
    const joined = joinWrappedUrl(src[i].text, src[i + 1].text);
    if (joined && !src[i].pageEdge && !src[i + 1].pageEdge) {
      src[i] = { ...src[i], text: joined };
      src.splice(i + 1, 1);
      i -= 1;
    }
  }

  // Typical vertical pitch between consecutive body lines on this page; a gap
  // clearly larger than the pitch is a paragraph boundary.
  const deltas = [];
  for (let i = 1; i < src.length; i += 1) {
    if (src[i].pageEdge || src[i - 1].pageEdge) continue;
    const d = src[i - 1].y - src[i].y;
    if (d > 0) deltas.push(d);
  }
  deltas.sort((a, b) => a - b);
  const pitch = deltas.length ? deltas[Math.floor(deltas.length / 2)] : 0;

  for (const line of src) {
    if (line.pageEdge) {
      flushPara();
      mk('paragraph', line.text, { layout: 'page_edge' });
      continue;
    }
    if (isObservableOnlyLine(line.text)) {
      flushPara();
      mk('list_item', line.text, {
        layout: 'observable_row',
        citation: hasCitationMarker(line.text) || undefined
      });
      continue;
    }
    if (isStructuralHeading(line, ctx)) {
      flushPara();
      mk('heading', line.text, { section: line.text.slice(0, 200) });
      continue;
    }
    // Paragraph break on a vertical gap clearly larger than the line pitch
    if (paraLastY != null && pitch > 0 && paraLastY - line.y > pitch * 1.6) {
      flushPara();
    }
    para.push(line.text);
    paraLastY = line.y;
    if (para.join(' ').length > MAX_PARAGRAPH_CHARS) flushPara();
  }
  flushPara();
  return { blocks, nextIdx: idx };
}

/**
 * Full document assembly from per-page pdf.js text items.
 * @param {{ page: number, items: PdfTextItem[], pageHeight?: number }[]} pages
 */
export function pagesToBlocks(pages) {
  const perPageLines = (pages || []).map((p) => ({
    page: p.page,
    lines: itemsToLines(p.items, { pageHeight: p.pageHeight })
  }));
  const allLines = perPageLines.flatMap((p) => p.lines);
  const fonts = bodyFonts(allLines);
  const bodyHeight = medianLineHeight(allLines);
  let blocks = [];
  let idx = 1;
  for (const p of perPageLines) {
    const r = linesToBlocks(p.lines, { pageNum: p.page, startIdx: idx, bodyFonts: fonts, bodyHeight });
    blocks = blocks.concat(r.blocks);
    idx = r.nextIdx;
  }
  return { blocks, bodyFonts: [...fonts], bodyHeight };
}

/**
 * Plain-text fallback (no geometry): split lines, collapse letter spacing,
 * keep observable rows as list items.
 * @param {string} pageText
 * @param {number} pageNum
 * @param {number} startIdx
 */
export function plainTextToBlocks(pageText, pageNum, startIdx) {
  const lines = String(pageText || '')
    .split(/\n+/)
    .map((l) => collapseLetterSpacing(l.replace(/\s+/g, ' ').trim()))
    .filter(Boolean)
    .map((text) => ({ text, x: 0, y: 0, height: 0, fontName: null, pageEdge: false, itemCount: 1 }));
  return linesToBlocks(lines, { pageNum, startIdx, bodyFonts: new Set(), bodyHeight: 0 });
}
