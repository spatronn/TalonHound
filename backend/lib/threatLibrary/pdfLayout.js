/**
 * Geometry-based PDF layout reconstruction (pdf.js text items → lines → blocks).
 *
 * pdf-parse's default pagerender joins every text item with a space, which
 * collapses a whole page into one paragraph and destroys headings, IOC list
 * rows and printed header/footer lines. This module rebuilds that structure
 * from item coordinates only (language-agnostic — no keyword lists here).
 */

import { refangTextForExtraction } from './defang.js';
import { createTableBlock } from './canonicalDocument.js';

/**
 * v3: multi-column regions are reconstructed as canonical `table` blocks
 * (cells by span overlap, rows by column conflict + vertical gap, wrapped cell
 * fragments re-joined) instead of being flattened into paragraphs/headings.
 */
export const PDF_LAYOUT_VERSION = 'threat_library_pdf_v3';

/** Fraction of page height (top/bottom) treated as printed header/footer band. */
const PAGE_EDGE_FRACTION = 0.055;
const MAX_HEADING_CHARS = 72;
const MAX_PARAGRAPH_CHARS = 600;
/** Horizontal gap (in line heights) that separates two cells on one visual line. */
const CELL_GAP_FACTOR = 1.5;
const MIN_CELL_GAP = 8;
/** Span-overlap slack when assigning a cell to a column (points). */
const COLUMN_OVERLAP_SLACK = 2;
/** Vertical gap (in line heights) above which a same-column cell starts a new row. */
const ROW_GAP_FACTOR = 1.6;
/** Vertical gap (in line heights) that always starts a new row, conflict or not. */
const ROW_HARD_GAP_FACTOR = 2.6;
/** A wrapped fragment starts at the same x0 / centre / x1 as the cell it continues (points). */
const WRAP_ALIGN_TOLERANCE = 12;
const MAX_TABLE_CELL_CHARS = 2000;

/**
 * @typedef {{ str: string, width?: number, height?: number, transform?: number[], fontName?: string }} PdfTextItem
 * @typedef {{ x0: number, x1: number, text: string, fontName: string|null }} PdfCell
 * @typedef {{
 *   text: string, x: number, y: number, height: number, fontName: string|null,
 *   pageEdge: boolean, itemCount: number, cells?: PdfCell[]
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
    /** @type {PdfCell[]} */
    const cells = [];
    let cell = null;
    const cellGap = Math.max(MIN_CELL_GAP, CELL_GAP_FACTOR * g.height);
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
      // Cell segmentation: a horizontal gap clearly wider than a word space starts
      // a new cell; so does a run that overlaps the previous one (an overlay such as
      // a floating banner printed over body text is never sequential text).
      if (piece.trim()) {
        const overlaps = cell && it.x < cell.x1 - Math.max(2, 0.3 * g.height);
        if (cell && !overlaps && it.x - cell.x1 <= cellGap) {
          const sp =
            it.x - cell.x1 > 0.25 * Math.max(it.height, 4) && !cell.text.endsWith(' ') && !piece.startsWith(' ') ? ' ' : '';
          cell.text += sp + piece;
          cell.x1 = Math.max(cell.x1, it.x + it.width);
        } else {
          cell = { x0: it.x, x1: it.x + it.width, text: piece, fontName: it.fontName || null };
          cells.push(cell);
        }
      }
      prevEnd = it.x + it.width;
      if (it.fontName && piece.trim()) {
        fontChars.set(it.fontName, (fontChars.get(it.fontName) || 0) + piece.trim().length);
      }
    }
    const clean = collapseLetterSpacing(text.replace(/\s+/g, ' ').trim());
    if (!clean) continue;
    for (const c of cells) c.text = collapseLetterSpacing(c.text.replace(/\s+/g, ' ').trim());
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
      itemCount: g.items.length,
      cells: cells.filter((c) => c.text)
    });
  }
  return lines;
}

function looksObservableLike(text) {
  const t = refangTextForExtraction(String(text || ''));
  return /https?:\/\//i.test(t) || /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(t) || /\b[a-f0-9]{32,64}\b/i.test(t);
}

/**
 * Join fragments of one table cell that wrapped across visual lines. A hex run
 * split in two (hash cells), or a URL/path cut at a separator, re-joins without
 * a space; ordinary wrapped prose gets a space.
 * @param {string[]} fragments
 */
export function joinWrappedCellFragments(fragments) {
  let out = '';
  for (const raw of fragments || []) {
    const f = String(raw || '').trim();
    if (!f) continue;
    if (!out) {
      out = f;
      continue;
    }
    const outSingle = !/\s/.test(out);
    const fSingle = !/\s/.test(f);
    if (outSingle && fSingle && /^[a-f0-9]+$/i.test(out + f)) out += f;
    else if (outSingle && fSingle && /[/=&?_%.\-]$/.test(out)) out += f;
    else if (outSingle && fSingle && /^[/?&=.]/.test(f)) out += f;
    else out += ` ${f}`;
  }
  return out;
}

/**
 * Column index for a cell by span overlap (null = no overlap; -1 = spans several).
 * @param {{ x0: number, x1: number }[]} columns
 * @param {PdfCell} cell
 */
function columnForCell(columns, cell) {
  let hit = null;
  for (let i = 0; i < columns.length; i += 1) {
    const col = columns[i];
    if (cell.x0 < col.x1 + COLUMN_OVERLAP_SLACK && cell.x1 > col.x0 - COLUMN_OVERLAP_SLACK) {
      if (hit != null) return -1;
      hit = i;
    }
  }
  return hit;
}

/**
 * Grow a multi-column region from line index `start`. A line joins while every
 * cell maps to exactly one column (existing or new) and no two cells share a
 * column; a heading, a page-edge line or a line spanning several columns ends it.
 * @param {PdfLine[]} src
 * @param {number} start
 * @param {{ bodyFonts?: Set<string>, bodyHeight: number }} ctx
 */
function growTableRegion(src, start, ctx) {
  /** @type {{ x0: number, x1: number }[]} */
  const columns = [];
  const members = [];
  for (let i = start; i < src.length; i += 1) {
    const line = src[i];
    if (line.pageEdge || line.repeated) break;
    const cells = line.cells || [];
    if (!cells.length) break;
    if (cells.length === 1 && isStructuralHeading(line, ctx)) {
      const prev = members.length ? members[members.length - 1].line : null;
      const gap = prev ? prev.y - line.y : Infinity;
      const continues =
        prev && columns.length >= 2 && columnForCell(columns, cells[0]) != null && gap <= ROW_GAP_FACTOR * Math.max(prev.height, line.height, 1);
      if (!continues) break;
    }
    const assignment = [];
    const used = new Set();
    let ok = true;
    const added = [];
    for (const cell of cells) {
      let idx = columnForCell(columns.concat(added), cell);
      if (idx === -1) {
        ok = false;
        break;
      }
      if (idx == null) {
        added.push({ x0: cell.x0, x1: cell.x1 });
        idx = columns.length + added.length - 1;
      }
      if (used.has(idx)) {
        ok = false;
        break;
      }
      used.add(idx);
      assignment.push(idx);
    }
    if (!ok) break;
    for (const a of added) columns.push(a);
    cells.forEach((cell, k) => {
      const col = columns[assignment[k]];
      col.x0 = Math.min(col.x0, cell.x0);
      col.x1 = Math.max(col.x1, cell.x1);
    });
    members.push({ index: i, line, assignment });
  }
  return { columns, members };
}

/**
 * Row grouping: a cell landing in a column the current row already fills starts
 * a new row unless it is a wrapped continuation (at wrapped-line pitch below the
 * previous line and aligned with the cell it continues); a clearly larger gap
 * always starts a row.
 * @returns {{ colPos: Map<number, number>, spans: number[] }}
 */
function groupRegionRows(region, pitch) {
  const order = region.columns
    .map((c, i) => ({ i, x0: c.x0 }))
    .sort((a, b) => a.x0 - b.x0)
    .map((c) => c.i);
  const colPos = new Map(order.map((origIdx, pos) => [origIdx, pos]));
  const spans = [];
  /** @type {Map<number, PdfCell>|null} column → last cell placed in the current row */
  let filled = null;
  let prev = null;
  const aligned = (a, b) =>
    Math.abs(a.x0 - b.x0) <= WRAP_ALIGN_TOLERANCE ||
    Math.abs(a.x1 - b.x1) <= WRAP_ALIGN_TOLERANCE ||
    Math.abs((a.x0 + a.x1) / 2 - (b.x0 + b.x1) / 2) <= WRAP_ALIGN_TOLERANCE;
  for (const m of region.members) {
    const line = m.line;
    const h = Math.max(prev ? prev.height : 0, line.height, 1);
    const gap = prev ? prev.y - line.y : 0;
    const tight = Math.max(ROW_GAP_FACTOR * h, pitch > 0 ? pitch * 1.2 : 0);
    const cols = m.assignment.map((a) => colPos.get(a));
    let conflict = false;
    let wrapped = Boolean(filled);
    if (filled) {
      cols.forEach((c, k) => {
        const existing = filled.get(c);
        if (!existing) return;
        conflict = true;
        if (!aligned(existing, line.cells[k])) wrapped = false;
      });
    }
    const newRow = !filled || (conflict && (gap > tight || !wrapped)) || gap > ROW_HARD_GAP_FACTOR * h;
    if (newRow) {
      filled = new Map();
      spans.push(0);
    }
    cols.forEach((c, k) => filled.set(c, line.cells[k]));
    spans[spans.length - 1] += 1;
    prev = line;
  }
  return { colPos, spans };
}

/**
 * @param {{ columns: {x0:number,x1:number}[], members: { line: PdfLine, assignment: number[] }[] }} region
 * @param {number} pitch
 */
function regionToRows(region, pitch) {
  const { colPos, spans } = groupRegionRows(region, pitch);
  const width = region.columns.length;
  const rows = [];
  let cursor = 0;
  for (const span of spans) {
    const frags = Array.from({ length: width }, () => []);
    const fonts = new Map();
    for (const m of region.members.slice(cursor, cursor + span)) {
      m.line.cells.forEach((cell, k) => {
        frags[colPos.get(m.assignment[k])].push(cell.text);
        if (cell.fontName) fonts.set(cell.fontName, (fonts.get(cell.fontName) || 0) + cell.text.length);
      });
    }
    cursor += span;
    rows.push({
      cells: frags.map((f) => joinWrappedCellFragments(f).slice(0, MAX_TABLE_CELL_CHARS)),
      font: dominantFont(fonts),
      lines: span
    });
  }
  return rows;
}

function dominantFont(map) {
  let best = null;
  let n = -1;
  for (const [f, c] of map || []) {
    if (c > n) {
      n = c;
      best = f;
    }
  }
  return best;
}

/**
 * Detect table regions on one page. Returns non-overlapping regions with the
 * line index range they consume and their reconstructed rows.
 * @param {PdfLine[]} src
 * @param {{ bodyFonts?: Set<string>, bodyHeight: number, pitch: number }} ctx
 */
export function detectTableRegions(src, ctx) {
  const regions = [];
  let i = 0;
  while (i < src.length) {
    const line = src[i];
    if (line.pageEdge || line.repeated || !(line.cells || []).length) {
      i += 1;
      continue;
    }
    const region = growTableRegion(src, i, ctx);
    const multiCellLines = region.members.filter((m) => m.line.cells.length >= 2).length;
    if (region.columns.length < 2 || multiCellLines < 2) {
      i += 1;
      continue;
    }
    // A line of chrome above a table (banner, stray label) seeds a short region
    // that the real rows cannot join. If starting one line lower reaches
    // further, this line is not part of the table.
    if (i + 1 < src.length && !src[i + 1].pageEdge && !src[i + 1].repeated) {
      const lower = growTableRegion(src, i + 1, ctx);
      const lowerEnd = lower.members.length ? lower.members[lower.members.length - 1].index : -1;
      const thisEnd = region.members[region.members.length - 1].index;
      if (lower.columns.length >= 2 && lowerEnd > thisEnd) {
        i += 1;
        continue;
      }
    }
    let rows = regionToRows(region, ctx.pitch);
    let startMember = 0;
    let endMember = region.members.length;
    while (rows.length > 2 && isStrayEdgeRow(rows, rows.length - 1)) {
      endMember -= rows[rows.length - 1].lines;
      rows.pop();
    }
    while (rows.length > 2 && isStrayEdgeRow(rows, 0)) {
      startMember += rows[0].lines;
      rows.shift();
    }
    rows = dropEmptyColumns(rows);
    // A table needs at least two columns that two or more rows actually share;
    // two unrelated multi-cell lines (a caption plus an icon, a banner) do not.
    const sharedColumns = rows.length
      ? rows[0].cells.map((_, c) => rows.filter((r) => r.cells[c]).length).filter((n) => n >= 2).length
      : 0;
    if (rows.length < 2 || sharedColumns < 2) {
      i += 1;
      continue;
    }
    const first = region.members[startMember].index;
    const last = region.members[endMember - 1].index;
    regions.push({ start: first, end: last + 1, rows, columns: rows[0].cells.length });
    i = last + 1;
  }
  return regions;
}

/**
 * Header row by typography: first row set in a font no other row uses, with no
 * observable-looking cell. Label-based header promotion happens downstream in
 * the table interpreter (language hints), so this stays purely structural.
 * @param {{ cells: string[], font: string|null }[]} rows
 */
function splitHeaderByFont(rows) {
  if (rows.length < 2) return { headers: null, rows };
  const first = rows[0];
  if (!first.font) return { headers: null, rows };
  if (first.cells.some((c) => looksObservableLike(c))) return { headers: null, rows };
  const others = rows.slice(1).map((r) => r.font).filter(Boolean);
  if (!others.length || others.includes(first.font)) return { headers: null, rows };
  // A header labels the columns the data rows use; a row missing them is chrome, not a header.
  const coverage = coverageColumns(rows.slice(1));
  if (coverage.some((c) => !first.cells[c])) return { headers: null, rows };
  return { headers: first.cells, rows: rows.slice(1) };
}

/** Columns filled by at least half of the given rows. */
function coverageColumns(rows) {
  if (!rows.length) return [];
  const width = rows[0].cells.length;
  const out = [];
  for (let c = 0; c < width; c += 1) {
    const filled = rows.filter((r) => r.cells[c]).length;
    if (filled * 2 >= rows.length) out.push(c);
  }
  return out;
}

/**
 * Leading / trailing rows that do not use the columns the body of the table
 * uses (a banner or paragraph tail absorbed at the region edge) are stray.
 * Observable-bearing rows never are.
 * @param {{ cells: string[], font: string|null, lines: number }[]} rows
 * @param {number} idx
 */
function isStrayEdgeRow(rows, idx) {
  if (rows.length < 3) return false;
  const row = rows[idx];
  const body = rows.filter((_, i) => i !== idx);
  const coverage = coverageColumns(body);
  const filled = row.cells.map((c, i) => (c ? i : -1)).filter((i) => i >= 0);
  if (!filled.length) return true;
  if (filled.some((c) => looksObservableLike(row.cells[c]))) return false;
  const missing = coverage.filter((c) => !row.cells[c]).length;
  const extra = filled.filter((c) => !coverage.includes(c)).length;
  if (filled.length <= 1) return true;
  return coverage.length > 0 && missing + extra >= Math.ceil(coverage.length / 2);
}

/** Drop columns no row uses any more (after stray-row trimming). */
function dropEmptyColumns(rows) {
  if (!rows.length) return rows;
  const width = rows[0].cells.length;
  const keep = [];
  for (let c = 0; c < width; c += 1) if (rows.some((r) => r.cells[c])) keep.push(c);
  if (keep.length === width) return rows;
  return rows.map((r) => ({ ...r, cells: keep.map((c) => r.cells[c]) }));
}

const OBSERVABLE_LINE_RE =
  /^(?:[\[(]?\d{1,3}[\])]?[.、)]?\s*|[-•*·]\s*)?(?:https?:\/\/\S+|(?:\d{1,3}\.){3}\d{1,3}(?:\/(?:3[0-2]|[12]?\d)|:\d{1,5})?|[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\s*$/i;

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
  const numbered =
    /^(?:[一二三四五六七八九十]+[、.．]|\d{1,2}(?:\.\d{1,2})*(?:[.、)．]\s*|\s+)\S)/.test(text) && text.length <= 40;
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

  const regions = ctx.tables === false ? [] : detectTableRegions(src, { ...ctx, pitch });
  const regionByStart = new Map(regions.map((r) => [r.start, r]));

  for (let li = 0; li < src.length; li += 1) {
    const line = src[li];
    const region = regionByStart.get(li);
    if (region) {
      flushPara();
      const split = splitHeaderByFont(region.rows);
      const block = createTableBlock({
        id: `p${ctx.pageNum}-b${String(idx).padStart(2, '0')}`,
        page: ctx.pageNum,
        headers: split.headers,
        rows: split.rows.map((r) => r.cells),
        source: 'pdf_geometry'
      });
      if (block) {
        blocks.push(block);
        idx += 1;
        li = region.end - 1;
        continue;
      }
    }
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
 * Printed chrome that repeats on many pages (banners, running titles) is layout,
 * not content: it must never seed or join a table region. Mirrors the
 * repeated-block header/footer detection in documentZones, at line level.
 * @param {{ page: number, lines: PdfLine[] }[]} perPageLines
 */
export function markRepeatedLines(perPageLines) {
  const pageCount = perPageLines.length;
  if (pageCount < 4) return;
  const pagesByText = new Map();
  for (const p of perPageLines) {
    for (const l of p.lines) {
      const key = l.text.toLowerCase().replace(/\d+/g, '#').replace(/\s+/g, ' ').trim();
      if (key.length < 8 || key.length > 220) continue;
      if (!pagesByText.has(key)) pagesByText.set(key, new Set());
      pagesByText.get(key).add(p.page);
    }
  }
  const threshold = Math.max(4, Math.ceil(pageCount * 0.3));
  for (const p of perPageLines) {
    for (const l of p.lines) {
      const key = l.text.toLowerCase().replace(/\d+/g, '#').replace(/\s+/g, ' ').trim();
      const pages = pagesByText.get(key);
      if (pages && pages.size >= threshold && !looksObservableLike(l.text)) l.repeated = true;
    }
  }
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
  markRepeatedLines(perPageLines);
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
