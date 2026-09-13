/**
 * Canonical document model for Threat Library (URL + PDF converge here).
 */

/**
 * @typedef {{ headers: string[]|null, rows: string[][], caption?: string|null, source?: string|null }} CanonicalTable
 * @typedef {{ id: string, type: string, text: string, page?: number|null, section?: string|null, table?: CanonicalTable }} CanonicalBlock
 * @typedef {{ title: string, language: string|null, blocks: CanonicalBlock[], meta?: object }} CanonicalDocument
 */

/** Cell / row separators used when a table is flattened to one text line. */
export const TABLE_CELL_SEPARATOR = ' | ';
export const TABLE_ROW_SEPARATOR = ' ¶ ';

/**
 * Flatten table cells to one text line (rows in order, cells in order) so every
 * consumer that only reads `text` (AI chunks, evidence excerpts, quality gate)
 * still sees the full content, while `table` keeps the structure.
 * @param {CanonicalTable} table
 */
export function flattenTableText(table) {
  const lines = [];
  const clean = (c) => String(c ?? '').replace(/\s+/g, ' ').trim();
  if (Array.isArray(table?.headers) && table.headers.length) {
    lines.push(table.headers.map(clean).join(TABLE_CELL_SEPARATOR));
  }
  for (const row of table?.rows || []) {
    lines.push((Array.isArray(row) ? row : []).map(clean).join(TABLE_CELL_SEPARATOR));
  }
  return lines.join(TABLE_ROW_SEPARATOR).trim();
}

/**
 * Build a canonical table block. Cell values are always strings (hashes with
 * leading zeros are never numbers). Empty rows are dropped, ragged rows padded.
 * @param {{ id: string, page?: number|null, section?: string|null, headers?: string[]|null, rows: string[][], caption?: string|null, source?: string|null, layout?: string }} input
 * @returns {CanonicalBlock|null}
 */
export function createTableBlock(input) {
  const toCell = (c) => (c == null ? '' : String(c)).replace(/\s+/g, ' ').trim();
  const rows = (input.rows || [])
    .map((r) => (Array.isArray(r) ? r.map(toCell) : []))
    .filter((r) => r.some((c) => c.length > 0));
  const headers = Array.isArray(input.headers) && input.headers.some((h) => toCell(h)) ? input.headers.map(toCell) : null;
  const width = Math.max(headers ? headers.length : 0, ...rows.map((r) => r.length), 0);
  if (!width || !rows.length) return null;
  const padded = rows.map((r) => {
    const out = r.slice(0, width);
    while (out.length < width) out.push('');
    return out;
  });
  const table = {
    headers: headers ? headers.slice(0, width).concat(Array(Math.max(0, width - headers.length)).fill('')) : null,
    rows: padded,
    caption: input.caption ? toCell(input.caption) : null,
    source: input.source || null
  };
  const text = flattenTableText(table);
  if (!text) return null;
  return {
    id: input.id,
    type: 'table',
    text,
    page: input.page ?? null,
    section: input.section ?? null,
    layout: input.layout || 'table',
    table
  };
}

/**
 * @param {Partial<CanonicalDocument>} doc
 * @returns {CanonicalDocument}
 */
export function createCanonicalDocument(doc = {}) {
  return {
    title: String(doc.title || '').trim() || 'Untitled',
    language: doc.language == null ? null : String(doc.language),
    blocks: Array.isArray(doc.blocks) ? doc.blocks : [],
    meta: doc.meta && typeof doc.meta === 'object' ? doc.meta : {}
  };
}

/**
 * @param {string} prefix
 * @param {number} index
 */
export function blockId(prefix, index) {
  const n = String(index).padStart(3, '0');
  return `${prefix}${n}`;
}

/**
 * Flatten document to plain text with block markers (for AI chunking / evidence).
 * @param {CanonicalDocument} doc
 * @param {{ maxChars?: number }} [opts]
 */
export function flattenCanonicalText(doc, opts = {}) {
  const maxChars = opts.maxChars || Infinity;
  const parts = [];
  let used = 0;
  for (const b of doc.blocks || []) {
    const line = `[${b.id}|${b.type}${b.page != null ? `|p${b.page}` : ''}] ${b.text || ''}`;
    if (used + line.length + 1 > maxChars) break;
    parts.push(line);
    used += line.length + 1;
  }
  return parts.join('\n');
}

/**
 * @param {CanonicalDocument} doc
 * @returns {Set<string>}
 */
export function collectBlockIds(doc) {
  return new Set((doc.blocks || []).map((b) => b.id).filter(Boolean));
}

/**
 * Detect effectively empty / scanned PDF after extraction.
 * @param {CanonicalDocument} doc
 */
export function isEffectivelyEmptyDocument(doc) {
  const text = (doc.blocks || []).map((b) => b.text || '').join('').replace(/\s+/g, '');
  return text.length < 40;
}

/**
 * Chunk blocks for AI with approximate char budget.
 * @param {CanonicalDocument} doc
 * @param {{ maxCharsPerChunk?: number, maxChunks?: number }} [opts]
 */
export function chunkCanonicalDocument(doc, opts = {}) {
  const maxChars = opts.maxCharsPerChunk || 12000;
  const maxChunks = opts.maxChunks || 8;
  /** @type {import('./canonicalDocument.js').CanonicalBlock[][]} */
  const chunks = [];
  let current = [];
  let size = 0;

  const flush = () => {
    if (!current.length) return;
    chunks.push(current);
    current = [];
    size = 0;
  };

  for (const b of doc.blocks || []) {
    const len = (b.text || '').length + 32;
    if (current.length && size + len > maxChars && chunks.length < maxChunks - 1) {
      flush();
    }
    current.push(b);
    size += len;
  }
  flush();

  // Never discard leftover content: if somehow empty, return [].
  return chunks.length ? chunks : [];
}
