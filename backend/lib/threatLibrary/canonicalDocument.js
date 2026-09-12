/**
 * Canonical document model for Threat Library (URL + PDF converge here).
 */

/**
 * @typedef {{ id: string, type: string, text: string, page?: number|null, section?: string|null }} CanonicalBlock
 * @typedef {{ title: string, language: string|null, blocks: CanonicalBlock[], meta?: object }} CanonicalDocument
 */

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
