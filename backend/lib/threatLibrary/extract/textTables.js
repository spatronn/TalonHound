/**
 * Table-like structure in plain text: Markdown pipe tables and rows of
 * tab / multi-space separated fields. Produces the same canonical `table`
 * blocks as the HTML and PDF extractors so the table interpreter and the
 * candidate extractor never need to know the source format.
 */

import { createTableBlock } from '../canonicalDocument.js';

const MD_ROW_RE = /^\s*\|.*\|\s*$/;
const MD_SEPARATOR_RE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
const FIELD_SPLIT_RE = /\t+| {2,}/;

function splitMarkdownRow(line) {
  const inner = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return inner.split('|').map((c) => c.trim());
}

/**
 * Split a text block into paragraph/table blocks.
 * @param {string} text
 * @param {{ nextIndex: () => string, page?: number|null, section?: string|null }} ids
 * @returns {object[]}
 */
export function textToBlocksWithTables(text, ids) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  const blocks = [];
  let prose = [];
  const flushProse = () => {
    const t = prose.join(' ').replace(/\s+/g, ' ').trim();
    prose = [];
    if (!t) return;
    blocks.push({ id: ids.nextIndex(), type: 'paragraph', text: t, page: ids.page ?? null, section: ids.section ?? null });
  };
  const pushTable = (rows, headers, source) => {
    const block = createTableBlock({
      id: ids.nextIndex(),
      page: ids.page ?? null,
      section: ids.section ?? null,
      headers,
      rows,
      source
    });
    if (block) blocks.push(block);
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    // Markdown pipe table
    if (MD_ROW_RE.test(line)) {
      const rows = [];
      let headers = null;
      let j = i;
      while (j < lines.length && MD_ROW_RE.test(lines[j])) {
        if (MD_SEPARATOR_RE.test(lines[j])) {
          if (rows.length === 1 && !headers) headers = rows.pop();
        } else {
          rows.push(splitMarkdownRow(lines[j]));
        }
        j += 1;
      }
      if (rows.length + (headers ? 1 : 0) >= 2 && Math.max(...rows.map((r) => r.length), headers ? headers.length : 0) >= 2) {
        flushProse();
        pushTable(rows, headers, 'text_markdown');
        i = j;
        continue;
      }
    }
    // Tab / multi-space aligned rows: ≥2 consecutive lines with the same field count (≥2)
    const fields = line.trim() ? line.trim().split(FIELD_SPLIT_RE).map((f) => f.trim()).filter(Boolean) : [];
    if (fields.length >= 2) {
      let j = i + 1;
      const rows = [fields];
      while (j < lines.length) {
        const f = lines[j].trim() ? lines[j].trim().split(FIELD_SPLIT_RE).map((x) => x.trim()).filter(Boolean) : [];
        if (f.length !== fields.length) break;
        rows.push(f);
        j += 1;
      }
      if (rows.length >= 2) {
        flushProse();
        pushTable(rows, null, 'text_aligned');
        i = j;
        continue;
      }
    }
    prose.push(line);
    i += 1;
  }
  flushProse();
  return blocks;
}
