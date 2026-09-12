/**
 * PDF upload → canonical document (page-aware).
 * Uses pdf-parse for native text extraction. Scanned PDFs are flagged (no OCR in V1).
 */

import crypto from 'node:crypto';
import { PDF_MAX_BYTES } from './constants.js';
import {
  createCanonicalDocument,
  blockId,
  isEffectivelyEmptyDocument
} from './canonicalDocument.js';

/**
 * @param {Buffer} buffer
 * @param {{ fileName?: string, maxBytes?: number }} [opts]
 */
export function validatePdfBuffer(buffer, opts = {}) {
  const maxBytes = opts.maxBytes || PDF_MAX_BYTES;
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { ok: false, error: 'PDF file is required' };
  }
  if (buffer.length > maxBytes) {
    return { ok: false, error: `PDF exceeds maximum size (${maxBytes} bytes)` };
  }
  const head = buffer.subarray(0, 5).toString('utf8');
  if (head !== '%PDF-') {
    return { ok: false, error: 'File is not a valid PDF (missing %PDF- header)' };
  }
  const fileName = sanitizePdfFileName(opts.fileName || 'report.pdf');
  return { ok: true, fileName, sha256: crypto.createHash('sha256').update(buffer).digest('hex'), sizeBytes: buffer.length };
}

/**
 * @param {string} name
 */
export function sanitizePdfFileName(name) {
  const base = String(name || 'report.pdf').split(/[/\\]/).pop() || 'report.pdf';
  const cleaned = base.replace(/[^\w.\- ()[\]]+/g, '_').slice(0, 180);
  return cleaned.toLowerCase().endsWith('.pdf') ? cleaned : `${cleaned}.pdf`;
}

/**
 * Split page text into blocks.
 * @param {string} pageText
 * @param {number} pageNum
 * @param {number} startIdx
 */
function pageTextToBlocks(pageText, pageNum, startIdx) {
  const blocks = [];
  let idx = startIdx;
  const lines = String(pageText || '').split(/\n+/).map((l) => l.trim()).filter(Boolean);
  let para = [];
  const flush = (type = 'paragraph') => {
    if (!para.length) return;
    const text = para.join(' ').replace(/\s+/g, ' ').trim();
    para = [];
    if (!text) return;
    blocks.push({
      id: `p${pageNum}-b${String(idx).padStart(2, '0')}`,
      type,
      text,
      page: pageNum,
      section: null
    });
    idx += 1;
  };

  for (const line of lines) {
    const isHeading = line.length < 80 && !/[.!?]$/.test(line) && /^[A-Z0-9]/.test(line) && line === line.toUpperCase();
    if (isHeading) {
      flush('paragraph');
      blocks.push({
        id: `p${pageNum}-b${String(idx).padStart(2, '0')}`,
        type: 'heading',
        text: line,
        page: pageNum,
        section: line.slice(0, 200)
      });
      idx += 1;
      continue;
    }
    para.push(line);
    if (para.join(' ').length > 600) flush('paragraph');
  }
  flush('paragraph');
  return { blocks, nextIdx: idx };
}

/**
 * Extract text by page using pdf-parse.
 * @param {Buffer} buffer
 * @param {{ fileName?: string }} [opts]
 */
export async function pdfToCanonicalDocument(buffer, opts = {}) {
  const validation = validatePdfBuffer(buffer, opts);
  if (!validation.ok) {
    const err = new Error(validation.error);
    err.code = 'invalid_pdf';
    throw err;
  }

  // Dynamic import so unit tests can mock and Docker image installs the dep.
  const pdfParseMod = await import('pdf-parse');
  const pdfParse = pdfParseMod.default || pdfParseMod;

  /** @type {{ page: number, text: string }[]} */
  const pages = [];
  const data = await pdfParse(buffer, {
    pagerender: async (pageData) => {
      const textContent = await pageData.getTextContent();
      const strings = (textContent.items || []).map((it) => it.str || '').join(' ');
      pages.push({ page: pages.length + 1, text: strings });
      return strings;
    }
  });

  // If pagerender did not populate (some pdf-parse versions), fall back to whole text
  let blocks = [];
  if (pages.length === 0) {
    const full = String(data.text || '');
    const approxPages = full.split(/\f/);
    let idx = 1;
    approxPages.forEach((pageText, i) => {
      const r = pageTextToBlocks(pageText, i + 1, idx);
      blocks = blocks.concat(r.blocks);
      idx = r.nextIdx;
    });
  } else {
    let idx = 1;
    for (const p of pages) {
      const r = pageTextToBlocks(p.text, p.page, idx);
      blocks = blocks.concat(r.blocks);
      idx = r.nextIdx;
    }
  }

  const title =
    (data.info && (data.info.Title || data.info.title)) ||
    validation.fileName.replace(/\.pdf$/i, '') ||
    'PDF report';

  const document = createCanonicalDocument({
    title: String(title).trim() || 'PDF report',
    language: null,
    blocks,
    meta: {
      extractor: 'threat_library_pdf_v1',
      file_name: validation.fileName,
      sha256: validation.sha256,
      page_count: data.numpages || pages.length || null
    }
  });

  const requiresOcr = isEffectivelyEmptyDocument(document);

  return {
    document,
    requiresOcr,
    fileName: validation.fileName,
    sha256: validation.sha256,
    sizeBytes: validation.sizeBytes,
    pageCount: data.numpages || pages.length || 0
  };
}
