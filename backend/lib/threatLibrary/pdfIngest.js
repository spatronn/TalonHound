/**
 * PDF upload → canonical document (page-aware).
 * Uses pdf-parse for native text extraction. Scanned PDFs are flagged (no OCR in V1).
 */

import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { PDF_MAX_BYTES } from './constants.js';
import {
  createCanonicalDocument,
  isEffectivelyEmptyDocument
} from './canonicalDocument.js';
import { meaningfulCharCount } from './extract/quality.js';
import { pagesToBlocks, plainTextToBlocks, PDF_LAYOUT_VERSION } from './pdfLayout.js';

/** Bump when block segmentation changes; older canonical documents are re-extracted from the stored PDF. */
export const THREAT_LIBRARY_PDF_EXTRACTOR_VERSION = PDF_LAYOUT_VERSION;

const require = createRequire(import.meta.url);

/**
 * Load pdf-parse via its library entry (avoids package root side effects).
 * @returns {(buf: Buffer, opts?: object) => Promise<object>}
 */
function loadPdfParse() {
  // Prefer the implementation module; package root historically ran debug probes.
  try {
    return require('pdf-parse/lib/pdf-parse.js');
  } catch {
    // Fallback for alternate layouts
    // eslint-disable-next-line import/no-commonjs
    const mod = require('pdf-parse');
    return mod?.default || mod;
  }
}

/**
 * @param {Buffer} buffer
 * @param {{ fileName?: string, maxBytes?: number, mimeType?: string|null }} [opts]
 */
export function validatePdfBuffer(buffer, opts = {}) {
  const maxBytes = opts.maxBytes || PDF_MAX_BYTES;
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return {
      ok: false,
      code: 'pdf_upload_failed',
      error: 'PDF file is required'
    };
  }
  if (buffer.length > maxBytes) {
    return {
      ok: false,
      code: 'pdf_too_large',
      error: `PDF exceeds maximum size (${maxBytes} bytes)`
    };
  }
  const head = buffer.subarray(0, 5).toString('latin1');
  if (head !== '%PDF-') {
    return {
      ok: false,
      code: 'pdf_invalid',
      error: 'The uploaded file is not a valid PDF (missing %PDF- header)'
    };
  }

  // Encryption / password markers (common in trailer / Encrypt dict)
  const probe = buffer.subarray(0, Math.min(buffer.length, 512_000)).toString('latin1');
  if (/\/Encrypt\b/.test(probe) || /\/Filter\s*\/Standard\b/.test(probe)) {
    return {
      ok: false,
      code: 'pdf_password_required',
      error: 'PDF is encrypted or password-protected and cannot be imported.'
    };
  }

  const fileName = sanitizePdfFileName(opts.fileName || 'report.pdf');
  return {
    ok: true,
    fileName,
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    sizeBytes: buffer.length,
    mimeHint: opts.mimeType || null
  };
}

/**
 * Accept browser MIME hints when magic bytes already proved PDF.
 * @param {string|null|undefined} mime
 * @param {string|null|undefined} originalName
 */
export function isAcceptablePdfUploadMeta(mime, originalName) {
  const m = String(mime || '').toLowerCase().split(';')[0].trim();
  const name = String(originalName || '').toLowerCase();
  if (!m || m === 'application/pdf' || m === 'application/x-pdf') return true;
  // Browsers sometimes send generic types for Print-to-PDF / local files.
  if ((m === 'application/octet-stream' || m === 'binary/octet-stream') && name.endsWith('.pdf')) {
    return true;
  }
  // Extension fallback when MIME is empty/unknown — magic bytes are authoritative later.
  if (name.endsWith('.pdf')) return true;
  return false;
}

/**
 * @param {string} name
 */
export function sanitizePdfFileName(name) {
  const base = String(name || 'report.pdf').split(/[/\\]/).pop() || 'report.pdf';
  const cleaned = base.replace(/[^\w.\- ()[\]]+/g, '_').slice(0, 180);
  return cleaned.toLowerCase().endsWith('.pdf') ? cleaned : `${cleaned}.pdf`;
}

function classifyPdfParseError(err) {
  const msg = String(err?.message || err || '');
  if (/password|encrypted|EncryptDict|No password given/i.test(msg)) {
    return {
      code: 'pdf_password_required',
      message: 'PDF is encrypted or password-protected and cannot be imported.'
    };
  }
  if (/Invalid PDF structure|FormatError|bad XRef|Missing PDF header/i.test(msg)) {
    return {
      code: 'pdf_parse_failed',
      message: 'The PDF could not be parsed. The file may be corrupt or use an unsupported structure.'
    };
  }
  return {
    code: 'pdf_parse_failed',
    message: 'The PDF could not be parsed.'
  };
}

/**
 * Prefer page-aware pagerender; fall back to plain text extract.
 * @param {(buf: Buffer, opts?: object) => Promise<object>} pdfParse
 * @param {Buffer} buffer
 * @param {{ page: number, text: string }[]} pages
 */
/**
 * pdf.js (as bundled by pdf-parse 1.x) reads `buffer.buffer` and ignores
 * byteOffset. Node Buffers from fs.readFileSync / multer memory storage are
 * often slices of a shared pool, so the parser saw unrelated bytes and failed
 * with "Illegal character" / "bad XRef" — the source of the flaky first-parse
 * behaviour. A detached, exact-length copy is deterministic.
 * @param {Buffer|Uint8Array} buffer
 */
export function detachPdfBuffer(buffer) {
  const copy = new Uint8Array(buffer.length);
  copy.set(buffer);
  return copy;
}

async function extractPdfWithFallback(pdfParse, buffer, pages) {
  try {
    return await pdfParse(detachPdfBuffer(buffer), {
      pagerender: async (pageData) => {
        const textContent = await pageData.getTextContent();
        const items = textContent.items || [];
        const strings = items.map((it) => it.str || '').join(' ');
        const view = Array.isArray(pageData.view) ? pageData.view : pageData.pageInfo?.view || null;
        const pageHeight = view && view.length >= 4 ? Math.abs(Number(view[3]) - Number(view[1])) : 0;
        pages.push({ page: pages.length + 1, text: strings, items, pageHeight });
        return strings;
      }
    });
  } catch {
    // Some browser-generated PDFs fail only on custom pagerender; plain parse still works.
    pages.length = 0;
    return pdfParse(detachPdfBuffer(buffer));
  }
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
    err.code = validation.code || 'pdf_invalid';
    throw err;
  }

  const pdfParse = loadPdfParse();

  /** @type {{ page: number, text: string }[]} */
  const pages = [];
  let data;
  try {
    data = await extractPdfWithFallback(pdfParse, buffer, pages);
  } catch (parseErr) {
    // pdf.js occasionally throws transient "bad XRef" on first open of browser PDFs.
    pages.length = 0;
    try {
      data = await extractPdfWithFallback(pdfParse, buffer, pages);
    } catch (retryErr) {
      const classified = classifyPdfParseError(retryErr);
      const err = new Error(classified.message);
      err.code = classified.code;
      throw err;
    }
  }

  // If pagerender did not populate (some pdf-parse versions), fall back to whole text
  let blocks = [];
  let layoutMode = 'geometry';
  if (pages.length === 0) {
    layoutMode = 'plain_text';
    const full = String(data.text || '');
    const approxPages = full.split(//);
    let idx = 1;
    approxPages.forEach((pageText, i) => {
      const r = plainTextToBlocks(pageText, i + 1, idx);
      blocks = blocks.concat(r.blocks);
      idx = r.nextIdx;
    });
  } else {
    blocks = pagesToBlocks(pages).blocks;
  }

  const title =
    (data.info && (data.info.Title || data.info.title)) ||
    validation.fileName.replace(/\.pdf$/i, '') ||
    'PDF report';

  // Language hint from CJK density
  const sample = blocks.map((b) => b.text).join('').slice(0, 800);
  const cjk = (sample.match(/[\u4e00-\u9fff]/g) || []).length;
  const language = cjk >= 12 ? 'zh' : null;

  const document = createCanonicalDocument({
    title: String(title).trim() || 'PDF report',
    language,
    blocks,
    meta: {
      extractor: THREAT_LIBRARY_PDF_EXTRACTOR_VERSION,
      layout_mode: layoutMode,
      adapter: 'pdf',
      file_name: validation.fileName,
      sha256: validation.sha256,
      page_count: data.numpages || pages.length || null,
      meaningful_chars: meaningfulCharCount({ blocks })
    }
  });

  const requiresOcr = isEffectivelyEmptyDocument(document);

  return {
    document,
    requiresOcr,
    fileName: validation.fileName,
    sha256: validation.sha256,
    sizeBytes: validation.sizeBytes,
    pageCount: data.numpages || pages.length || 0,
    meaningfulChars: meaningfulCharCount(document)
  };
}
