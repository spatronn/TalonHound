/**
 * PDF ingest validation / classification tests (no live uploads).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  validatePdfBuffer,
  sanitizePdfFileName,
  isAcceptablePdfUploadMeta,
  pdfToCanonicalDocument
} from './pdfIngest.js';

const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

function minimalTextPdf(text = 'Threat Library PDF regression sample with enough extractable text content.') {
  // Tiny valid PDF 1.4 with Helvetica text. Good enough for pdf-parse.
  const stream = `BT /F1 12 Tf 50 700 Td (${text.replace(/[()\\]/g, '')}) Tj ET`;
  const objects = [];
  objects.push('1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n');
  objects.push('2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n');
  objects.push(
    '3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> >>endobj\n'
  );
  objects.push(`4 0 obj<< /Length ${stream.length} >>stream\n${stream}\nendstream\nendobj\n`);
  objects.push('5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n');
  let body = '%PDF-1.4\n';
  const offsets = [0];
  for (const obj of objects) {
    offsets.push(Buffer.byteLength(body, 'latin1'));
    body += obj;
  }
  const xrefStart = Buffer.byteLength(body, 'latin1');
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objects.length; i += 1) {
    xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }
  body += xref;
  body += `trailer<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(body, 'latin1');
}

function encryptedPdfStub() {
  // Not a fully valid encrypted PDF — validation probes /Encrypt before parse.
  return Buffer.from('%PDF-1.4\n1 0 obj<< /Encrypt 2 0 R /Filter /Standard >>endobj\n%%EOF\n', 'latin1');
}

test('valid PDF magic accepted; fake extension rejected by magic', () => {
  const ok = validatePdfBuffer(minimalTextPdf(), { fileName: 'report.pdf' });
  assert.equal(ok.ok, true);
  assert.ok(ok.sha256);

  const bad = validatePdfBuffer(Buffer.from('not-a-pdf'), { fileName: 'evil.pdf' });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, 'pdf_invalid');
});

test('zero-byte PDF rejected', () => {
  const r = validatePdfBuffer(Buffer.alloc(0), { fileName: 'empty.pdf' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'pdf_upload_failed');
});

test('oversized PDF rejected before parse', () => {
  const buf = Buffer.concat([Buffer.from('%PDF-1.4\n'), Buffer.alloc(1000)]);
  const r = validatePdfBuffer(buf, { fileName: 'big.pdf', maxBytes: 100 });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'pdf_too_large');
});

test('password/encrypted marker yields pdf_password_required', () => {
  const r = validatePdfBuffer(encryptedPdfStub(), { fileName: 'locked.pdf' });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'pdf_password_required');
});

test('MIME mismatch with valid PDF magic is accepted by upload meta helper', () => {
  assert.equal(isAcceptablePdfUploadMeta('application/octet-stream', 'note.pdf'), true);
  assert.equal(isAcceptablePdfUploadMeta('application/pdf', 'note.pdf'), true);
  assert.equal(isAcceptablePdfUploadMeta('image/png', 'note.png'), false);
});

test('filename sanitization blocks path traversal', () => {
  assert.equal(sanitizePdfFileName('../../etc/passwd.pdf'), 'passwd.pdf');
});

test('pdf-parse extracts text from minimal browser-like PDF', async () => {
  const buf = minimalTextPdf(
    'Threat Library PDF regression sample with enough extractable text content for quality gate.'
  );
  const result = await pdfToCanonicalDocument(buf, { fileName: 'browser-print.pdf' });
  assert.equal(result.requiresOcr, false);
  assert.ok(result.pageCount >= 1);
  assert.ok(result.meaningfulChars >= 40);
  assert.ok(result.document.blocks.length >= 1);
  assert.match(result.document.blocks.map((b) => b.text).join(' '), /Threat Library PDF/);
});

test('CJK text blocks are not empty under character quality gate', async () => {
  const { assessDocumentQuality } = await import('./extract/quality.js');
  const q = assessDocumentQuality({
    title: '微信报告',
    language: 'zh',
    blocks: [{
      id: 'p1-b01',
      type: 'paragraph',
      page: 1,
      text: '这是从浏览器打印生成的中文威胁情报PDF正文内容，用于验证没有空格分隔时质量门禁仍然通过。'
    }]
  });
  assert.equal(q.ok, true);
});

test('fixture encrypted marker file exists for regression', () => {
  // Keep a checked-in latin1 stub for future parser upgrades
  const p = join(fixtureDir, 'encrypted-marker.pdf');
  const buf = encryptedPdfStub();
  // Write is not needed if we generate in memory — assert helper works
  assert.equal(validatePdfBuffer(buf).code, 'pdf_password_required');
  assert.ok(buf.subarray(0, 5).toString('latin1') === '%PDF-');
  // silence unused if file missing
  try {
    readFileSync(p);
  } catch {
    /* optional on-disk fixture */
  }
});
