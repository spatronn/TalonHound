/**
 * URL import of a report published as a PDF (report 35552: a Virus Bulletin
 * conference paper URL). URL import used to fail every such report with
 * `pdf_via_url_unsupported`; it now runs the PDF extractor on the raw bytes
 * and the pipeline retains the PDF like an upload.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchFeedUrl } from '../customThreatFeedFetch.js';
import { ingestUrlToCanonicalDocument, pdfFileNameFromUrl } from './urlIngest.js';
import { isDocumentContractCurrent, rebuildDocumentFromRetainedSource } from './extractionStages.js';
import { THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } from './pdfIngest.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const PDF = fs.readFileSync(path.join(here, 'extract', 'fixtures', 'browser-print-cjk.pdf'));
const loopback = { lookup: async () => [{ address: '127.0.0.1', family: 4 }], isForbiddenAddress: () => false };

function serve(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    server.on('error', reject);
  });
}
const close = (server) => new Promise((resolve) => server.close(() => resolve()));

test('fetchFeedUrl returns the raw body bytes (a UTF-8 decode corrupts binary PDFs)', async () => {
  const { server, port } = await serve((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/pdf' });
    res.end(PDF);
  });
  try {
    const r = await fetchFeedUrl(`http://reports.example.com:${port}/paper.pdf`, { ...loopback, timeoutMs: 5000 });
    assert.ok(Buffer.isBuffer(r.bodyBuffer));
    assert.ok(r.bodyBuffer.equals(PDF));
    assert.ok(!Buffer.from(r.bodyText, 'utf8').equals(PDF), 'fixture must contain non-UTF-8 bytes');
  } finally {
    await close(server);
  }
});

test('URL serving a PDF is extracted with the PDF extractor (was pdf_via_url_unsupported)', async () => {
  const { server, port } = await serve((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/pdf' });
    res.end(PDF);
  });
  try {
    const url = `http://reports.example.com:${port}/uploads/pdf/Break-the-silence.pdf`;
    const r = await ingestUrlToCanonicalDocument(url, { fetchDeps: loopback });
    assert.equal(r.contentType, 'application/pdf');
    assert.equal(r.bodyText, null, 'a PDF is never retained as source HTML');
    assert.ok(r.pdf.buffer.equals(PDF));
    assert.equal(r.pdf.fileName, 'Break-the-silence.pdf');
    assert.equal(r.document.meta.adapter, 'pdf');
    assert.equal(r.document.meta.extractor, THREAT_LIBRARY_PDF_EXTRACTOR_VERSION);
    assert.ok(r.document.blocks.length > 0);
    assert.ok(isDocumentContractCurrent({ source_type: 'url' }, r.document), 'URL-PDF document is current under the PDF contract');
  } finally {
    await close(server);
  }
});

test('PDF magic bytes behind a non-PDF content type still take the PDF path', async () => {
  const { server, port } = await serve((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(PDF);
  });
  try {
    const r = await ingestUrlToCanonicalDocument(`http://reports.example.com:${port}/download?id=7`, { fetchDeps: loopback });
    assert.equal(r.document.meta.adapter, 'pdf');
    assert.equal(r.pdf.fileName, 'download.pdf');
  } finally {
    await close(server);
  }
});

test('HTTP error serving a PDF fails as a fetch error, not as an extracted report', async () => {
  const { server, port } = await serve((_req, res) => {
    res.writeHead(404, { 'Content-Type': 'application/pdf' });
    res.end(PDF);
  });
  try {
    await assert.rejects(
      ingestUrlToCanonicalDocument(`http://reports.example.com:${port}/gone.pdf`, { fetchDeps: loopback }),
      (err) => err.code === 'fetch_http_error'
    );
  } finally {
    await close(server);
  }
});

test('HTML URL reports keep the HTML contract (negative)', async () => {
  const html = `<html><head><title>Report</title></head><body><article><h1>Report</h1>${'<p>Threat actors used infrastructure for command and control operations across several sectors.</p>'.repeat(8)}</article></body></html>`;
  const { server, port } = await serve((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });
  try {
    const r = await ingestUrlToCanonicalDocument(`http://reports.example.com:${port}/blog/post`, { fetchDeps: loopback });
    assert.equal(r.pdf, undefined);
    assert.equal(r.bodyText, html);
    assert.notEqual(r.document.meta.adapter, 'pdf');
    assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { ...r.document, meta: { ...r.document.meta, extractor: THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } }), false);
  } finally {
    await close(server);
  }
});

test('rebuildDocumentFromRetainedSource re-extracts a URL report from its retained PDF', async () => {
  process.env.THREAT_LIBRARY_STORAGE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-urlpdf-'));
  const fs2 = await import('./artifactStore.js');
  const stored = await fs2.storeArtifactBuffer(999_001, PDF, { fileName: 'paper.pdf', ext: '.pdf' });
  const pool = {
    async query(sql) {
      if (/artifact_type = 'pdf_upload'/.test(sql)) return { rows: [{ storage_key: stored.storageKey, file_name: 'paper.pdf' }] };
      throw new Error(`unexpected query: ${sql}`);
    }
  };
  const rebuilt = await rebuildDocumentFromRetainedSource(pool, { id: 999_001, source_type: 'url', source_url: 'https://x.example/paper.pdf' });
  assert.ok(rebuilt);
  assert.equal(rebuilt.sourceHtml, null);
  assert.equal(rebuilt.document.meta.adapter, 'pdf');
});

test('pdfFileNameFromUrl', () => {
  assert.equal(pdfFileNameFromUrl('https://a.example/x/Report%20One.pdf'), 'Report One.pdf');
  assert.equal(pdfFileNameFromUrl('https://a.example/'), 'report.pdf');
  assert.equal(pdfFileNameFromUrl('not a url'), 'report.pdf');
});
