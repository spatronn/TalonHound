/**
 * Extraction reliability follow-ups to import audit 35880–35889.
 *
 * 1. Structured-fallback HTML documents. The fallback reads blocks with
 *    htmlBlocks, but its extractor id stayed `threat_library_html_fallback_v4`
 *    through htmlBlocks v7–v12. A stored fallback document therefore always
 *    looked contract-current, so Refresh never rebuilt it, and the
 *    React-streaming reconstruction (htmlBlocks v12) could not reach 35888.
 *    From fallback v5 a fallback document records the htmlBlocks version it was
 *    read with, and it is current only while that version matches.
 *
 * 2. Linked PDF IOC sources. pdfIngest.pdfToCanonicalDocument returns
 *    { document, requiresOcr, … }, and parseIocSourceContent read that wrapper
 *    as the document. The ESET 35880 white paper (18 Cereal SHA-1) therefore
 *    parsed "ok" with 0 values. A linked PDF is a full report, not an IOC pack,
 *    so its candidates are scoped to its own report Indicator membership.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  CURRENT_HTML_EXTRACTOR_VERSIONS,
  THREAT_LIBRARY_HTML_EXTRACTOR_VERSION,
  THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION,
  extractStructuredFallbackDocument
} from './extract/extractHtml.js';
import { HTML_BLOCKS_VERSION } from './extract/htmlBlocks.js';
import { extractReportCandidates, isDocumentContractCurrent } from './extractionStages.js';
import { computeExtractionRefresh, prepareRefreshDocument } from './extractionRefresh.js';
import { storeArtifactBuffer } from './artifactStore.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { pdfToCanonicalDocument } from './pdfIngest.js';
import { buildPreviewFromParses, parseIocSourceContent } from './iocSources/parseContent.js';
import { IOC_SOURCE_SCOPE_VERSION } from './iocSources/campaignScope.js';

const SOURCE = 'https://vendor-research.example/blog/fallback-refresh/';
const URL_REPORT = { source_type: 'url', source_url: SOURCE };

const idOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const members = (report, document) =>
  extractReportCandidates(report, document).candidates
    .filter((c) => isReportIndicatorMember({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) }))
    .map(idOf)
    .sort();

// --- 1. Structured-fallback contract ------------------------------------------

const row = (v, t, d) => `<tr><td><p>${v}</p></td><td><p>${t}</p></td><td><p>${d}</p></td></tr>`;

/** No <article>/<main>: only a content-hinted div, so the structured fallback reads it. */
function streamedFallbackPage({ withInstructions = true } = {}) {
  return `<!doctype html><html lang="en"><head><title>Streamed fallback</title></head><body>
<div class="post-content">
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
<h2>Analysis</h2>
<p>The loader beacons to its staging server and pulls a second stage over HTTPS.</p>
<h2>E. Network indicators</h2>
<table><thead><tr><th>Indicator</th><th>Type</th><th>Description</th></tr></thead>
<tbody>${row('hxxps://198.51.100[.]10/s', 'URL', 'Stager download path')}<template id="P:5"></template></tbody></table>
<h2>F. Conclusion</h2>
<p>The actor continues to evolve its toolset and infrastructure over time.</p>
</div>
<table hidden><tbody id="S:5">${row('198.51.100[.]10', 'IPv4', 'Stager hosting and beacon endpoint')}${row('lookalike-signin[.]example', 'Domain', 'Device-code phishing lookalike')}${row('203.0.113[.]77', 'IPv4', 'Primary C2 VPS')}</tbody></table>
${withInstructions ? '<script>$RS=function(a,b){};$RS("S:5","P:5")</script>' : ''}
</body></html>`;
}

const STREAMED_MEMBERS = ['domain:lookalike-signin.example', 'ip:198.51.100.10', 'ip:203.0.113.77', 'url:https://198.51.100.10/s'];

/** What production stored for 35888 before this change: fallback v4, no html_blocks, the segment rows missing. */
function legacyFallbackDocument() {
  const doc = extractStructuredFallbackDocument(streamedFallbackPage({ withInstructions: false }), { url: SOURCE });
  const { html_blocks: _drop, ...meta } = doc.meta;
  return { ...doc, meta: { ...meta, extractor: 'threat_library_html_fallback_v4' } };
}

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION, 'threat_library_html_fallback_v5');
  assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v12');
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v12');
  assert.equal(IOC_SOURCE_SCOPE_VERSION, 'tl-ioc-source-scope-v9');
  assert.ok(!CURRENT_HTML_EXTRACTOR_VERSIONS.includes('threat_library_html_fallback_v4'));
});

test('fallback: a fallback document records the htmlBlocks version it was read with', () => {
  const doc = extractStructuredFallbackDocument(streamedFallbackPage(), { url: SOURCE });
  assert.equal(doc.meta.adapter, 'structured_fallback');
  assert.equal(doc.meta.extractor, THREAT_LIBRARY_HTML_FALLBACK_EXTRACTOR_VERSION);
  assert.equal(doc.meta.html_blocks, HTML_BLOCKS_VERSION);
  assert.equal(isDocumentContractCurrent(URL_REPORT, doc), true);
});

test('fallback: stored fallback documents of an earlier contract are not current', () => {
  // The 35888 state: fallback_v4 read with an older htmlBlocks.
  assert.equal(isDocumentContractCurrent(URL_REPORT, legacyFallbackDocument()), false);
  // The current fallback id, but read by an older (or unrecorded) block parser.
  const fresh = extractStructuredFallbackDocument(streamedFallbackPage(), { url: SOURCE });
  assert.equal(isDocumentContractCurrent(URL_REPORT, { ...fresh, meta: { ...fresh.meta, html_blocks: 'threat_library_html_v11' } }), false);
  const { html_blocks: _drop, ...unrecorded } = fresh.meta;
  assert.equal(isDocumentContractCurrent(URL_REPORT, { ...fresh, meta: unrecorded }), false);
});

test('fallback negative: current main-extractor documents stay current (no needless rebuild)', () => {
  const main = { title: 't', blocks: [{ id: 'b1', type: 'paragraph', text: 'x' }], meta: { extractor: THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, adapter: 'generic_html' } };
  assert.equal(isDocumentContractCurrent(URL_REPORT, main), true);
  // Non-URL reports are unaffected by the HTML contract.
  assert.equal(isDocumentContractCurrent({ source_type: 'text' }, { ...main, meta: { extractor: 'threat_library_html_fallback_v4' } }), true);
});

test('fallback: the structured fallback re-places React streaming segments ($RS)', () => {
  const doc = extractStructuredFallbackDocument(streamedFallbackPage(), { url: SOURCE });
  const ioc = doc.blocks.find((b) => b.type === 'table' && /Stager download path/.test(b.text || ''));
  assert.ok(ioc, 'IOC table missing');
  assert.equal(ioc.table.rows.length, 4);
  assert.deepEqual(members(URL_REPORT, doc), STREAMED_MEMBERS);
});

test('fallback negative: without a streaming instruction the hidden segment is not moved', () => {
  const doc = extractStructuredFallbackDocument(streamedFallbackPage({ withInstructions: false }), { url: SOURCE });
  const ioc = doc.blocks.find((b) => b.type === 'table' && /Stager download path/.test(b.text || ''));
  assert.equal(ioc.table.rows.length, 1);
});

function urlPoolWith(artifacts) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const text = String(sql).replace(/\s+/g, ' ');
      queries.push(text);
      if (text.includes('FROM threat_report_artifacts')) {
        const type = /artifact_type = '([a-z_]+)'/.exec(text)?.[1];
        return { rows: artifacts.filter((a) => Number(a.report_id) === Number(params[0]) && a.artifact_type === type) };
      }
      if (/FROM ioc_items|FROM ioc_|ioc_lookup/.test(text)) return { rows: [] };
      if (/INTO threat_report_(extraction_run|observable_dispositions|dropped_regions)|FROM threat_report_extraction_runs/.test(text)) {
        return { rows: /INSERT INTO threat_report_extraction_runs/.test(text) ? [{ id: 1 }] : [], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

async function withStorage(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-fallback-refresh-'));
  const prev = process.env.THREAT_LIBRARY_STORAGE_DIR;
  process.env.THREAT_LIBRARY_STORAGE_DIR = dir;
  t.after(() => {
    if (prev == null) delete process.env.THREAT_LIBRARY_STORAGE_DIR;
    else process.env.THREAT_LIBRARY_STORAGE_DIR = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  });
}

test('Refresh rebuilds a fallback_v4 document from retained HTML; the streamed rows become Indicators', async (t) => {
  await withStorage(t);
  const { storageKey } = await storeArtifactBuffer(81, Buffer.from(streamedFallbackPage(), 'utf8'), { fileName: 'source.html' });
  const legacy = legacyFallbackDocument();
  assert.deepEqual(members(URL_REPORT, legacy), ['url:https://198.51.100.10/s'], 'the stale document is missing the streamed rows');
  const report = { id: 81, ...URL_REPORT, canonical_document: legacy };
  const pool = urlPoolWith([{ id: 1, report_id: 81, artifact_type: 'url_fetch', storage_key: storageKey, source_metadata: { final_url: SOURCE, http_status: 200 } }]);

  const { document, documentRebuilt } = await prepareRefreshDocument(pool, report);
  assert.equal(documentRebuilt, true);
  assert.notEqual(document, legacy);
  assert.equal(isDocumentContractCurrent(URL_REPORT, document), true);
  assert.deepEqual(members(report, document), STREAMED_MEMBERS);
  assert.ok(pool.queries.every((q) => /^\s*SELECT /i.test(q)), 'the rebuild only reads');
});

test('Refresh keeps a current fallback document as stored (no rebuild, no artifact read)', async () => {
  const fresh = extractStructuredFallbackDocument(streamedFallbackPage(), { url: SOURCE });
  const pool = urlPoolWith([]);
  const { document, documentRebuilt } = await prepareRefreshDocument(pool, { id: 82, ...URL_REPORT, canonical_document: fresh });
  assert.equal(documentRebuilt, false);
  assert.equal(document, fresh);
  assert.equal(pool.queries.length, 0);
});

test('without retained HTML a fallback_v4 document is refused (refresh_source_unavailable), never reused', async () => {
  const report = { id: 83, ...URL_REPORT, canonical_document: legacyFallbackDocument() };
  await assert.rejects(prepareRefreshDocument(urlPoolWith([]), report), (err) => err.code === 'refresh_source_unavailable');
});

test('a rebuilt fallback refresh keeps prior analyst decisions on surviving identities', async (t) => {
  await withStorage(t);
  const { storageKey } = await storeArtifactBuffer(84, Buffer.from(streamedFallbackPage(), 'utf8'), { fileName: 'source.html' });
  const legacy = legacyFallbackDocument();
  const report = { id: 84, ...URL_REPORT, canonical_document: legacy };
  const pool = urlPoolWith([{ id: 1, report_id: 84, artifact_type: 'url_fetch', storage_key: storageKey, source_metadata: { final_url: SOURCE, http_status: 200 } }]);
  const previousRows = extractReportCandidates(report, legacy).candidates.map((c, i) => ({
    ...c,
    id: String(i + 1),
    has_original_document_occurrence: true,
    evidence: buildCandidateEvidenceRecord(c),
    review_status: idOf(c) === 'url:https://198.51.100.10/s' ? 'approved' : 'pending'
  }));
  assert.ok(previousRows.some((r) => r.review_status === 'approved'));

  const { document, documentRebuilt } = await prepareRefreshDocument(pool, report);
  assert.equal(documentRebuilt, true);
  const refreshed = await computeExtractionRefresh(pool, { report, document, previousRows, documentRebuilt });
  const approved = refreshed.candidates.find((c) => idOf(c) === 'url:https://198.51.100.10/s');
  assert.equal(approved?.review_status, 'approved');
  for (const id of STREAMED_MEMBERS.filter((x) => x !== 'url:https://198.51.100.10/s')) {
    const c = refreshed.candidates.find((x) => idOf(x) === id);
    assert.ok(c, `${id} missing after refresh`);
    assert.equal(c.review_status || 'pending', 'pending', `${id} must not be auto-approved`);
  }
});

// --- 2. Linked PDF IOC sources ------------------------------------------------

/** Byte-accurate PDF 1.4 with positioned lines: [text, x, y, fontSize]. */
function pdfWithLines(lines) {
  const content = lines
    .map(([text, x, y, size]) => `BT /F1 ${size} Tf ${x} ${y} Td (${String(text).replace(/[()\\]/g, ' ')}) Tj ET`)
    .join('\n') + '\n';
  const objs = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1200 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n',
    `4 0 obj\n<< /Length ${Buffer.byteLength(content, 'latin1')} >>\nstream\n${content}endstream\nendobj\n`,
    '5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n'
  ];
  let body = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
  const offsets = [0];
  for (const obj of objs) {
    offsets.push(Buffer.byteLength(body, 'latin1'));
    body += obj;
  }
  const xrefStart = Buffer.byteLength(body, 'latin1');
  let xref = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objs.length; i += 1) xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  body += `${xref}trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(body, 'latin1');
}

const sha1 = (s) => crypto.createHash('sha1').update(`linked-pdf:${s}`).digest('hex');
const md5 = (s) => crypto.createHash('md5').update(`linked-pdf:${s}`).digest('hex');
const SAMPLES = ['loader.dll', 'runner.exe', 'neuron.dll'].map((file) => ({ file, hash: sha1(file) }));
const PATH_DIGEST = md5('native-image-cache-dir');

/** A white paper: prose (with a path that embeds a digest) and an IOC appendix. */
const WHITE_PAPER = pdfWithLines([
  ['The loader was copied into the native image cache rather than generated by the image generator tool.', 50, 740, 10],
  [`An example path is C:/Windows/assembly/NativeImages/Example#/${PATH_DIGEST}/Example.ni.dll on the server.`, 50, 726, 10],
  ['Further background on the campaign is published at nato.int for reference.', 50, 712, 10],
  ['Indicators of Compromise', 50, 670, 16],
  ['Files', 50, 650, 12],
  [SAMPLES.map((s) => `${s.file} ${s.hash}`).join(' '), 50, 630, 10],
  ['Conclusion', 50, 590, 16],
  ['The actor continues to evolve its toolset and infrastructure over time.', 50, 570, 10]
]);

const PDF_URL = 'https://vendor-research.example/papers/white-paper.pdf';
const parsePdf = (buffer, extra = {}) => parseIocSourceContent({
  body: buffer.toString('utf8'),
  buffer,
  contentType: 'application/pdf',
  url: PDF_URL,
  path: null,
  sourcePublicId: 'src_pdf',
  pdfToDocument: pdfToCanonicalDocument,
  reportScope: {},
  ...extra
});

test('linked PDF: the real pdfIngest result yields the appendix hashes (was 0)', async () => {
  const parsed = await parsePdf(WHITE_PAPER);
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  assert.equal(parsed.format, 'pdf');
  const got = parsed.candidates.map(idOf).sort();
  assert.deepEqual(got, SAMPLES.map((s) => `sha1:${s.hash}`).sort());
  assert.ok(parsed.candidates.every((c) => c.source_assertion === 'linked_source_ioc' && c.has_original_document_occurrence === false));
  const preview = buildPreviewFromParses([{ ...parsed, path: null }], {});
  assert.equal(preview.unique_count, 3);
  assert.equal(preview.new_identities, 3);
});

test('linked PDF negative: prose digests and reference domains are not linked Indicators', async () => {
  const parsed = await parsePdf(WHITE_PAPER);
  const ids = parsed.candidates.map(idOf);
  assert.ok(!ids.includes(`md5:${PATH_DIGEST}`), 'a digest embedded in a prose file path became an Indicator');
  assert.ok(!ids.some((x) => x.startsWith('domain:')), ids.join(', '));
});

test('linked PDF negative: a PDF with no extractable text is reported, not an empty success', async () => {
  const parsed = await parsePdf(WHITE_PAPER, { pdfToDocument: async () => ({ document: null, requiresOcr: true, pageCount: 3 }) });
  assert.equal(parsed.ok, false);
  assert.equal(parsed.code, 'pdf_requires_ocr');
  const empty = await parsePdf(WHITE_PAPER, { pdfToDocument: async () => ({ document: { title: 't', blocks: [], meta: {} }, requiresOcr: false }) });
  assert.equal(empty.ok, false);
  assert.equal(empty.code, 'parse_failed');
});

test('linked PDF: an injected parser returning a bare canonical document still works', async () => {
  const bare = async (buf, opts) => (await pdfToCanonicalDocument(buf, opts)).document;
  const parsed = await parsePdf(WHITE_PAPER, { pdfToDocument: bare });
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.candidates.map(idOf).sort(), SAMPLES.map((s) => `sha1:${s.hash}`).sort());
});

test('linked text packs keep pack semantics (membership scoping is PDF-only)', async () => {
  const body = `Hashes\n${SAMPLES.map((s) => s.hash).join('\n')}\n${PATH_DIGEST}\n`;
  const parsed = await parseIocSourceContent({ body, contentType: 'text/plain', url: 'https://vendor-research.example/iocs.txt', sourcePublicId: 'src_txt', reportScope: {} });
  assert.equal(parsed.ok, true);
  const ids = parsed.candidates.map(idOf);
  for (const s of SAMPLES) assert.ok(ids.includes(`sha1:${s.hash}`));
  assert.ok(ids.includes(`md5:${PATH_DIGEST}`), 'a plain IOC list keeps every listed value');
});
