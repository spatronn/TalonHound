/**
 * threat_library_pdf_v5 → v6 contract transition on Refresh extraction.
 *
 * A stored pdf_v5 canonical document is not contract-current under pdf_v6:
 * Refresh rebuilds it from the stored PDF upload (never re-fetches, never
 * reuses the v5 blocks), and refuses with refresh_source_unavailable when no
 * upload was retained. The rebuilt document carries the v6 row structure for
 * a dense filename/hash line, so its hashes become publisher Indicators.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { prepareRefreshDocument } from './extractionRefresh.js';
import { isDocumentContractCurrent, extractReportCandidates } from './extractionStages.js';
import { THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } from './pdfIngest.js';
import { storeArtifactBuffer } from './artifactStore.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';

const md5 = (s) => crypto.createHash('md5').update(`pdf-contract:${s}`).digest('hex');
const SAMPLES = ['vulkan-1.dll', 'oleasapi.dll', 'loader.exe'].map((file) => ({ file, hash: md5(file) }));

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

const PDF = pdfWithLines([
  ['The intrusion set deploys a modular loader chain against several regional targets across multiple waves.', 50, 720, 10],
  ['Analysts should review the artifacts listed in the appendix below for detection coverage.', 50, 706, 10],
  ['Indicators of compromise', 50, 670, 16],
  [SAMPLES.map((s) => `${s.file} ${s.hash}`).join(' '), 50, 640, 10],
  ['Conclusion', 50, 600, 16],
  ['The actor continues to evolve its toolset and infrastructure over time.', 50, 580, 10]
]);

/** The same content as pdf_v5 stored it: the dense line merged into a narrative paragraph. */
const V5_DOCUMENT = {
  title: 'Contract report',
  blocks: [
    { id: 'p1-b01', type: 'paragraph', text: 'The intrusion set deploys a modular loader chain.', page: 1 },
    { id: 'p1-b02', type: 'heading', text: 'Indicators of compromise', level: 2, page: 1 },
    { id: 'p1-b03', type: 'paragraph', text: `Samples observed: ${SAMPLES.map((s) => `${s.file} ${s.hash}`).join(' ')}`, page: 1 },
    { id: 'p1-b04', type: 'heading', text: 'Conclusion', level: 2, page: 1 }
  ],
  meta: { extractor: 'threat_library_pdf_v5', adapter: 'pdf' }
};

function poolWith(artifacts) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const text = String(sql).replace(/\s+/g, ' ');
      queries.push(text);
      if (text.includes('FROM threat_report_artifacts') && text.includes("artifact_type = 'pdf_upload'")) {
        return { rows: artifacts.filter((a) => Number(a.report_id) === Number(params[0])) };
      }
      throw new Error(`unexpected SQL: ${text.slice(0, 120)}`);
    }
  };
}

const members = (report, document) =>
  extractReportCandidates(report, document).candidates
    .filter((c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) }))
    .map((c) => `${c.candidate_type}:${c.normalized_value}`)
    .sort();

test('pdf_v5 stored documents are not contract-current under pdf_v6', () => {
  assert.equal(THREAT_LIBRARY_PDF_EXTRACTOR_VERSION, 'threat_library_pdf_v6');
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, V5_DOCUMENT), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { ...V5_DOCUMENT, meta: { ...V5_DOCUMENT.meta, extractor: 'threat_library_pdf_v6' } }), true);
});

test('Refresh rebuilds a pdf_v5 document from the stored PDF upload; dense inventory hashes become Indicators', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-pdf-contract-'));
  const prev = process.env.THREAT_LIBRARY_STORAGE_DIR;
  process.env.THREAT_LIBRARY_STORAGE_DIR = dir;
  t.after(() => {
    if (prev == null) delete process.env.THREAT_LIBRARY_STORAGE_DIR;
    else process.env.THREAT_LIBRARY_STORAGE_DIR = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const stored = await storeArtifactBuffer(71, PDF, { fileName: 'report.pdf' });
  const { storageKey } = stored;
  assert.ok(storageKey, JSON.stringify(stored));
  const report = { id: 71, source_type: 'pdf', source_file_name: 'report.pdf', canonical_document: V5_DOCUMENT };
  const pool = poolWith([{ id: 1, report_id: 71, artifact_type: 'pdf_upload', storage_key: storageKey, file_name: 'report.pdf' }]);

  // Under the stored v5 document the hashes were narrative, never Indicators.
  assert.deepEqual(members(report, V5_DOCUMENT).filter((id) => id.startsWith('md5:')), []);

  const { document, documentRebuilt } = await prepareRefreshDocument(pool, report);
  assert.equal(documentRebuilt, true);
  assert.equal(document.meta.extractor, 'threat_library_pdf_v6');
  assert.notEqual(document, V5_DOCUMENT);
  const row = document.blocks.find((b) => SAMPLES.every((s) => String(b.text).includes(s.hash)));
  assert.ok(row, JSON.stringify(document.blocks.map((b) => [b.type, b.text])));
  assert.equal(row.layout, 'observable_row');
  assert.deepEqual(row.text.split('\n'), SAMPLES.map((s) => `${s.file} ${s.hash}`));
  assert.deepEqual(members(report, document), SAMPLES.map((s) => `md5:${s.hash}`).sort());
  assert.ok(pool.queries.every((q) => /^\s*SELECT /i.test(q)), 'the rebuild only reads');
});

test('without a retained PDF upload a pdf_v5 document is refused (refresh_source_unavailable), never reused', async () => {
  const report = { id: 72, source_type: 'pdf', canonical_document: V5_DOCUMENT };
  await assert.rejects(prepareRefreshDocument(poolWith([]), report), (err) => err.code === 'refresh_source_unavailable');
});
