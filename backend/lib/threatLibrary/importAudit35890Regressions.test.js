/**
 * Import audit 35890–35901 regressions (threat_library_html_v13,
 * threat_library_pdf_v9, tl-candidates-v68, tl-section-tree-v20,
 * tl-quality-v17, tl-published-at-v6).
 *
 *  FN-1 (35901 BI.ZONE): the article, its "Indicators of compromise" section
 *       and ATT&CK table were server-rendered inside `<template v-slot:content>`;
 *       htmlBlocks dropped every <template> as noise (8-block stub, 0 of 42
 *       Indicators, quality only "warning").
 *  FN-2 (35894 FBI FLASH PDF): Indicator | Context | Source tables set their
 *       rows at the wrapped-line pitch and stack several IPs in one cell; pdf_v8
 *       merged the whole table into one row, rejected it and flattened it into
 *       paragraphs (11 of 25 Indicators). The PDF had no Title metadata (the
 *       report was named "261113") and its date sits in the page-header band.
 *  FP guard: rebuilding the "Indicator Type | Description | Source" behavioral
 *       table must not turn the legitimate LLM API endpoints in its Description
 *       column into Indicators.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractCanonicalDocumentFromHtml, THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import { HTML_BLOCKS_VERSION, isContentTemplate, parseHtml, findElements } from './extract/htmlBlocks.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { EXTRACTION_QUALITY_VERSION, assessExtractionQuality } from './extractionQuality.js';
import { PDF_LAYOUT_VERSION, pagesToBlocks, pdfCoverTitle, itemsToLines } from './pdfLayout.js';
import { selectPdfTitle } from './pdfIngest.js';
import { createCanonicalDocument } from './canonicalDocument.js';
import { PUBLICATION_DATE_EXTRACTOR_VERSION, extractDocumentPublicationDate } from './publicationDate.js';
import { isDescriptionColumnMention } from './tableSemantics.js';
import { reselectReportTitle } from './extractionStages.js';
import { CRITICAL_QUALITY_CODES, evaluateFinalizeObligations, reportStatusAxes } from './reportQualityStatus.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = 'https://vendor-labs.example/eng/expertise/blog/slot-rendered-actor/';

const persisted = (c) => ({
  ...c,
  has_original_document_occurrence: true,
  review_status: 'pending',
  evidence: buildCandidateEvidenceRecord(c)
});
const idOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const members = (x) => x.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map(idOf).sort();
const outcomeOf = (x, id) => {
  const c = x.candidates.find((k) => idOf(k) === id);
  return c ? persisted(c).evidence.membership_outcome : null;
};

function runHtml(html, url = SOURCE) {
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true);
  return { document: r.document, ...extractReportCandidates({ source_type: 'url', source_url: url }, r.document) };
}

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v68');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v20');
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v13');
  assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v13');
  assert.equal(PDF_LAYOUT_VERSION, 'threat_library_pdf_v9');
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v17');
  assert.equal(PUBLICATION_DATE_EXTRACTOR_VERSION, 'tl-published-at-v6');
  assert.ok(CRITICAL_QUALITY_CODES.includes('ioc_section_region_dropped'));
});

// --- FN-1: Vue slot templates -------------------------------------------------

const VUE_PAGE = fs.readFileSync(path.join(here, 'benchmark', 'cases', 'control-vue-slot-template-article.html'), 'utf8');
const VUE_INDICATORS = [
  'domain:slot-relay-update.example',
  'ip:198.51.100.51',
  'ip:203.0.113.87',
  'sha256:3f1c0f4f6c1e2a9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c',
  'sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
  'url:http://198.51.100.51/agent.exe',
  'url:http://198.51.100.51:5173/api/clients/7c1e4d2b9a8f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d/stream/ws'
].sort();

test('FN-1: an article inside <template v-slot:content> is read; its IOC section yields every Indicator', () => {
  const x = runHtml(VUE_PAGE);
  assert.deepEqual(members(x), VUE_INDICATORS);
  const headings = x.document.blocks.filter((b) => b.type === 'heading').map((b) => b.text);
  for (const h of ['Overview', 'Indicators of compromise', 'Checksums', 'Network indicators']) assert.ok(headings.includes(h), `${h} missing`);
  assert.equal(outcomeOf(x, 'domain:api.ipify.org'), 'context_only');
});

test('FN-1: menu, contact, listing and cookie templates stay noise', () => {
  const x = runHtml(VUE_PAGE);
  const text = x.document.blocks.map((b) => b.text).join('\n');
  for (const s of ['Incident response hotline', 'We use cookies', 'Other research', 'Moscow office']) {
    assert.ok(!text.includes(s), `${s} leaked into the document`);
  }
  assert.ok(!x.candidates.some((c) => /vendor-labs\.example\/(?:contacts|cookies)/.test(c.normalized_value)));
});

test('FN-1: isContentTemplate needs article structure and never takes a React streaming placeholder', () => {
  const body = '<h2>One</h2><p>' + 'word '.repeat(400) + '</p><h2>Two</h2>' + '<p>paragraph text here</p>'.repeat(5);
  const dom = parseHtml(`<div><template v-slot:content>${body}</template><template id="P:3">${body}</template>` +
    `<template #menu><a href="/a">A</a><a href="/b">B</a></template><template #short><h2>A</h2><h2>B</h2><p>tiny</p></template></div>`);
  const [slot, streamed, menu, short] = findElements(dom, (e) => e.name === 'template');
  assert.equal(isContentTemplate(slot), true);
  assert.equal(isContentTemplate(streamed), false);
  assert.equal(isContentTemplate(menu), false);
  assert.equal(isContentTemplate(short), false);
});

// --- FN-1 safety net: a dropped region that held an IOC section is critical ---

const HIDDEN_IOC_TEMPLATE = `<!doctype html><html><head><title>t</title></head><body><main><article>
<h1>Campaign report</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments over the year.</p>
<h2>Analysis</h2>
<p>The loader beacons to its staging server and pulls a second stage over HTTPS before the operator moves laterally.</p>
<template #appendix><h2>Indicators of compromise</h2><p>198.51.100[.]7</p><p>203.0.113[.]9</p></template>
</article></main></body></html>`;

test('quality: a discarded region carrying an IOC section heading is ioc_section_region_dropped (high, critical)', () => {
  const x = runHtml(HIDDEN_IOC_TEMPLATE);
  const region = x.document.meta.source_accounting.dropped_regions.find((r) => r.region_kind === 'template');
  assert.ok(region, 'template region not accounted');
  assert.deepEqual(region.heading_texts, ['Indicators of compromise']);
  const q = x.diagnostics.quality;
  const w = q.warnings.find((k) => k.code === 'ioc_section_region_dropped');
  assert.ok(w, JSON.stringify(q.warnings.map((k) => k.code)));
  assert.equal(w.severity, 'high');
  assert.equal(q.status, 'high');
  assert.ok(!q.warnings.some((k) => k.code === 'source_region_observables_dropped'), 'region reported twice');

  const snapshot = {
    firstPassRun: { id: 1 },
    latestRun: { id: 1, run_type: 'initial', operational_status: 'completed' },
    significantRegions: [],
    latestDiscovery: { status: 'completed' },
    sources: [],
    candidates: [],
    quality: q
  };
  const unmet = evaluateFinalizeObligations(snapshot).unmet.map((u) => u.code);
  assert.ok(unmet.includes('critical_extraction_failure'), unmet.join(', '));
  assert.deepEqual(reportStatusAxes({ ...snapshot, currentFingerprint: 'x' }).operational_execution.critical_failures, ['ioc_section_region_dropped']);
});

test('quality: an observable-bearing region without an IOC heading stays a warning', () => {
  const q = assessExtractionQuality({
    blocks: [],
    candidates: [],
    diagnostics: {},
    documentMeta: {
      source_accounting: {
        dropped_regions: [{ region_kind: 'textarea', reason: 'noise_element', locator: 'textarea', observable_count: 9, significant: true, sample_observables: ['346b04985ec6c5d107ba0ddf32fe7691'] }]
      }
    }
  });
  assert.deepEqual(q.warnings.map((w) => `${w.code}:${w.severity}`), ['source_region_observables_dropped:warning']);
});

// --- FN-2: FBI FLASH PDF tables ---------------------------------------------

const IC3 = JSON.parse(fs.readFileSync(path.join(here, 'fixtures', 'ic3-flash-ioc-tables-pdf-items.json'), 'utf8'));
const IC3_URL = 'https://www.ic3.gov/CSA/2026/261113.pdf';
const IC3_INDICATORS = [
  ...'38.244.50.120 144.172.64.60 144.172.64.99 144.172.64.128 187.15.88.186 187.15.90.217 187.15.89.186 101.53.80.20 205.214.59.31 124.155.252.63 154.201.79.246 23.248.249.90 23.158.220.98 103.248.148.84 203.160.133.172 209.209.85.38 199.19.95.66 199.19.95.67 199.19.95.68 91.92.240.238 85.11.168.45 178.16.54.129 31.77.229.35 85.11.167.52'
    .split(' ').map((ip) => `ip:${ip}`),
  'domain:xcai.pro'
].sort();

function ic3Document() {
  const laid = pagesToBlocks(IC3.pages);
  return {
    laid,
    document: createCanonicalDocument({
      title: selectPdfTitle({ metadataTitle: null, coverTitle: laid.coverTitle, fileName: '261113.pdf' }),
      blocks: laid.blocks,
      meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf', layout_mode: 'geometry', file_name: '261113.pdf', source_url: IC3_URL }
    })
  };
}

test('FN-2: rows set at wrapped-line pitch split at their top-aligned row lines; stacked values stay in one cell', () => {
  const { laid } = ic3Document();
  const tables = laid.blocks.filter((b) => b.type === 'table');
  const ips = tables.find((b) => b.page === 6 && b.table.headers);
  assert.deepEqual(ips.table.headers, ['Indicator', 'Context', 'Source']);
  assert.deepEqual(ips.table.rows.map((r) => r[0]), [
    '38.244.50[.]120',
    '144.172.64[.]60 144.172.64[.]99 144.172.64[.]128',
    '187.15.88[.]186 187.15.90[.]217 187.15.89[.]186'
  ]);
  assert.equal(ips.table.rows[0][1], 'ARTEX host and open directory (South Korea financial campaign)');
  assert.equal(ips.table.rows[2][2], 'Microsoft²');
  // The ATT&CK table above it keeps its two rows (a mixed-font first line is not a header).
  const ttp = tables.find((b) => b.page === 6 && !b.table.headers);
  assert.equal(ttp.table.rows.length, 2);
});

test('FN-2: a header-less table opening the next page continues the previous table and takes its headers', () => {
  const { laid } = ic3Document();
  const cont = laid.blocks.find((b) => b.type === 'table' && b.page === 7);
  assert.deepEqual(cont.table.headers, ['Indicator', 'Context', 'Source']);
  assert.ok(cont.continued_from && cont.continued_from.startsWith('p6-'));
  assert.equal(cont.table.rows.length, 4);
  assert.equal(cont.table.rows[2][0], '91.92.240[.]238 85.11.168[.]45 178.16.54[.]129 31.77.229[.]35');
});

test('FN-2: all 25 published Indicators are members; the LLM API endpoints stay out', () => {
  const { document } = ic3Document();
  const x = extractReportCandidates({ source_type: 'url', source_url: IC3_URL }, document);
  assert.deepEqual(members(x), IC3_INDICATORS);
  for (const d of ['api.anthropic.com', 'api.deepseek.com', 'open.bigmodel.cn', 'api.x.ai']) {
    assert.notEqual(outcomeOf(x, `domain:${d}`), 'member', d);
  }
});

test('FN-2: title from the cover page, publication date from the cover dateline', () => {
  const { laid, document } = ic3Document();
  assert.equal(laid.coverTitle, 'Threat Overview of ARTEX Autonomous Penetration Testing Framework');
  assert.equal(document.title, 'Threat Overview of ARTEX Autonomous Penetration Testing Framework');
  const d = extractDocumentPublicationDate(document, { sourceType: 'pdf' });
  assert.equal(d.published_date, '2026-11-13');
  assert.equal(d.evidence.signal, 'cover_dateline');
});

test('FN-2: a date repeated as a running header on other pages is not a cover dateline', () => {
  const { document } = ic3Document();
  const repeated = {
    ...document,
    blocks: [...document.blocks, { id: 'p6-bx', type: 'paragraph', text: '13 NOVEMBER 2026', page: 6, layout: 'page_edge', section: null }]
  };
  assert.equal(extractDocumentPublicationDate(repeated, { sourceType: 'pdf' }).published_date, null);
});

test('selectPdfTitle: real metadata wins; file-name / tool metadata falls back to the cover, then the file name', () => {
  assert.equal(selectPdfTitle({ metadataTitle: 'APT Report', coverTitle: 'Cover', fileName: 'x.pdf' }), 'APT Report');
  assert.equal(selectPdfTitle({ metadataTitle: '261113', coverTitle: 'Cover Title', fileName: '261113.pdf' }), 'Cover Title');
  assert.equal(selectPdfTitle({ metadataTitle: 'Microsoft Word - draft.docx', coverTitle: 'Cover Title', fileName: 'a.pdf' }), 'Cover Title');
  assert.equal(selectPdfTitle({ metadataTitle: null, coverTitle: null, fileName: '261113.pdf' }), '261113');
});

test('pdfCoverTitle: no title when nothing on page 1 is clearly larger than body text', () => {
  const item = (str, y, h = 11) => ({ str, transform: [h, 0, 0, h, 54, y], width: str.length * h * 0.5, height: h, fontName: 'F1' });
  const lines = itemsToLines([item('Body text line one of the report.', 600), item('Another body line.', 586)], { pageHeight: 792 });
  assert.equal(pdfCoverTitle(lines, 11), null);
});

// --- Row-split guard: a cell cut on the line above is not a row start ---------

test('pdf_v9: a full line after a partial line whose cell ends mid-token continues the row; the next top-aligned line starts one', () => {
  const h = 10;
  const it = (str, x, y, font = 'F1') => ({ str, transform: [h, 0, 0, h, x, y], width: str.length * h * 0.5, height: h, fontName: font });
  const page = {
    page: 1,
    pageHeight: 792,
    items: [
      it('Indicators of compromise', 54, 720, 'F3'),
      it('Indicator', 60, 700, 'F2'), it('Description', 250, 700, 'F2'), it('Source', 420, 700, 'F2'),
      it('hxxps://cdn-sync[.]example/', 60, 686), it('Payload host serving the', 250, 686), it('Vendor A', 420, 686),
      it('stage/two/', 60, 672), it('second-stage archive', 250, 672),
      it('loader.bin', 60, 658), it('to new victims', 250, 658), it('Vendor B', 420, 658),
      it('over several weeks', 250, 644),
      it('198.51.100[.]23', 60, 630), it('Backup C2 server', 250, 630), it('Vendor A', 420, 630),
      it('Body paragraph after the table explains the campaign and the operator infrastructure in detail.', 54, 600)
    ]
  };
  const table = pagesToBlocks([page]).blocks.find((b) => b.type === 'table');
  assert.ok(table, 'table not detected');
  assert.deepEqual(table.table.headers, ['Indicator', 'Description', 'Source']);
  assert.deepEqual(table.table.rows.map((r) => r[0]), ['hxxps://cdn-sync[.]example/stage/two/loader.bin', '198.51.100[.]23']);
});

// --- Description-column mentions ---------------------------------------------

test('isDescriptionColumnMention: only values under a Description header of a table without an Indicator column', () => {
  const block = {
    type: 'table',
    table: {
      headers: ['Indicator Type', 'Description', 'Source'],
      rows: [['Outbound API calls', 'api.vendor.example, api.other.example (investigate unexpected calls)', 'Vendor']]
    }
  };
  assert.equal(isDescriptionColumnMention(block, 'api.vendor.example'), true);
  assert.equal(isDescriptionColumnMention(block, 'Vendor'), false);
  assert.equal(isDescriptionColumnMention({ ...block, table: { ...block.table, headers: null } }, 'api.vendor.example'), false);
  assert.equal(isDescriptionColumnMention({ type: 'paragraph', text: 'api.vendor.example' }, 'api.vendor.example'), false);
  // An IOC table (declared Indicator column) keeps its description values for the publisher reading.
  const iocTable = { type: 'table', table: { headers: ['Indicator', 'Type', 'Description'], rows: [['198.51.100.4', 'IP', 'Opened by shortcut api.vendor.example']] } };
  assert.equal(isDescriptionColumnMention(iocTable, 'api.vendor.example'), false);
});

// --- Refresh: a PDF named after its file takes the rebuilt cover title -------

test('reselectReportTitle: a PDF title that is only the file name takes the cover title; any other title is kept', async () => {
  const document = { title: 'Threat Overview of ARTEX Autonomous Penetration Testing Framework', blocks: [{ id: 'p1-b01', type: 'paragraph', text: 'x' }], meta: { adapter: 'pdf', file_name: '261113.pdf' } };
  const fallback = await reselectReportTitle(null, { source_type: 'url', title: '261113' }, { document });
  assert.equal(fallback.changed, true);
  assert.equal(fallback.title, document.title);
  assert.equal(fallback.previous_title, '261113');
  const analyst = await reselectReportTitle(null, { source_type: 'pdf', title: 'ARTEX FLASH (analyst title)' }, { document });
  assert.equal(analyst.changed, false);
  const same = await reselectReportTitle(null, { source_type: 'pdf', title: '261113' }, { document: { ...document, title: '261113' } });
  assert.equal(same.changed, false);
});
