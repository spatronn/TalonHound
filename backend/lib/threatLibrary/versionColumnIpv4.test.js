/**
 * Software-version columns vs IPv4 (tl-table-v5 / tl-candidates-v18).
 *
 * A CVE table's "Versions Affected" cell ("2.3.19 to 2.3.20.2, 2.3.21 to
 * 2.3.24.1") is not an IOC table, so it fell through to the flattened-text
 * pass: column provenance was gone and the IPv4-shaped release numbers became
 * standalone IP candidates. MODE A kept them out of Indicators only by chance;
 * in a MODE B report they were reviewable IP Indicators.
 *
 * The rule is column semantics, never values: a token found only in an
 * explicitly version-labelled column is version metadata; the same string in
 * any IP / value column, in prose, or in an IOC section stays an IPv4.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { deriveMatchState } from './constants.js';
import { interpretIocTable, isVersionColumnLabel, tableVersionColumns } from './tableSemantics.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { pagesToBlocks, PDF_LAYOUT_VERSION } from './pdfLayout.js';

const STRUTS = '2.3.19 to 2.3.20.2, 2.3.21 to 2.3.24.1, and 2.3.25 to 2.3.28';
const CVE_HEADER = ['CVE', 'Vendor', 'Product', 'Versions Affected', 'Vulnerability Type'];
const CVE_ROWS = [
  ['CVE-2015-5477* [CWE-19: Data Processing Errors]', 'ISC', 'BIND 9.x', 'Before 9.9.7-P2 and 9.10.x before 9.10.2-P3', 'Denial of service'],
  ['CVE-2016-3081* [CWE-77: Command Injection]', 'Apache', 'Struts', STRUTS, 'Remote code execution']
];

let n = 0;
const para = (text, extra = {}) => ({ id: `b${(n += 1)}`, type: 'paragraph', text, page: extra.page ?? 1, section: null, ...extra });
const heading = (text, extra = {}) => ({ id: `b${(n += 1)}`, type: 'heading', text, page: extra.page ?? 1, section: text, ...extra });
const table = (rows, headers = null, extra = {}) =>
  createTableBlock({ id: `b${(n += 1)}`, page: extra.page ?? 1, headers, rows, source: 'pdf_geometry' });
const edge = (text, page) => ({ id: `b${(n += 1)}`, type: 'paragraph', text, page, section: null, layout: 'page_edge' });

function run(blocks) {
  const doc = createCanonicalDocument({ title: 'fixture', blocks, meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' } });
  const { candidates } = extractCandidatesWithDiagnostics(doc);
  return candidates.map((c) => ({
    ...c,
    evidence: buildCandidateEvidenceRecord(c),
    match_state: deriveMatchState({ assessment: c.assessment, confidence: c.confidence, matchedIocId: null, valid: c.assessment !== 'invalid' })
  }));
}
const get = (rows, value) => rows.filter((c) => c.normalized_value === value);
const ip = (rows, value) => rows.find((c) => c.candidate_type === 'ip' && c.normalized_value === value) || null;
const isVersionArtifact = (c) =>
  c?.candidate_type === 'technical_artifact' && c.is_ioc === false && c.evidence.artifact_kind === 'metadata' && c.evidence.typing_reason === 'version_column';

const NARRATIVE = [
  heading('Technical Details'),
  para('The operators exploited CVE-2016-3081 in Apache Struts and staged tooling on 45.32.140.182 before moving laterally.'),
  para('Defenders should patch affected versions and review web server logs for suspicious POST requests.')
];
const CVE_APPENDIX = () => [heading('Appendix B: Observed Common Vulnerabilities and Exposures'), heading('Table 16. Successfully Exploited CVEs'), table([CVE_HEADER, ...CVE_ROWS])];

// --- labels ------------------------------------------------------------------

test('version column labels are explicit; ambiguous or network headings never qualify', () => {
  for (const l of ['Versions Affected', 'Affected Versions', 'Software Version', 'Product Version', 'Build Number', 'Version(s)', 'Version', 'Firmware version']) {
    assert.equal(isVersionColumnLabel(l), true, l);
  }
  for (const l of ['IP Address', 'Source IP', 'Destination IP', 'C2 IP', 'Malicious IP Addresses', 'Value', 'Details', 'Product', 'Vulnerability Type', 'Version / IP', 'Host Version Info']) {
    assert.equal(isVersionColumnLabel(l), false, l);
  }
});

test('table interpreter: a version column is never an indicator column, whatever its values look like', () => {
  const t = interpretIocTable({ id: 't', table: { headers: ['IP Address', 'Software Version'], rows: [['45.32.140.182', '2.3.20.2'], ['36.249.156.51', '192.168.1.1']] } });
  const cols = Object.fromEntries(t.columns.map((c) => [c.header, c]));
  assert.equal(cols['IP Address'].intent, 'indicator');
  assert.equal(cols['Software Version'].intent, 'other');
  assert.equal(cols['Software Version'].method, 'version_column');
  const values = t.rows.flatMap((r) => r.values.map((v) => v.normalized_value)).sort();
  assert.deepEqual(values, ['36.249.156.51', '45.32.140.182']);
  // Header-like first row (PDF tables have no <th>) is recognised too.
  const v = tableVersionColumns({ headers: null, rows: [CVE_HEADER, ...CVE_ROWS] });
  assert.deepEqual(v.columns, [3]);
  assert.equal(v.header_row, true);
});

// --- extraction --------------------------------------------------------------

test('MODE B: Struts versions in "Versions Affected" are version metadata, not IPv4 Indicators', () => {
  const rows = run([...NARRATIVE, ...CVE_APPENDIX()]);
  assert.equal(rows.some((c) => c.evidence.document_has_authoritative_scope === true), false, 'no curated IOC section (MODE B)');
  for (const v of ['2.3.20.2', '2.3.24.1']) {
    const hits = get(rows, v);
    assert.equal(hits.length, 1, `${v}: one candidate`);
    assert.ok(isVersionArtifact(hits[0]), `${v} typed as version metadata`);
    assert.equal(isReportIndicatorMember(hits[0]), false);
    assert.equal(ip(rows, v), null);
  }
  const real = ip(rows, '45.32.140.182');
  assert.ok(real && isReportIndicatorMember(real), 'narrative IPv4 keeps MODE B review membership');
});

test('the same strings in an explicitly malicious IP column stay IPv4 IOC candidates', () => {
  const rows = run([
    ...NARRATIVE,
    heading('Indicators of Compromise'),
    table([['Malicious IP Addresses', 'First Seen'], ['2.3.20.2', '3/15/2023'], ['2.3.24.1', '3/20/2023'], ['8.8.8.8', '4/1/2023']])
  ]);
  for (const v of ['2.3.20.2', '2.3.24.1', '8.8.8.8']) {
    const c = ip(rows, v);
    assert.ok(c, `${v} is an IPv4 candidate`);
    assert.equal(c.source_assertion, 'explicit_ioc');
    assert.equal(isVersionArtifact(c), false);
  }
  assert.ok(isReportIndicatorMember(ip(rows, '2.3.20.2')));
});

test('mixed table: IPs keep IPv4; versions (even private-range shaped) become metadata', () => {
  const rows = run([
    ...NARRATIVE,
    heading('Observed hosts'),
    table([['IP Address', 'Software Version'], ['45.63.59.121', '2.3.20.2'], ['36.249.156.51', '192.168.1.1']])
  ]);
  assert.ok(ip(rows, '45.63.59.121') && ip(rows, '36.249.156.51'));
  assert.ok(isVersionArtifact(get(rows, '2.3.20.2')[0]));
  assert.ok(isVersionArtifact(get(rows, '192.168.1.1')[0]), 'explicit version column decides, not the private-range shape');
  assert.equal(ip(rows, '192.168.1.1'), null);
});

test('a value in a version column AND another column of the same table keeps its IPv4 reading', () => {
  const rows = run([...NARRATIVE, table([['Host', 'Version', 'Notes'], ['web01', '2.3.20.2', 'beacons to 2.3.20.2 every hour']])]);
  assert.ok(ip(rows, '2.3.20.2'), 'conservative: also present outside the version column');
});

test('ambiguous headings suppress nothing', () => {
  const rows = run([...NARRATIVE, table([['Name', 'Value'], ['relay', '2.3.20.2'], ['backup', '2.3.24.1']])]);
  assert.ok(ip(rows, '2.3.20.2') && ip(rows, '2.3.24.1'));
});

test('multi-page: a header-less continuation after page-break chrome inherits the version column; prose breaks it', () => {
  const continued = run([
    ...NARRATIVE,
    ...CVE_APPENDIX(),
    edge('Page 58 of 59 | Product ID: XX', 58),
    edge('TLP:CLEAR', 59),
    table([['CVE-2017-5638 [CWE-20]', 'Apache', 'Struts', '2.3.5 to 2.3.31.4 and 2.5 to 2.5.10', 'Remote code execution']], null, { page: 59 })
  ]);
  assert.ok(isVersionArtifact(get(continued, '2.3.31.4')[0]), 'continuation row inherits "Versions Affected"');
  const broken = run([
    ...NARRATIVE,
    ...CVE_APPENDIX(),
    para('Unrelated prose follows the table and ends it.'),
    table([['relay', 'Apache', 'Struts', '2.3.31.4', 'beacon']])
  ]);
  assert.ok(ip(broken, '2.3.31.4'), 'no inheritance across body text');
});

test('wrapped multi-line version cells keep their column (PDF geometry)', () => {
  const item = (str, x, y, size = 10.5, font = 'g_d0_f1') => ({ str, transform: [size, 0, 0, size, x, y], width: str.length * size * 0.5, height: size * size, fontName: font });
  const prose = ['Advisory prose line one describing the campaign activity in detail for readers.', 'Advisory prose line two describing the campaign activity in detail for readers.', 'Advisory prose line three describing the campaign activity in detail for readers.', 'Advisory prose line four describing the campaign activity in detail for readers.'];
  const items = [
    item('Appendix B: Observed Common Vulnerabilities', 36, 700, 16, 'g_d0_f5'),
    ...prose.map((t, i) => item(t, 36, 675 - i * 15, 11)),
    item('CVE', 40, 590), item('Product', 200, 590), item('Versions Affected', 330, 590),
    item('CVE-2016-3081', 40, 560), item('Struts', 200, 560), item('2.3.19 to 2.3.20.2,', 330, 560),
    item('2.3.21 to 2.3.24.1', 330, 547.4),
    item('CVE-2015-5477', 40, 520), item('BIND', 200, 520), item('before 9.9.7-P2', 330, 520)
  ];
  const { blocks } = pagesToBlocks([{ page: 1, items, pageHeight: 792 }]);
  const tbl = blocks.find((b) => b.type === 'table');
  assert.ok(tbl, 'table reconstructed');
  assert.ok(tbl.table.rows.some((r) => r.includes('2.3.19 to 2.3.20.2, 2.3.21 to 2.3.24.1')), 'wrapped version cell re-joined in its column');
  const rows = run([...NARRATIVE, ...blocks]);
  for (const v of ['2.3.20.2', '2.3.24.1']) {
    assert.ok(isVersionArtifact(get(rows, v)[0]), `${v} from the PDF table`);
    assert.equal(ip(rows, v), null);
  }
});

test('HTML: <th>Versions Affected</th> cells are version metadata; an IP column stays IPv4', () => {
  const html = `<!doctype html><html><head><title>Advisory</title></head><body><article>
<h1>Joint advisory</h1>
<p>The operators exploited CVE-2016-3081 in Apache Struts and staged tooling on 45.32.140.182 before moving laterally across networks.</p>
<h2>Exploited vulnerabilities</h2>
<table><thead><tr><th>CVE</th><th>Product</th><th>Versions Affected</th></tr></thead>
<tbody><tr><td>CVE-2016-3081</td><td>Struts</td><td>${STRUTS}</td></tr></tbody></table>
<h2>Observed infrastructure</h2>
<table><thead><tr><th>IP Address</th><th>First Seen</th></tr></thead>
<tbody><tr><td>36.249.156[.]51</td><td>3/15/2023</td></tr><tr><td>112.5.168[.]102</td><td>4/2/2023</td></tr></tbody></table>
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: 'https://advisory.example/a', finalUrl: 'https://advisory.example/a', httpStatus: 200 });
  assert.equal(r.ok, true);
  const { candidates } = extractCandidatesWithDiagnostics(r.document, { sourceUrl: 'https://advisory.example/a' });
  const rows = candidates.map((c) => ({ ...c, evidence: buildCandidateEvidenceRecord(c) }));
  for (const v of ['2.3.20.2', '2.3.24.1']) assert.ok(isVersionArtifact(get(rows, v)[0]), `${v} (HTML)`);
  assert.ok(ip(rows, '36.249.156.51') && ip(rows, '112.5.168.102'));
});

test('MODE A: publisher-declared IPs keep explicit membership; CVE-table versions stay out', () => {
  const rows = run([
    ...NARRATIVE,
    heading('Appendix A: Indicators of Compromise'),
    heading('Table 11. IP Addresses'),
    table([['IP Address', 'First Seen'], ['36.249.156.51', '3/15/2023'], ['112.5.168.102', '4/2/2023'], ['45.32.140.182', '5/1/2023']]),
    ...CVE_APPENDIX()
  ]);
  assert.ok(rows.some((c) => c.evidence.document_has_authoritative_scope === true), 'MODE A');
  const members = rows.filter(isReportIndicatorMember).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
  assert.deepEqual(members, ['ip:112.5.168.102', 'ip:36.249.156.51', 'ip:45.32.140.182']);
  const shared = ip(rows, '45.32.140.182');
  assert.equal(shared.source_assertion, 'explicit_ioc', 'narrative + appendix stays one explicit candidate');
  for (const v of ['2.3.20.2', '2.3.24.1']) assert.ok(isVersionArtifact(get(rows, v)[0]));
});

test('deterministic: repeated extraction yields identical identities and readings', () => {
  const sig = () =>
    run([...NARRATIVE, ...CVE_APPENDIX(), table([['IP Address', 'Software Version'], ['45.63.59.121', '2.3.20.2']])])
      .map((c) => `${c.candidate_type}:${c.normalized_value}:${c.source_assertion}:${c.assessment}:${isReportIndicatorMember(c)}`)
      .sort();
  assert.deepEqual(sig(), sig());
});
