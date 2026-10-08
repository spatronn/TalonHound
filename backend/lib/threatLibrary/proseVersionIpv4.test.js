/**
 * Prose software versions vs IPv4 (tl-candidates-v19, ipv4VersionContext.js).
 *
 * The text pass added every standalone IPv4-shaped token as an `ip`
 * candidate: "Apache Struts 2.3.24.1 is vulnerable" and "Version=4.0.0.0"
 * became reviewable IP Indicators in MODE B. Only the clause around the token
 * decides — a network cue keeps the address, explicit version evidence makes
 * it version metadata, anything else keeps the existing IPv4 reading.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { deriveMatchState } from './constants.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { pagesToBlocks, PDF_LAYOUT_VERSION } from './pdfLayout.js';
import { ipv4VersionContext } from './ipv4VersionContext.js';
import { preserveAnalystCandidates } from './candidateAnalystState.js';

const SOURCE = 'https://research.example/post';
const persist = (c) => ({
  ...c,
  evidence: buildCandidateEvidenceRecord(c),
  match_state: deriveMatchState({ assessment: c.assessment, confidence: c.confidence, matchedIocId: null, valid: c.assessment !== 'invalid' })
});
function html(inner) {
  const page = `<!doctype html><html><head><title>t</title></head><body><article><h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set, its tooling and its victims across several environments over many months.</p>${inner}</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(page, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }).candidates.map(persist);
}
const prose = (...sentences) => html(sentences.map((s) => `<p>${s}</p>`).join(''));
const ip = (rows, v) => rows.find((c) => c.candidate_type === 'ip' && c.normalized_value === v) || null;
const version = (rows, v) => rows.find((c) => c.candidate_type === 'technical_artifact' && c.normalized_value === v) || null;
const isVersionMeta = (c) => Boolean(c) && c.is_ioc === false && c.evidence.artifact_kind === 'metadata' && c.evidence.typing_reason === 'version_context';
const at = (text, value) => {
  const i = text.indexOf(value);
  return ipv4VersionContext(text, i, i + value.length);
};

// --- clause classifier -------------------------------------------------------

test('classifier: explicit version evidence vs network cues (clause only, never the value)', () => {
  const versions = [
    ['Apache Struts 2.3.24.1 is vulnerable.', '2.3.24.1'],
    ['Affected versions include 2.3.20.2.', '2.3.20.2'],
    ['Struts version 2.3.20.2 shipped the fix.', '2.3.20.2'],
    ['affected versions: 2.3.24.1', '2.3.24.1'],
    ['the vendor software release 2.3.20.2 changed it', '2.3.20.2'],
    ['product version 2.3.24.1', '2.3.24.1'],
    ['customers should upgrade from 2.3.20.2 immediately', '2.3.20.2'],
    ['all versions prior to 2.3.24.1 are affected', '2.3.24.1'],
    ["Load('System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral')", '4.0.0.0'],
    ['Struts (2.3.24.1) and earlier', '2.3.24.1'],
    ['2.3.19 to 2.3.20.2 are affected', '2.3.20.2']
  ];
  for (const [text, v] of versions) assert.equal(at(text, v)?.kind, 'version', text);
  const addresses = [
    ['The C2 server is 2.3.24.1.', '2.3.24.1'],
    ['Attacker connected to 2.3.20.2 over port 443.', '2.3.20.2'],
    ['C2 server: 2.3.24.1', '2.3.24.1'],
    ['connected to IP 2.3.20.2', '2.3.20.2'],
    ['destination address 2.3.24.1', '2.3.24.1'],
    ['malicious IP: 2.3.20.2', '2.3.20.2'],
    ['network traffic to 2.3.24.1', '2.3.24.1'],
    ['infrastructure shifting from 185.205.211.217 to 178.16.55.232 in May', '178.16.55.232'],
    ['infrastructure shifting from 185.205.211.217 to 178.16.55.232 in May', '185.205.211.217'],
    ['Struts version 2.3.24.1 was patched. The C2 IP 2.3.24.1 stayed online.', null],
    ['Initially 45.32.140.182 hosted the panel.', '45.32.140.182'],
    ['The implant reached 45.32.140.182 within minutes.', '45.32.140.182']
  ];
  for (const [text, v] of addresses) {
    if (!v) continue;
    assert.equal(at(text, v), null, text);
  }
  const both = 'Struts version 2.3.24.1 was patched. The C2 IP 2.3.24.1 stayed online.';
  const second = both.lastIndexOf('2.3.24.1');
  assert.equal(ipv4VersionContext(both, both.indexOf('2.3.24.1'), both.indexOf('2.3.24.1') + 8)?.kind, 'version');
  assert.equal(ipv4VersionContext(both, second, second + 8), null, 'a version in the previous sentence never suppresses the next one');
});

// --- extraction (HTML / MODE B) ------------------------------------------------

test('MODE B: release numbers in prose are version metadata; network-asserted values stay IPv4 Indicators', () => {
  const rows = prose(
    'Apache Struts 2.3.24.1 is vulnerable to remote code execution through crafted headers.',
    'Affected versions include 2.3.20.2 and earlier releases of the framework.',
    'The C2 server is 45.77.11.47 and it received beacons every sixty seconds.',
    'Attacker connected to 36.249.156.51 to fetch the second stage payload.'
  );
  assert.equal(rows.some((c) => c.evidence.document_has_authoritative_scope === true), false, 'MODE B');
  for (const v of ['2.3.24.1', '2.3.20.2']) {
    assert.ok(isVersionMeta(version(rows, v)), `${v} → version metadata`);
    assert.equal(ip(rows, v), null);
    assert.equal(isReportIndicatorMember(version(rows, v)), false);
  }
  for (const v of ['45.77.11.47', '36.249.156.51']) {
    const c = ip(rows, v);
    assert.ok(c && isReportIndicatorMember(c), `${v} stays a reviewable IPv4 Indicator`);
  }
});

test('the brief table: identical values under network cues stay IPv4', () => {
  const rows = prose('The C2 server is 2.3.24.1 and it answered every beacon.', 'Attacker connected to 2.3.20.2 over TCP port 443.');
  assert.ok(ip(rows, '2.3.24.1') && isReportIndicatorMember(ip(rows, '2.3.24.1')));
  assert.ok(ip(rows, '2.3.20.2') && isReportIndicatorMember(ip(rows, '2.3.20.2')));
  assert.equal(version(rows, '2.3.24.1'), null);
});

test('one sentence, two readings: "Struts 2.3.24.1 contacted 8.8.8.8"', () => {
  const rows = prose('After exploitation, Struts 2.3.24.1 contacted 8.8.8.8 for name resolution checks.');
  assert.ok(isVersionMeta(version(rows, '2.3.24.1')));
  assert.ok(ip(rows, '8.8.8.8'), 'valid IPv4 kept');
});

test('same value as version and as C2 IP: the explicit IP evidence is preserved', () => {
  const rows = prose('Version 2.3.24.1 of the agent was deployed; C2 IP 2.3.24.1 coordinated the bots.');
  assert.ok(isVersionMeta(version(rows, '2.3.24.1')), 'version occurrence kept as metadata');
  const addr = ip(rows, '2.3.24.1');
  assert.ok(addr && isReportIndicatorMember(addr), 'IPv4 identity with its own evidence');
  assert.equal(addr.evidence.occurrences.length, 1);
  assert.match(addr.evidence.occurrences[0].surrounding_text, /C2 IP 2\.3\.24\.1/);
});

test('lists, ranges, parentheses and adjacent sentences', () => {
  const rows = prose(
    'Versions 2.3.20.2, 2.3.24.1 and 2.3.28.1 are affected.',
    'Fixed releases: Struts (2.3.32.1) and later.',
    'The vendor shipped 2.3.19 to 2.3.29.4 without the patch.',
    'Struts 2.3.30.1 was patched. The relay at 45.63.59.121 stayed up.'
  );
  for (const v of ['2.3.20.2', '2.3.24.1', '2.3.28.1', '2.3.32.1', '2.3.29.4', '2.3.30.1']) assert.ok(isVersionMeta(version(rows, v)), v);
  assert.ok(ip(rows, '45.63.59.121'), 'adjacent sentence with a network cue keeps its address');
});

test('product-name cue needs release context and never reads a label row (prod counterexample)', () => {
  const row = '64.94.85.67: Associated with Pitboss Shell 62.133.62.80: Payload Delivery';
  assert.equal(at(row, '62.133.62.80'), null, 'IOC label row keeps the address');
  const code = 'Run Shell 45.32.140.182 for the reverse connection';
  const i = code.indexOf('45.32.140.182');
  assert.equal(ipv4VersionContext(code, i, i + 13, { code: true }), null, 'never in code samples');
  assert.equal(at('Struts 2.3.24.1 contacted 8.8.8.8', '2.3.24.1'), null, 'product name alone is not enough');
  assert.equal(at('After exploitation, Struts 2.3.24.1 contacted 8.8.8.8', '2.3.24.1')?.kind, 'version');
});

test('versions with invalid IPv4 octets are never IP candidates', () => {
  const rows = prose('Builds 2.3.300.1 and 10.0.19041.1 were scanned.');
  assert.equal(rows.some((c) => c.candidate_type === 'ip'), false);
});

test('ambiguous prose keeps the conservative IPv4 reading', () => {
  const rows = prose('We observed 2.3.24.1 in several logs during the incident.', 'Infrastructure shifted from 185.205.211.217 to 178.16.55.232 last month.');
  for (const v of ['2.3.24.1', '185.205.211.217', '178.16.55.232']) assert.ok(ip(rows, v), v);
});

// --- PDF / MODE A -------------------------------------------------------------

test('PDF: a version wrapped onto the next line keeps its product context', () => {
  const item = (str, y) => ({ str, transform: [11, 0, 0, 11, 36, y], width: str.length * 5.5, height: 121, fontName: 'f1' });
  const lines = [
    'The operators exploited a deserialization flaw in Apache Struts',
    '2.3.24.1 before pivoting to the internal network segment for weeks.',
    'They later staged tooling on the relay host 45.32.140.182 for collection.',
    'Additional detail on the campaign appears in later sections of this report.'
  ];
  const { blocks } = pagesToBlocks([{ page: 1, pageHeight: 792, items: lines.map((t, i) => item(t, 700 - i * 15)) }]);
  const doc = createCanonicalDocument({ title: 'pdf', blocks, meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' } });
  const rows = extractCandidatesWithDiagnostics(doc).candidates.map(persist);
  assert.ok(isVersionMeta(version(rows, '2.3.24.1')));
  assert.ok(ip(rows, '45.32.140.182'));
});

test('MODE A: publisher IOC table rows stay explicit even with version-like values; narrative versions stay out', () => {
  const rows = html(
    '<h2>Indicators of Compromise</h2><table><thead><tr><th>IP Address</th><th>First Seen</th></tr></thead><tbody>' +
      '<tr><td>2.3.24.1</td><td>2023</td></tr><tr><td>45.32.140[.]182</td><td>2023</td></tr></tbody></table>' +
      '<h2>Analysis</h2><p>Apache Struts 2.3.20.2 is vulnerable to remote code execution.</p>'
  );
  assert.ok(rows.some((c) => c.evidence.document_has_authoritative_scope === true), 'MODE A');
  const pub = ip(rows, '2.3.24.1');
  assert.equal(pub.source_assertion, 'explicit_ioc');
  assert.ok(isReportIndicatorMember(pub));
  assert.ok(isVersionMeta(version(rows, '2.3.20.2')));
  assert.equal(ip(rows, '2.3.20.2'), null);
});

test('publisher IOC section prose / rows are never re-read as versions', () => {
  const blocks = [
    { id: 'h1', type: 'heading', text: 'Indicators of Compromise', page: 1, section: 'Indicators of Compromise' },
    { id: 'l1', type: 'list_item', text: '2.3.24.1', page: 1, section: null },
    { id: 'l2', type: 'list_item', text: '45.32.140.182', page: 1, section: null },
    { id: 'l3', type: 'list_item', text: '36.249.156.51', page: 1, section: null }
  ];
  const rows = extractCandidatesWithDiagnostics(createCanonicalDocument({ title: 't', blocks })).candidates.map(persist);
  assert.ok(ip(rows, '2.3.24.1') && isReportIndicatorMember(ip(rows, '2.3.24.1')));
});

test('column fix still holds alongside the prose rule (tl-table-v5)', () => {
  const t = createTableBlock({ id: 't1', page: 1, rows: [['CVE', 'Product', 'Versions Affected'], ['CVE-2016-3081', 'Struts', '2.3.19 to 2.3.20.2, 2.3.21 to 2.3.24.1']] });
  const rows = extractCandidatesWithDiagnostics(createCanonicalDocument({ title: 't', blocks: [{ id: 'p', type: 'paragraph', text: 'Background prose about the campaign and the exploited services.', page: 1, section: null }, t] })).candidates.map(persist);
  for (const v of ['2.3.20.2', '2.3.24.1']) {
    const c = version(rows, v);
    assert.ok(c && c.evidence.typing_reason === 'version_column', v);
  }
});

// --- reconciliation -----------------------------------------------------------

test('reconciliation: deterministic and idempotent; reviewed IPv4 rows keep analyst state', () => {
  const run = () =>
    prose('Apache Struts 2.3.24.1 is vulnerable.', 'C2 IP 45.32.140.182 relayed tasking to implants.').map((c) => ({ ...c }));
  const first = run();
  const prior = first.map((c) => (c.candidate_type === 'ip' && c.normalized_value === '45.32.140.182' ? { ...c, review_status: 'approved' } : c));
  const second = preserveAnalystCandidates(run(), prior);
  const third = preserveAnalystCandidates(run(), second);
  const sig = (rows) => rows.map((c) => `${c.candidate_type}|${c.normalized_value}|${c.assessment}|${c.review_status || 'pending'}`).sort();
  assert.deepEqual(sig(second), sig(third), 'idempotent');
  assert.equal(second.find((c) => c.normalized_value === '45.32.140.182').review_status, 'approved', 'analyst approval preserved');
  assert.ok(isVersionMeta(persist(second.find((c) => c.normalized_value === '2.3.24.1'))));
});
