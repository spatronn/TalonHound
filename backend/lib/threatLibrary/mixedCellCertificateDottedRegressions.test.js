/**
 * Six-report audit regressions (tl-candidates-v29 / tl-table-v8 /
 * tl-type-resolver-v9 / tl-quality-v6). Generic shapes from the confirmed
 * production defects, with synthetic values — no publisher condition:
 *
 * 1. Mixed indicator cells: a leading file path / file name swallowed the
 *    hash written after it ("C:\…\x.dll SHA256: <h>", "x.dll (SHA-256 <h>)").
 * 2. Row-level benign assertion: a row that calls its value a legitimate
 *    component is context, the malicious sibling row stays an Indicator.
 * 3. Certificate attribute columns: a thumbprint column beside a SHA-256
 *    column produced SHA-1 "malware samples".
 * 4. Dotted technical identifiers on prose-led short lines under a C2-named
 *    topic ("CPU count via hw.ncpu") became C2 domains.
 * 5. Quality v6 makes each of these failure classes visible.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isContextOnlyCandidate, isReportIndicatorMember } from './indicatorMembership.js';
import { QUALITY_CODES, assessExtractionQuality } from './extractionQuality.js';
import { attributeColumnKind, parseIndicatorCell, TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION, rowLedByValueOrLabel } from './observableTypeResolver.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';

const SOURCE = 'https://vendor-research.example/blog/mixed-cells/';
const BS = String.fromCharCode(92);
const winPath = (...parts) => parts.join(BS);
const H1 = 'a'.repeat(63) + '1';
const H2 = 'b'.repeat(63) + '2';
const H3 = 'c'.repeat(63) + '3';
const SHA1A = 'd'.repeat(39) + '4';
const SHA1B = 'e'.repeat(39) + '5';
const MD5A = 'f'.repeat(31) + '6';

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Mixed</title></head><body><article>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
<h2>Conclusion</h2><p>The actor continues to evolve its toolset.</p>
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const members = (x) => x.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
const find = (x, value) => x.candidates.find((c) => c.normalized_value === value);
const codes = (x) => [...new Set(x.diagnostics.quality.warnings.map((w) => w.code))].sort();

test('contracts bumped for the six-report audit fixes', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v38');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v10');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v16');
});

// --- 1. Mixed cells -----------------------------------------------------------

test('mixed cell: every confirmed shape keeps the file identity as context and recovers the hash', () => {
  const shapes = [
    [`${winPath('c:', 'Users', 'Public', 'Downloads', 'loader.dll')} SHA256: ${H1}`, 'file_path', ['sha256']],
    [`loader.dll (SHA-256 ${H1})`, 'technical_artifact', ['sha256']],
    [`loader.dll SHA-256: ${H1}`, 'technical_artifact', ['sha256']],
    [`loader.exe - ${MD5A}`, 'technical_artifact', ['md5']],
    [`/tmp/loader.bin SHA256: ${H1}`, 'file_path', ['sha256']],
    [`loader.exe [SHA256] ${H1} [MD5] ${MD5A}`, 'technical_artifact', ['sha256', 'md5']]
  ];
  for (const [cell, fileType, hashTypes] of shapes) {
    const { values } = parseIndicatorCell(cell);
    const file = values.find((v) => v.is_ioc === false);
    const hashes = values.filter((v) => v.is_ioc !== false);
    assert.equal(file?.candidate_type, fileType, cell);
    assert.deepEqual(hashes.map((v) => v.candidate_type), hashTypes, cell);
    // Provenance: the file identity and its hash(es) are linked both ways.
    for (const h of hashes) assert.deepEqual(h.cell_companions, [`${file.candidate_type}:${file.normalized_value}`], cell);
    assert.deepEqual(file.cell_companions.sort(), hashes.map((h) => `${h.candidate_type}:${h.normalized_value}`).sort(), cell);
  }
});

test('mixed cell controls: hash-first, hash-only and labelled multi-hash cells are unchanged; a path alone stays one value', () => {
  assert.deepEqual(parseIndicatorCell(`${H1} (loader.dll)`).values.map((v) => v.candidate_type).sort(), ['sha256', 'technical_artifact']);
  assert.deepEqual(parseIndicatorCell(H1).values.map((v) => v.candidate_type), ['sha256']);
  assert.deepEqual(parseIndicatorCell(`MD5: ${MD5A} SHA256: ${H1}`).values.map((v) => v.candidate_type), ['md5', 'sha256']);
  const path = parseIndicatorCell(winPath('c:', 'ProgramData', 'tool', 'svc.exe'));
  assert.equal(path.values.length, 1);
  assert.equal(path.values[0].candidate_type, 'file_path');
  assert.equal(path.values[0].cell_residual, undefined);
});

test('mixed cell: a prose remainder is not decomposed, but its observable is reported, never silently lost', () => {
  const r = parseIndicatorCell(`${winPath('c:', 'temp', 'stage.dll')} dropped by the installer and beacons to 203.0.113.77`);
  assert.equal(r.values.length, 1);
  assert.equal(r.values[0].candidate_type, 'file_path');
  assert.ok(r.values[0].cell_residual);
  assert.deepEqual(r.values[0].residual_observables, ['ip:203.0.113.77']);
  assert.equal(r.decomposition.residual_unparsed, true);
});

test('mixed cell: a multi-pair cell links each hash to the file identity written before it', () => {
  const a = winPath('C:', 'ProgramData', 'vendor', 'first.dll');
  const b = winPath('C:', 'ProgramData', 'vendor', 'second.dll');
  const { values } = parseIndicatorCell(`${a} (MD5 ${MD5A}) ${b} (MD5 ${'9'.repeat(32)})`);
  assert.deepEqual(values.map((v) => [v.candidate_type, v.cell_companions]), [
    ['file_path', [`md5:${MD5A}`]],
    ['md5', [`file_path:${a}`]],
    ['file_path', [`md5:${'9'.repeat(32)}`]],
    ['md5', [`file_path:${b}`]]
  ]);
});

test('mixed cell: an unquoted path with spaces is not split into a bogus second file; its hash is reported', () => {
  const r = parseIndicatorCell(`${winPath('C:', 'Program Files', 'Vendor', 'app.exe')} SHA256: ${H1}`);
  assert.equal(r.values.length, 1, 'no fragment artifact');
  assert.deepEqual(r.values[0].residual_observables, [`sha256:${H1}`]);
});

test('appendix table with path-first and name-first hash cells: hashes are Indicators, files are Context Only, no duplicates', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<table><thead><tr><th>Indicator</th><th>Notes</th></tr></thead><tbody>
<tr><td>198.51.100[.]23</td><td>C2 server</td></tr>
<tr><td>${winPath('c:', 'Users', 'Public', 'stage.dll')} SHA256: ${H1}</td><td>Malicious DLL used for the C2</td></tr>
<tr><td>injector.dll (SHA-256 ${H2})</td><td>Process injector</td></tr>
<tr><td>${H2}</td><td>Same injector listed again by hash</td></tr>
</tbody></table>`);
  const m = members(x);
  assert.ok(m.includes(`sha256:${H1}`), m.join(' '));
  assert.ok(m.includes(`sha256:${H2}`), m.join(' '));
  assert.ok(m.includes('ip:198.51.100.23'));
  assert.equal(x.candidates.filter((c) => c.normalized_value === H2).length, 1, 'one candidate per identity');
  const dll = find(x, 'injector.dll');
  assert.equal(dll?.is_ioc, false);
  assert.equal(isContextOnlyCandidate(persisted(dll)), true);
  const row = find(x, H1).table_rows?.[0];
  assert.match(row.indicator_cell, /SHA256:/, 'full cell kept as evidence');
  assert.deepEqual(row.cell_companions, [`file_path:${winPath('c:', 'Users', 'Public', 'stage.dll')}`]);
  assert.equal(x.diagnostics.explicit_tables.mixed_cells.recovered_values >= 2, true);
  assert.deepEqual(codes(x), []);
});

// --- 2. Row-level benign assertion --------------------------------------------

test('a legitimate side-loading host row is traceable Context Only; its malicious sibling row is an Indicator', () => {
  const x = run(`<h2>Indicators of compromise (IOCs)</h2>
<table><tbody>
<tr><td><p>Item</p></td><td><p>Description</p></td></tr>
<tr><td><p>173.0.2[.]10</p></td><td><p>IP address used with ssh</p></td></tr>
<tr><td><p>${winPath('c:', 'Users', 'Public', 'Downloads', 'HOST.exe')}</p><p>SHA256: ${H1}</p></td><td><p>Legitimate Example Inc. executable</p></td></tr>
<tr><td><p>${winPath('c:', 'Users', 'Public', 'Downloads', 'HOST.dll')}</p><p>SHA256: ${H2}</p></td><td><p>Malicious DLL used for the C2</p></td></tr>
</tbody></table>`);
  const m = members(x);
  assert.ok(m.includes(`sha256:${H2}`), 'malicious DLL hash is an Indicator');
  assert.ok(!m.includes(`sha256:${H1}`), 'legitimate executable hash is not an Indicator');
  const legit = find(x, H1);
  assert.ok(legit, 'legitimate hash is still extracted (traceable)');
  assert.equal(legit.policy_decision, 'context_only_benign_component');
  assert.equal(isContextOnlyCandidate(persisted(legit)), true);
  assert.equal(legit.occurrences.every((o) => o.relation_marker === 'benign' && o.asserted === false), true);
  assert.match(legit.table_rows[0].cell_companions[0], /HOST\.exe$/);
  assert.deepEqual(codes(x), [], JSON.stringify(x.diagnostics.quality.warnings));
});

test('benign wording with an abuse / maliciousness cue keeps the row assertion', () => {
  for (const note of ['Legitimate binary trojanized by the actor', 'Legitimate remote tool abused for persistence', 'Signed loader dropped by the installer']) {
    const x = run(`<h2>Indicators of compromise</h2>
<table><thead><tr><th>SHA256</th><th>Notes</th></tr></thead><tbody>
<tr><td>${H3}</td><td>${note}</td></tr><tr><td>${H2}</td><td>Malicious payload</td></tr></tbody></table>`);
    assert.ok(members(x).includes(`sha256:${H3}`), note);
  }
});

// --- 3. Certificate attribute columns -----------------------------------------

test('attribute headers: certificate / fuzzy-hash columns are recognised, observable columns are not', () => {
  for (const h of ['Certificate Thumbprint', 'Certificate Serial Number', 'Certificate Common Name', 'Signer', 'Issuer', 'Imphash', 'ssdeep', 'TLSH']) {
    assert.ok(attributeColumnKind(h), h);
  }
  for (const h of ['SHA1', 'SHA256', 'MD5', 'Hash', 'Indicator', 'Domain', 'IP Address', 'Malware Family', 'File name', 'Description']) {
    assert.equal(attributeColumnKind(h), null, h);
  }
});

test('SHA-256 + certificate thumbprint table: thumbprints are attributes of the sample, never SHA-1 Indicators', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<h3>Malware samples signed with suspicious certificates</h3>
<table><thead><tr><th>sha256</th><th>Certificate Common Name</th><th>Certificate Thumbprint</th><th>Certificate Serial Number</th><th>Malware Family</th></tr></thead><tbody>
<tr><td>${H1}</td><td>Example Signer</td><td>${SHA1A}</td><td>330007f1068f41bf0f662a03b500000007f106</td><td>LoaderFamily</td></tr>
<tr><td>${H2}</td><td>Example Signer</td><td>${SHA1A}</td><td>330007f1068f41bf0f662a03b500000007f106</td><td>LoaderFamily</td></tr>
<tr><td>${H3}</td><td>Other Signer</td><td>${SHA1B}</td><td>3300072b29c3bf8403a6c15be2000000072b29</td><td>OtherFamily</td></tr>
</tbody></table>`);
  assert.deepEqual(members(x), [`sha256:${H1}`, `sha256:${H2}`, `sha256:${H3}`]);
  assert.equal(x.candidates.some((c) => c.candidate_type === 'sha1'), false);
  const cells = find(x, H1).table_rows[0].cells;
  assert.deepEqual(cells.filter((c) => c.attribute_kind === 'certificate').map((c) => c.header), [
    'Certificate Common Name',
    'Certificate Thumbprint',
    'Certificate Serial Number'
  ]);
  assert.equal(cells.find((c) => c.header === 'Certificate Thumbprint').text, SHA1A, 'thumbprint preserved as an attribute');
  assert.deepEqual(codes(x), []);
});

test('control: an MD5 | SHA1 | SHA256 file-hash table keeps all three hash columns as Indicators', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<table><thead><tr><th>MD5</th><th>SHA1</th><th>SHA256</th><th>File name</th></tr></thead><tbody>
<tr><td>${MD5A}</td><td>${SHA1A}</td><td>${H1}</td><td>loader.exe</td></tr></tbody></table>`);
  assert.deepEqual(members(x), [`md5:${MD5A}`, `sha1:${SHA1A}`, `sha256:${H1}`]);
});

// --- 4. Dotted technical identifiers ------------------------------------------

test('prose-led sysctl lines under a C2-named topic are not domains; real C2 hosts in the same section stay', () => {
  const x = run(`<h3>Second stage: Host discovery and C2 tasking</h3>
<p>The implant collects the following hardware details:</p>
<p>CPU count via hw.ncpu</p>
<p>Physical RAM via hw.memsize</p>
<p>Hardware model identifier via hw.model</p>
<p>It then posts the data to the C2 server:</p>
<p>hxxps://tasking-relay[.]com/macos/jquery.js</p>
<h2>Indicators of compromise</h2>
<ul><li>tasking-relay[.]com</li><li>update.badhost[.]top</li></ul>`);
  const m = members(x);
  for (const id of ['hw.ncpu', 'hw.memsize', 'hw.model']) {
    const c = find(x, id);
    assert.ok(!m.includes(`domain:${id}`), id);
    if (c) assert.notEqual(c.candidate_type, 'domain', id);
  }
  assert.ok(m.includes('domain:tasking-relay.com'));
  assert.ok(m.includes('domain:update.badhost.top'));
});

test('row lead reader: value-led and label-led rows qualify, prose leads do not', () => {
  for (const lead of ['', '- ', 'C2: ', 'Domain - ', '1. ', '• ', 'Domains: ']) assert.equal(rowLedByValueOrLabel(lead), true, JSON.stringify(lead));
  for (const lead of ['CPU count via ', 'Physical RAM via ', 'the malware reads ']) assert.equal(rowLedByValueOrLabel(lead), false, lead);
});

// --- 5. Quality v6 makes the failure classes visible ---------------------------

test('quality: an unparsed observable in an IOC-table indicator cell is reported', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<table><thead><tr><th>Indicator</th><th>Notes</th></tr></thead><tbody>
<tr><td>198.51.100[.]23</td><td>C2 server</td></tr>
<tr><td>${winPath('c:', 'temp', 'stage.dll')} dropped by the installer and beacons to 203.0.113.77</td><td>Stage two</td></tr>
</tbody></table>`);
  assert.ok(codes(x).includes(QUALITY_CODES.TABLE_OBSERVABLE_NOT_EXTRACTED), codes(x).join(','));
  const w = x.diagnostics.quality.warnings.find((v) => v.code === QUALITY_CODES.TABLE_OBSERVABLE_NOT_EXTRACTED);
  assert.deepEqual(w.candidates, ['203.0.113.77']);
});

test('quality: a content-inferred hash column beside a declared SHA-256 column warns', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<table><thead><tr><th>sha256</th><th>Reference value</th><th>Family</th></tr></thead><tbody>
<tr><td>${H1}</td><td>${SHA1A}</td><td>LoaderFamily</td></tr><tr><td>${H2}</td><td>${SHA1B}</td><td>LoaderFamily</td></tr>
</tbody></table>`);
  assert.ok(codes(x).includes(QUALITY_CODES.CONTENT_INFERRED_HASH_COLUMN), codes(x).join(','));
});

test('quality: an Indicator domain with an undelegated suffix warns; special-use suffixes do not', () => {
  // tl-candidates-v30: an undeclared list value with an undelegated suffix is a
  // system identifier, never a domain Indicator (sd-pam.service under "Host Indicators").
  const listed = run(`<h2>Indicators of compromise</h2><ul><li>beacon.corp-mgmt.internalzone</li><li>198.51.100[.]24</li></ul>`);
  const undeclared = listed.candidates.find((c) => c.normalized_value === 'beacon.corp-mgmt.internalzone');
  assert.equal(undeclared.policy_decision, 'ioc_excluded_undelegated_suffix');
  assert.ok(!codes(listed).includes(QUALITY_CODES.UNDELEGATED_SUFFIX_DOMAIN_INDICATOR), codes(listed).join(','));
  // A value the publisher typed "Domain" in an indicator table keeps membership, and check 12 warns.
  const x = run(`<h2>Indicators of compromise</h2><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>
<tr><td>Domain</td><td>beacon.corp-mgmt[.]internalzone</td></tr><tr><td>IP</td><td>198.51.100[.]24</td></tr></tbody></table>`);
  assert.ok(codes(x).includes(QUALITY_CODES.UNDELEGATED_SUFFIX_DOMAIN_INDICATOR), codes(x).join(','));
  const y = run(`<h2>Indicators of compromise</h2><ul><li>${'q'.repeat(56)}.onion</li><li>198.51.100[.]24</li></ul>`);
  assert.ok(!codes(y).includes(QUALITY_CODES.UNDELEGATED_SUFFIX_DOMAIN_INDICATOR), codes(y).join(','));
});

test('quality: an Indicator whose own row text calls it legitimate is flagged even without a benign relation marker', () => {
  const block = { id: 'b1', type: 'table', zone: 'explicit_ioc_section', text: 'x' };
  const candidate = {
    candidate_type: 'sha256',
    normalized_value: H1,
    original_value: H1,
    is_ioc: true,
    assessment: 'malicious',
    match_state: 'new',
    review_status: 'pending',
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    has_original_document_occurrence: true,
    evidence_text: `${H1} | Legitimate Example Inc. executable`,
    occurrences: [{ block_id: 'b1', zone: 'explicit_ioc_section', form: 'table_row', asserted: true, occurrence_kind: 'typed_table_row', relation_marker: 'structural_row', surrounding_text: `${H1} | Legitimate Example Inc. executable` }]
  };
  const q = assessExtractionQuality({ candidates: [candidate], blocks: [block], diagnostics: {} });
  assert.ok(q.warnings.some((w) => w.code === QUALITY_CODES.LEGITIMATE_MARKER_INDICATOR), JSON.stringify(q.warnings.map((w) => w.code)));
});
