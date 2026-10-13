/**
 * Extraction quality detector (tl-quality-v1): each reason code on a minimal
 * document, false-positive behaviour on clean layouts, and the read-only
 * contract (candidates, membership and MODE never change).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates, compactExtractionDiagnostics } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import {
  EXTRACTION_QUALITY_THRESHOLDS,
  EXTRACTION_QUALITY_VERSION,
  QUALITY_CODES,
  assessExtractionQuality,
  compactExtractionQuality
} from './extractionQuality.js';

const SOURCE = 'https://vendor-research.example/blog/quality/';

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Quality</title></head><body><article>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
<h2>Conclusion</h2><p>The actor continues to evolve its toolset.</p>
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}

const codes = (q, severity = null) =>
  [...new Set(q.warnings.filter((w) => !severity || w.severity === severity).map((w) => w.code))].sort();
const hex = (c, n = 32) => c.repeat(n);
const members = (cands) =>
  cands.filter((c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) })).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();

test('contract: version, central thresholds, stable codes', () => {
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v1');
  assert.ok(Object.isFrozen(EXTRACTION_QUALITY_THRESHOLDS));
  assert.equal(EXTRACTION_QUALITY_THRESHOLDS.orphanRunMinValues, 3);
  assert.equal(new Set(Object.values(QUALITY_CODES)).size, Object.keys(QUALITY_CODES).length);
});

test('clean IOC appendix: no warning', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>Network</h3><ul><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>
<h3>File hashes</h3><p>${hex('a')}</p><p>${hex('b')}</p><p>${hex('c')}</p>`);
  assert.equal(x.diagnostics.quality.status, 'clean');
  assert.equal(x.diagnostics.quality.mode, 'A');
});

test('rows that lost appendix scope after a sibling sub-heading warn with candidates, blocks and section context', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>C2 servers</h3><ul><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>
<h3>Loaders</h3>
<pre>loader.exe ${hex('a')}
helper.dll ${hex('b')}
plugin.dll ${hex('c')}</pre>`);
  const q = x.diagnostics.quality;
  const w = q.warnings.find((y) => y.code === QUALITY_CODES.INDICATOR_ROWS_ADJACENT_TO_SCOPE);
  assert.ok(w, JSON.stringify(q.warnings.map((y) => y.code)));
  assert.equal(w.severity, 'warning');
  assert.deepEqual(w.candidates, [`md5:${hex('a')}`, `md5:${hex('b')}`, `md5:${hex('c')}`]);
  assert.equal(w.candidate_count, 3);
  assert.ok(w.block_ids.length >= 1);
  assert.equal(w.section.heading, 'Loaders');
  assert.ok(w.section.adjacent_authoritative_block);
  assert.match(w.explanation, /MODE A/);
  assert.ok(w.evidence.some((e) => /loader\.exe/.test(e.text)));
  assert.equal(w.extractor_version.quality, 'tl-quality-v1');
  assert.ok(codes(q, 'high').includes(QUALITY_CODES.APPENDIX_WITHOUT_HASH_INDICATORS));
});

test('an analysis inventory far from the appendix is info only, never a warning', () => {
  const x = run(`<h2>Technical analysis</h2>
<p>The archive dropped several components during the second stage of the intrusion.</p>
<table><thead><tr><th>Component</th><th>MD5</th></tr></thead><tbody>
<tr><td>stage2.bin</td><td>${hex('a')}</td></tr><tr><td>stage3.bin</td><td>${hex('b')}</td></tr><tr><td>cfg.dat</td><td>${hex('c')}</td></tr>
</tbody></table>
<p>The configuration is decrypted with a hard-coded key before the loader proceeds.</p>
<p>Persistence is established through a scheduled task that runs every hour.</p>
<p>Network traffic is tunnelled over HTTPS with a custom header.</p>
<h2>Indicators of compromise</h2>
<ul><li>evil-c2[.]example</li><li>198.51.100.21</li><li>${hex('d')}</li></ul>`);
  const q = x.diagnostics.quality;
  assert.deepEqual(codes(q, 'warning'), []);
  assert.deepEqual(codes(q, 'high'), []);
  assert.deepEqual(codes(q, 'info'), [QUALITY_CODES.INDICATOR_ROWS_OUTSIDE_SCOPE]);
});

test('narrative hashes outside the appendix (MODE A strict) do not warn', () => {
  const x = run(`<h2>Technical analysis</h2>
<p>The dropper wrote ${hex('e')} to disk, then fetched ${hex('f')} and ${hex('a')} before beaconing.</p>
<h2>Indicators of compromise</h2><p>${hex('b')}</p><p>evil-c2[.]example</p>`);
  assert.equal(x.diagnostics.quality.status, 'clean');
});

test('legitimate binaries in an analysis table are not reported as lost rows', () => {
  const x = run(`<h2>Technical analysis</h2>
<table><thead><tr><th>Filename</th><th>MD5</th><th>Description</th></tr></thead><tbody>
<tr><td>RasTls.exe</td><td>${hex('a')}</td><td>Legitimate signed binary</td></tr>
<tr><td>MsMpEng.exe</td><td>${hex('b')}</td><td>Legitimate Microsoft component</td></tr>
<tr><td>vmtoolsd.exe</td><td>${hex('c')}</td><td>Legitimate VMware binary</td></tr>
</tbody></table>
<h2>Indicators of compromise</h2><p>${hex('d')} RasTls.dll</p><p>evil-c2[.]example</p>`);
  assert.equal(x.diagnostics.quality.status, 'clean', JSON.stringify(x.diagnostics.quality.warnings));
});

test('MODE B reports never get scope warnings', () => {
  const x = run(`<p>The stealer beacons to c2-update[.]info and downloads ${hex('a')}, ${hex('b')} and ${hex('c')}.</p>`);
  assert.equal(x.diagnostics.quality.mode, 'B');
  assert.deepEqual(codes(x.diagnostics.quality).filter((c) => /scope|appendix/.test(c)), []);
});

test('an IOC heading without observables is info (published elsewhere)', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<p>The full list is available in our public repository.</p>
<h2>Detection</h2><p>Alert on unsigned DLLs loaded by signed hosts.</p>`);
  const q = x.diagnostics.quality;
  assert.deepEqual(codes(q), [QUALITY_CODES.AUTHORITATIVE_SECTION_EMPTY]);
  assert.equal(q.warnings[0].severity, 'info');
});

test('merged value paragraph inside the appendix: values left to the model warn', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<p>loader.exe ${hex('a')} helper.dll ${hex('b')} plugin.dll ${hex('c')}</p>
<ul><li>evil-c2[.]example</li></ul>`);
  const q = x.diagnostics.quality;
  assert.ok(codes(q).includes(QUALITY_CODES.AUTHORITATIVE_VALUES_NOT_ASSERTED), JSON.stringify(codes(q)));
  assert.ok(codes(q, 'high').includes(QUALITY_CODES.APPENDIX_WITHOUT_HASH_INDICATORS));
});

test('suspicious Indicators: publisher domain family is flagged', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<ul><li>cdn.vendor-research[.]example</li><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>`);
  const w = x.diagnostics.quality.warnings.find((y) => y.code === QUALITY_CODES.PUBLISHER_DOMAIN_INDICATOR);
  assert.ok(w);
  assert.deepEqual(w.candidates, ['domain:cdn.vendor-research.example']);
});

test('suspicious Indicators: reserved, example, legitimate marker, email-only, missing provenance (direct input)', () => {
  const base = {
    is_ioc: true,
    assessment: 'malicious',
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    evidence_text: 'row'
  };
  const occ = (extra = {}) => ({ block_id: 'b1', zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row', surrounding_text: 'row', ...extra });
  const candidates = [
    { ...base, candidate_type: 'domain', normalized_value: 'docs.example', rfc_example: true, occurrences: [occ()] },
    { ...base, candidate_type: 'md5', normalized_value: hex('a'), occurrences: [occ({ relation_marker: 'benign' })] },
    { ...base, candidate_type: 'domain', normalized_value: 'mailer.example', occurrences: [occ({ form: 'email_domain' })] },
    { ...base, candidate_type: 'ip', normalized_value: '198.51.100.9', evidence_text: null, occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }] }
  ];
  const q = assessExtractionQuality({ blocks: [], candidates, diagnostics: {} });
  assert.deepEqual(codes(q), [
    QUALITY_CODES.EXAMPLE_INDICATOR,
    QUALITY_CODES.LEGITIMATE_MARKER_INDICATOR,
    QUALITY_CODES.EMAIL_DOMAIN_ONLY_INDICATOR,
    QUALITY_CODES.INDICATOR_MISSING_PROVENANCE
  ].sort());
  // Reserved identities never pass the membership gates, so the defensive check stays silent.
  const reserved = assessExtractionQuality({
    blocks: [],
    candidates: [{ ...base, candidate_type: 'ip', normalized_value: '127.0.0.1', reserved_address: true, non_actionable_local: true, occurrences: [occ()] }],
    diagnostics: {}
  });
  assert.equal(codes(reserved).includes(QUALITY_CODES.RESERVED_INDICATOR), false);
});

test('explicit table inconsistency passes through as a high warning', () => {
  const q = assessExtractionQuality({
    blocks: [],
    candidates: [],
    diagnostics: {
      explicit_tables: {
        inconsistent: true,
        missing_identities: ['domain:lost.example'],
        dropped_asserted_identities: [{ type: 'domain', value: 'lost.example', reason: 'embedded_in_dns_hostname' }]
      }
    }
  });
  assert.equal(q.status, 'high');
  assert.equal(q.warnings[0].code, QUALITY_CODES.EXPLICIT_TABLE_ROWS_DROPPED);
  assert.deepEqual(q.warnings[0].candidates, ['domain:lost.example']);
});

test('read-only: assessment never changes candidates, membership or MODE', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>C2 servers</h3><ul><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>
<h3>Loaders</h3><pre>loader.exe ${hex('a')}
helper.dll ${hex('b')}
plugin.dll ${hex('c')}</pre>`);
  const snapshot = JSON.stringify(x.candidates);
  const before = members(x.candidates);
  const q = assessExtractionQuality({ blocks: x.annotated.blocks, candidates: x.candidates, diagnostics: x.diagnostics, sourceHost: 'vendor-research.example' });
  assert.ok(q.warnings.length > 0);
  assert.equal(JSON.stringify(x.candidates), snapshot);
  assert.deepEqual(members(x.candidates), before);
  assert.ok(x.candidates.every((c) => c.__member === undefined));
});

test('persisted diagnostics keep a bounded quality record', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>C2 servers</h3><ul><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>
<h3>Loaders</h3><pre>loader.exe ${hex('a')}
helper.dll ${hex('b')}
plugin.dll ${hex('c')}</pre>`);
  const compact = compactExtractionDiagnostics(x.diagnostics);
  assert.equal(compact.quality.version, 'tl-quality-v1');
  assert.equal(compact.quality.status, 'high');
  assert.ok(compact.quality.warnings.every((w) => w.code && w.severity && Array.isArray(w.candidates)));
  assert.equal(compactExtractionQuality(null), null);
  const many = assessExtractionQuality({
    blocks: [],
    candidates: Array.from({ length: 60 }, (_, i) => ({
      candidate_type: 'domain',
      normalized_value: `d${i}.example`,
      is_ioc: true,
      rfc_example: true,
      assessment: 'malicious',
      source_assertion: 'explicit_ioc',
      document_has_authoritative_scope: true,
      evidence_text: 'x',
      occurrences: [{ block_id: 'b', zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'list_item', surrounding_text: 'x' }]
    })),
    diagnostics: {}
  });
  assert.equal(many.warnings[0].candidate_count, 60);
  assert.equal(many.warnings[0].candidates.length, EXTRACTION_QUALITY_THRESHOLDS.maxListedCandidates);
});

test('stored quality accessors for report rows (REST extraction_quality, MCP summary)', async () => {
  const { storedExtractionQuality, extractionQualitySummary } = await import('./extractionQuality.js');
  assert.equal(storedExtractionQuality({ analysis_progress: {} }), null);
  assert.equal(storedExtractionQuality(null), null);
  const quality = { version: 'tl-quality-v1', status: 'warning', mode: 'A', counts: { high: 0, warning: 1, info: 0 }, warnings: [{ code: 'x' }, { code: 'x' }] };
  const row = { analysis_progress: { extraction_diagnostics: { quality } } };
  assert.equal(storedExtractionQuality(row), quality);
  assert.deepEqual(extractionQualitySummary(quality), {
    version: 'tl-quality-v1', status: 'warning', mode: 'A', counts: { high: 0, warning: 1, info: 0 }, codes: ['x'], warnings_total: 2
  });
  assert.equal(extractionQualitySummary(null), null);
});
