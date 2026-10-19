/**
 * Extraction quality detector (tl-quality-v6): each reason code on a minimal
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
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v9');
  assert.ok(Object.isFrozen(EXTRACTION_QUALITY_THRESHOLDS));
  assert.equal(EXTRACTION_QUALITY_THRESHOLDS.orphanRunMinValues, 3);
  assert.equal(EXTRACTION_QUALITY_THRESHOLDS.appendixHeadingNonmemberMinValues, 2);
  assert.equal(new Set(Object.values(QUALITY_CODES)).size, Object.keys(QUALITY_CODES).length);
});

test('clean IOC appendix: no warning', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>Network</h3><ul><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>
<h3>File hashes</h3><p>${hex('a')}</p><p>${hex('b')}</p><p>${hex('c')}</p>`);
  assert.equal(x.diagnostics.quality.status, 'clean');
  assert.equal(x.diagnostics.quality.mode, 'A');
});

test('typed Loaders subgroup under an IOC appendix stays in scope (P1) and stays clean', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>C2 servers</h3><ul><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>
<h3>Loaders</h3>
<pre>loader.exe ${hex('a')}
helper.dll ${hex('b')}
plugin.dll ${hex('c')}</pre>`);
  const q = x.diagnostics.quality;
  assert.equal(q.status, 'clean', JSON.stringify(q.warnings));
  assert.deepEqual(members(x.candidates).filter((id) => id.startsWith('md5:')), [
    `md5:${hex('a')}`,
    `md5:${hex('b')}`,
    `md5:${hex('c')}`
  ]);
  assert.equal(q.version, EXTRACTION_QUALITY_VERSION);
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
  // Mixed pair order — which filename belongs to which hash is not recoverable,
  // so the paragraph stays narrative and the detector must surface it.
  const x = run(`<h2>Indicators of compromise</h2>
<p>loader.exe ${hex('a')} ${hex('b')} helper.dll plugin.dll ${hex('c')}</p>
<ul><li>evil-c2[.]example</li></ul>`);
  const q = x.diagnostics.quality;
  assert.ok(codes(q).includes(QUALITY_CODES.AUTHORITATIVE_VALUES_NOT_ASSERTED), JSON.stringify(codes(q)));
  assert.ok(codes(q, 'high').includes(QUALITY_CODES.APPENDIX_WITHOUT_HASH_INDICATORS));
});

test('pure filename/hash inventory paragraph inside the appendix is read as rows (tl-zones-v11)', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<p>loader.exe ${hex('a')} helper.dll ${hex('b')} plugin.dll ${hex('c')}</p>
<ul><li>evil-c2[.]example</li></ul>`);
  const q = x.diagnostics.quality;
  assert.deepEqual(
    members(x.candidates).filter((id) => id.startsWith('md5:')).sort(),
    [hex('a'), hex('b'), hex('c')].map((h) => `md5:${h}`).sort()
  );
  assert.ok(!codes(q).includes(QUALITY_CODES.AUTHORITATIVE_VALUES_NOT_ASSERTED), JSON.stringify(codes(q)));
  assert.ok(!codes(q).includes(QUALITY_CODES.APPENDIX_WITHOUT_HASH_INDICATORS), JSON.stringify(codes(q)));
});

test('publisher-host family is not a report Indicator; quality still flags residual publisher-domain members', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<ul><li>cdn.vendor-research[.]example</li><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>`);
  // Gate: same-site publisher chrome is provenance, not an Indicator.
  assert.equal(members(x.candidates).includes('domain:cdn.vendor-research.example'), false);
  assert.ok(members(x.candidates).includes('domain:evil-c2.example'));
  // Defensive quality path: if a publisher-family domain somehow remained a member.
  const q = assessExtractionQuality({
    blocks: x.annotated.blocks,
    candidates: [
      ...x.candidates,
      {
        candidate_type: 'domain',
        normalized_value: 'cdn.vendor-research.example',
        is_ioc: true,
        assessment: 'malicious',
        source_assertion: 'explicit_ioc',
        document_has_authoritative_scope: true,
        evidence_text: 'cdn.vendor-research.example',
        occurrences: [{ block_id: 'b1', zone: 'explicit_ioc_section', asserted: true, surrounding_text: 'cdn.vendor-research.example' }]
      }
    ],
    diagnostics: x.diagnostics,
    sourceHost: 'vendor-research.example'
  });
  const w = q.warnings.find((y) => y.code === QUALITY_CODES.PUBLISHER_DOMAIN_INDICATOR);
  assert.ok(w);
  assert.ok(w.candidates.includes('domain:cdn.vendor-research.example'));
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
<ul><li>evil-c2[.]example</li><li>198.51.100.21</li><li>${hex('a')}</li></ul>
<h2>Technical analysis</h2>
<table><thead><tr><th>Component</th><th>MD5</th></tr></thead><tbody>
<tr><td>stage2.bin</td><td>${hex('b')}</td></tr><tr><td>stage3.bin</td><td>${hex('c')}</td></tr><tr><td>cfg.dat</td><td>${hex('d')}</td></tr>
</tbody></table>`);
  const snapshot = JSON.stringify(x.candidates);
  const before = members(x.candidates);
  const q = assessExtractionQuality({ blocks: x.annotated.blocks, candidates: x.candidates, diagnostics: x.diagnostics, sourceHost: 'vendor-research.example' });
  assert.ok(q.warnings.length > 0 || q.status === 'info' || q.status === 'clean');
  assert.equal(JSON.stringify(x.candidates), snapshot);
  assert.deepEqual(members(x.candidates), before);
  assert.ok(x.candidates.every((c) => c.__member === undefined));
});

test('persisted diagnostics keep a bounded quality record', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<p>The full list is available in our public repository.</p>`);
  const compact = compactExtractionDiagnostics(x.diagnostics);
  assert.equal(compact.quality.version, EXTRACTION_QUALITY_VERSION);
  assert.equal(compact.quality.status, 'info');
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

// --- False-positive-prone layouts (measured 2026-10-15; not threshold tuning) --

test('a dropped-files table right BEFORE the appendix is analysis content: info only', () => {
  const x = run(`<h2>Technical analysis</h2>
<p>The installer dropped these files.</p>
<table><thead><tr><th>Filename</th><th>MD5</th></tr></thead><tbody>
<tr><td>a.dll</td><td>${hex('b')}</td></tr><tr><td>b.dll</td><td>${hex('c')}</td></tr><tr><td>c.dll</td><td>${hex('d')}</td></tr>
</tbody></table>
<h2>Indicators of compromise</h2>
<ul><li>evil-c2[.]example</li><li>198.51.100.21</li><li>${hex('a')}</li></ul>`);
  const q = x.diagnostics.quality;
  assert.deepEqual(codes(q, 'warning'), []);
  assert.deepEqual(codes(q, 'high'), []);
  assert.deepEqual(codes(q, 'info'), [QUALITY_CODES.INDICATOR_ROWS_OUTSIDE_SCOPE]);
});

test('filename/hash Loaders subgroup after C2 stays inside the appendix (P1 scope retention)', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>C2 servers</h3><ul><li>evil-c2[.]example</li><li>198.51.100.21</li></ul>
<h3>Loaders</h3>
<pre>a.dll ${hex('b')}
b.dll ${hex('c')}
c.dll ${hex('d')}</pre>`);
  assert.equal(x.diagnostics.quality.status, 'clean', JSON.stringify(x.diagnostics.quality.warnings));
  assert.ok(members(x.candidates).includes(`md5:${hex('b')}`));
});

test('references after the appendix, legitimate detection tables and narrative hashes stay clean', () => {
  const appendix = `<h2>Indicators of compromise</h2><ul><li>evil-c2[.]example</li><li>198.51.100.21</li><li>${hex('a')}</li></ul>`;
  for (const inner of [
    `${appendix}<h2>References</h2><ul><li>https://vendor.example/a</li><li>https://vendor.example/b</li><li>https://vendor.example/c</li></ul>`,
    `${appendix}<h2>Detection opportunities</h2><table><tr><th>File</th><th>SHA256</th><th>Note</th></tr>${['1', '2', '3']
      .map((c, i) => `<tr><td>tool${i}.exe</td><td>${c.repeat(64)}</td><td>Legitimate Windows binary</td></tr>`).join('')}</table>`,
    `${appendix}<h2>Analysis</h2><p>Samples ${hex('e')}, ${hex('f')} and ${hex('0')} share code with older variants.</p>`
  ]) {
    assert.equal(run(inner).diagnostics.quality.status, 'clean');
  }
});

// --- tl-quality-v3: false warnings measured on production / real reports ---

test('a table not read as explicit is silent when every IOC value in it is an Indicator anyway', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<ul><li>evil-c2[.]example</li><li>198.51.100.21</li><li>${hex('a')}</li></ul>`);
  const member = x.annotated.blocks.find((b) => /evil-c2/.test(String(b.text || '')));
  const assess = (blockId) => assessExtractionQuality({
    blocks: x.annotated.blocks,
    candidates: x.candidates,
    diagnostics: { ...x.diagnostics, structural_completeness: { tables_not_interpreted: [{ block_id: blockId, ioc_shaped_values: 3, reason: 'no_header', zone: 'explicit_ioc_section' }] } }
  });
  assert.deepEqual(codes(assess(member.id), 'warning'), []);
  // A table whose values never became Indicators still warns.
  assert.ok(codes(assess('no-such-block'), 'warning').includes(QUALITY_CODES.AUTHORITATIVE_TABLE_NOT_INTERPRETED));
});

test('values left to the model are silent when each is the platform of a more specific Indicator', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<ul><li>https://api.github[.]com/repos/actor-team/payloads</li><li>g-prx.operator1.workers[.]dev</li><li>198.51.100.21</li></ul>
<p>GitHub (github.com, api.github.com) and Cloudflare workers.dev are shared platforms; match the exact repository and Worker host.</p>`);
  const prose = x.annotated.blocks.find((b) => /shared platforms/.test(String(b.text || '')));
  const assess = (blockId) => assessExtractionQuality({
    blocks: x.annotated.blocks,
    candidates: x.candidates,
    diagnostics: { ...x.diagnostics, structural_completeness: { degraded_blocks: [{ block_id: blockId, ai_needed_values: 3, block_type: 'paragraph', zone: 'explicit_ioc_section' }] } }
  });
  assert.deepEqual(codes(assess(prose.id), 'warning'), []);
});

test('body Domain|IP|First seen table outside the appendix stays non-Indicator (P1) and stays silent when duplicates are appendix-only', () => {
  const x = run(`<h2>Infrastructure</h2>
<table><thead><tr><th>Domain</th><th>IP</th><th>First seen</th><th>ASN</th></tr></thead><tbody>
<tr><td>pinkgoat-c2.example</td><td>203.0.113.11</td><td>2022-03-03</td><td>AS64500</td></tr>
<tr><td>purplebear-c2.example</td><td>203.0.113.12</td><td>2021-01-08</td><td>AS64501</td></tr>
<tr><td>greycat-c2.example</td><td>203.0.113.13</td><td>2020-09-01</td><td>AS64502</td></tr>
</tbody></table>
<h2>Indicators of compromise</h2>
<h3>C2 domains</h3><ul><li>pinkgoat-c2[.]example</li><li>purplebear-c2[.]example</li><li>greycat-c2[.]example</li></ul>
<h3>MD5</h3><ul><li>${hex('a')}</li><li>${hex('b')}</li></ul>`);
  const q = x.diagnostics.quality;
  // P1: infrastructure-lookup tables no longer self-prove; resolution IPs
  // must not become Indicators. Shared appendix domains do not warn.
  assert.equal(members(x.candidates).includes('ip:203.0.113.11'), false);
  assert.equal(members(x.candidates).includes('ip:203.0.113.12'), false);
  assert.ok(!codes(q).includes(QUALITY_CODES.BODY_IOC_TABLE_OUTSIDE_APPENDIX), JSON.stringify(q.warnings));
});

test('body IOC table that exclusively contributes Indicators still warns', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<ul><li>evil-c2[.]example</li><li>${hex('a')}</li></ul>
<h2>Related infrastructure</h2>
<table><thead><tr><th>Type</th><th>Indicator</th><th>Description</th></tr></thead><tbody>
<tr><td>IP</td><td>203.0.113.88</td><td>resolver</td></tr>
<tr><td>IP</td><td>203.0.113.89</td><td>resolver</td></tr>
<tr><td>Domain</td><td>only-in-body.example</td><td>sighting</td></tr>
</tbody></table>`);
  const q = x.diagnostics.quality;
  // Type|Indicator tables may still self-prove; exclusive body members warn.
  if (members(x.candidates).some((id) => id === 'domain:only-in-body.example' || id.startsWith('ip:203.0.113.8'))) {
    assert.ok(codes(q).includes(QUALITY_CODES.BODY_IOC_TABLE_OUTSIDE_APPENDIX) || codes(q).includes(QUALITY_CODES.INDICATORS_FROM_STRUCTURAL_DISCOVERY), JSON.stringify(q.warnings));
  }
});

test('legitimate-service lead-in demotes unlabelled list; chrome discovery no longer warns as Indicators', () => {
  const x = run(`<h2>Check suspicious network communications</h2>
<p>The malware interacts with numerous legitimate web services; unexpected connections to them may indicate compromise.</p>
<ul><li>api[.]telegram[.]org</li><li>backblazeb2[.]com</li><li>storjshare[.]io</li><li>lightningproxies[.]net</li></ul>`);
  const q = x.diagnostics.quality;
  assert.equal(members(x.candidates).includes('domain:api.telegram.org'), false);
  assert.equal(members(x.candidates).includes('domain:storjshare.io'), false);
  assert.ok(!codes(q).includes(QUALITY_CODES.INDICATORS_FROM_STRUCTURAL_DISCOVERY), JSON.stringify(q.warnings));
});

test('two row-shaped non-members retaining an IOC section_heading warn below orphan-run threshold', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<ul><li>evil-c2[.]example</li><li>198.51.100.21</li><li>${hex('a')}</li></ul>`);
  const q = assessExtractionQuality({
    blocks: x.annotated.blocks,
    candidates: [
      ...x.candidates,
      {
        candidate_type: 'domain',
        normalized_value: 'lost-one.example',
        is_ioc: true,
        document_has_authoritative_scope: true,
        policy_decision: 'context_only_narrative_with_authoritative_scope',
        occurrences: [{
          block_id: 'lost-b1',
          zone: 'report_body',
          form: 'list_row',
          structural_row: true,
          section_heading: 'Indicators of compromise'
        }]
      },
      {
        candidate_type: 'domain',
        normalized_value: 'lost-two.example',
        is_ioc: true,
        document_has_authoritative_scope: true,
        policy_decision: 'context_only_narrative_with_authoritative_scope',
        occurrences: [{
          block_id: 'lost-b2',
          zone: 'report_body',
          form: 'list_row',
          structural_row: true,
          section_heading: 'Indicators of compromise'
        }]
      }
    ],
    diagnostics: x.diagnostics
  });
  const w = q.warnings.find((y) => y.code === QUALITY_CODES.APPENDIX_HEADING_NONMEMBER_ROWS);
  assert.ok(w, JSON.stringify(q.warnings.map((y) => y.code)));
  assert.equal(w.severity, 'warning');
  assert.deepEqual(w.candidates, ['domain:lost-one.example', 'domain:lost-two.example']);
  assert.equal(w.section.heading, 'Indicators of compromise');
});

test('discovery rows still governed by the publisher IOC heading are not reported', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>MD5</h3><ul><li>${hex('a')}</li><li>${hex('b')}</li></ul>
<h3>C2</h3><p>45.150.109[.]102</p><p>85.155.224[.]59</p><p>103.153.65[.]67</p><p>111.92.246[.]145</p>`);
  const q = x.diagnostics.quality;
  assert.ok(!codes(q).includes(QUALITY_CODES.INDICATORS_FROM_STRUCTURAL_DISCOVERY), JSON.stringify(q.warnings));
});
