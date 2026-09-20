/**
 * THIB export carries indicator provenance and never exports parser-derived hosts.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { exportThibBundle, validateThibBundle, thibIndicatorEvidence } from './codec.js';

const report = {
  title: 'Kimsuky LNK chain',
  source_type: 'pdf',
  tlp: 'clear',
  summary: 'sum',
  portable_id: 'report--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  bundle_id: 'thib--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
};

const urlRow = {
  id: 1,
  portable_id: 'indicator--11111111-1111-4111-8111-111111111111',
  candidate_type: 'url',
  normalized_value: 'http://217.60.36.94/unicorn/mort.php',
  assessment: 'malicious',
  role: 'command_and_control',
  confidence: 0.9,
  review_status: 'approved',
  match_state: 'new',
  source_assertion: 'explicit_c2',
  evidence: {
    source_assertion: 'explicit_c2',
    evidence_strength: 'strong',
    occurrence_count: 2,
    zones: ['report_body', 'c2_section'],
    parsed: { host: '217.60.36.94', host_kind: 'ip', host_independently_asserted: false },
    occurrences: [{ page: 7, zone: 'report_body' }, { page: 17, zone: 'c2_section' }]
  }
};
const endpointRow = {
  id: 2,
  portable_id: 'indicator--22222222-2222-4222-8222-222222222222',
  candidate_type: 'ip',
  normalized_value: '107.172.249.140',
  assessment: 'malicious',
  role: 'command_and_control',
  confidence: 0.9,
  review_status: 'approved',
  match_state: 'new',
  source_assertion: 'explicit_c2',
  evidence: { occurrence_count: 2, zones: ['report_body', 'c2_section'], parsed: { ports: [443] }, occurrences: [{ page: 11, port: 443 }, { page: 17, port: 443 }] }
};
// A legacy / hypothetical parser-derived host row must never be exported as its own indicator.
const derivedHost = {
  id: 3,
  portable_id: 'indicator--33333333-3333-4333-8333-333333333333',
  candidate_type: 'ip',
  normalized_value: '217.60.36.94',
  assessment: 'malicious',
  role: 'command_and_control',
  review_status: 'approved',
  match_state: 'new',
  evidence: { is_parser_derived_metadata: true, derived_from: 'url:http://217.60.36.94/unicorn/mort.php' }
};
const reference = {
  id: 4,
  portable_id: 'indicator--44444444-4444-4444-8444-444444444444',
  candidate_type: 'url',
  normalized_value: 'https://www.fortinet.com/fr/blog/threat-research/x',
  assessment: 'context_only',
  role: 'reference',
  review_status: 'context_only',
  match_state: 'context_only',
  source_assertion: 'reference_only',
  evidence: { occurrence_count: 1, zones: ['reference_section'], parsed: { host: 'www.fortinet.com' }, occurrences: [{ page: 17, zone: 'reference_section' }] }
};

test('exported indicators carry provenance; URL host stays inside URL evidence', () => {
  const bundle = exportThibBundle({ report, entities: [], candidates: [urlRow, endpointRow, derivedHost, reference], relationships: [] });
  assert.equal(validateThibBundle(bundle).ok, true);
  const values = bundle.indicators.map((i) => `${i.type}:${i.value}`);
  assert.deepEqual(values, [
    'url:http://217.60.36.94/unicorn/mort.php',
    'ip:107.172.249.140',
    'url:https://www.fortinet.com/fr/blog/threat-research/x'
  ]);
  assert.equal(values.includes('ip:217.60.36.94'), false, 'parser-derived host is not a separate indicator object');

  const url = bundle.indicators[0];
  assert.equal(url.evidence.source_assertion, 'explicit_c2');
  assert.equal(url.evidence.url_host, '217.60.36.94');
  assert.deepEqual(url.evidence.pages, [7, 17]);
  assert.equal(url.evidence.occurrence_count, 2);

  const ep = bundle.indicators[1];
  assert.deepEqual(ep.evidence.ports, [443]);
  assert.equal(ep.evidence.url_host, null);

  const ref = bundle.indicators[2];
  assert.equal(ref.assessment, 'context_only');
  assert.equal(ref.evidence.source_assertion, 'reference_only');

  const s = JSON.stringify(bundle);
  assert.equal(/"ioc_id"\s*:/.test(s), false);
  assert.equal(/"matched_ioc_id"\s*:/.test(s), false);
});

test('spec 1.0 bundles without evidence still validate; evidence helper tolerates legacy rows', () => {
  const bundle = exportThibBundle({
    report,
    entities: [],
    candidates: [{ ...urlRow, evidence: undefined, source_assertion: undefined }],
    relationships: []
  });
  assert.equal(validateThibBundle(bundle).ok, true);
  assert.equal(bundle.indicators[0].evidence, null);
  assert.equal(thibIndicatorEvidence({ candidate_type: 'url' }), null);
  assert.equal(bundle.spec_version, '1.0');
});

test('report-level confidence stays in the THIB report block (UI Overview no longer shows it)', () => {
  const bundle = exportThibBundle({ report: { ...report, confidence: '0.950' }, entities: [], candidates: [urlRow], relationships: [] });
  assert.equal(validateThibBundle(bundle).ok, true);
  assert.equal(bundle.report.confidence, 0.95);
  assert.equal(bundle.indicators[0].confidence, 0.9, 'indicator confidence is a separate field and unchanged');
  const absent = exportThibBundle({ report, entities: [], candidates: [], relationships: [] });
  assert.equal(absent.report.confidence, null);
});
