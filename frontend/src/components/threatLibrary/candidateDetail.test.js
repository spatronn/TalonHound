/**
 * Table evidence preview and drawer detail read the same candidate row and
 * expose only display values — no canonical field is rewritten.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { candidateDisplayValue, describeCandidateDetail, describeEvidencePreview } from './candidateDetail.js';

const explicitIp = Object.freeze({
  id: 2430,
  candidate_type: 'ip',
  original_value: '157[.]185[.]143[.]150',
  normalized_value: '157.185.143.150',
  assessment: 'malicious',
  role: 'malicious_infrastructure',
  confidence: '0.900',
  evidence_text: 'Recent examples resolve to 157[.]185[.]143[.]150.',
  review_status: 'approved',
  match_state: 'existing',
  matched_ioc_id: 9001,
  matched_ioc_observable_type: 'ip',
  promotion_outcome: 'already_existing',
  promotion_detail: null,
  is_ioc: true,
  source_assertion: 'explicit_ioc',
  evidence: {
    source_assertion: 'explicit_ioc',
    decision_source: 'deterministic',
    is_direct_source_observable: true,
    is_parser_derived_metadata: false,
    occurrence_count: 2,
    zones: ['report_body'],
    parsed: {},
    table_rows: [],
    occurrences: [
      { block_id: 'b120', page: null, zone: 'report_body', section_heading: 'Recent Examples of Illegal Chinese-Language Casinos', form: 'ip', port: null, surrounding_text: 'hosted at 157[.]185[.]143[.]150 alongside' },
      { block_id: 'b131', page: null, zone: 'report_body', section_heading: 'Recent Examples of Illegal Chinese-Language Casinos', form: 'ip', port: null, surrounding_text: 'second sighting' }
    ]
  }
});

const aiUrl = Object.freeze({
  id: 77,
  candidate_type: 'url',
  normalized_value: 'js.cache-mcp.com/layer.js',
  assessment: 'suspicious',
  role: 'payload_hosting',
  confidence: '0.62',
  review_status: 'pending',
  match_state: 'needs_review',
  promotion_outcome: null,
  is_ioc: true,
  source_assertion: 'body_mention',
  evidence: {
    source_assertion: 'body_mention',
    decision_source: 'ai',
    occurrence_count: 1,
    parsed: { host: 'js.cache-mcp.com', host_kind: 'domain' },
    occurrences: [{ page: 3, zone: 'report_body' }],
    table_rows: [{ table_id: 't2', row_index: 4, type_cell: 'URL', description: 'Loader script' }]
  }
});

test('evidence preview is three short lines from the row provenance', () => {
  const p = describeEvidencePreview(explicitIp);
  assert.equal(p.primary, 'Explicit IOC');
  assert.equal(p.secondary, 'Recent Examples of Illegal Chinese-Language Casinos');
  assert.equal(p.tertiary, '2 occurrences');
  assert.equal(p.warning, null);
});

test('evidence preview flags AI decisions, derived values and table references', () => {
  const p = describeEvidencePreview(aiUrl);
  assert.equal(p.primary, 'Body assertion · AI');
  assert.equal(p.secondary, 'report body');
  assert.equal(p.tertiary, '1 occurrence · p3');
  const derived = describeEvidencePreview({ ...aiUrl, evidence: { ...aiUrl.evidence, is_direct_source_observable: false, occurrences: [] } });
  assert.match(derived.primary, /derived/);
  assert.equal(derived.secondary, 'table t2 row 5');
});

test('drawer detail carries labels plus canonical raw values', () => {
  const d = describeCandidateDetail(explicitIp);
  assert.equal(d.value, '157.185.143.150');
  assert.equal(d.typeLabel, 'IP');
  const byKey = Object.fromEntries(d.fields.map((f) => [f.key, f]));
  assert.equal(byKey.assessment.value, 'Malicious');
  assert.equal(byKey.assessment.raw, 'malicious');
  assert.equal(byKey.role.value, 'Malicious infrastructure');
  assert.equal(byKey.role.raw, 'malicious_infrastructure');
  assert.equal(byKey.confidence.value, 'Source asserted');
  assert.equal(byKey.review_status.value, 'Approved');
  assert.equal(byKey.match.value, 'Matched (IP)');
  assert.equal(byKey.ioc_result.value, 'Already exists');
  assert.equal(byKey.ioc_result.raw, 'already_existing');
  assert.equal(byKey.original_value.value, '157[.]185[.]143[.]150');
  assert.equal(d.evidence.assertion, 'Explicit IOC');
  assert.equal(d.evidence.decision, 'Report evidence');
  assert.equal(d.evidence.occurrenceCount, 2);
  assert.equal(d.evidence.text, 'Recent examples resolve to 157[.]185[.]143[.]150.');
  assert.equal(d.occurrences.length, 2);
  assert.equal(d.occurrences[0].label, 'Recent Examples of Illegal Chinese-Language Casinos · ip');
  assert.equal(d.occurrences[0].text, 'hosted at 157[.]185[.]143[.]150 alongside');
  assert.deepEqual(d.tableRows, []);
});

test('drawer detail includes table references, AI confidence and URL host metadata', () => {
  const d = describeCandidateDetail(aiUrl);
  const byKey = Object.fromEntries(d.fields.map((f) => [f.key, f]));
  assert.equal(byKey.confidence.value, '62%');
  assert.equal(byKey.review_status.value, 'Pending');
  assert.equal(byKey.match.value, 'Needs review');
  assert.equal(byKey.ioc_result.value, '—');
  assert.equal(d.evidence.decision, 'AI');
  assert.equal(d.evidence.urlHost, 'js.cache-mcp.com');
  assert.equal(d.tableRows.length, 1);
  assert.equal(d.tableRows[0].label, 'Table t2 · row 5 · URL');
  assert.equal(d.tableRows[0].description, 'Loader script');
  assert.equal(d.occurrences[0].label, 'report body · p3');
});

test('promoted timestamp goes through the supplied formatter', () => {
  const d = describeCandidateDetail({ ...explicitIp, promoted_at: '2026-09-17T23:36:34+03:00' }, { formatDateTime: (v) => `fmt(${v})` });
  assert.equal(d.fields.find((f) => f.key === 'promoted_at').value, 'fmt(2026-09-17T23:36:34+03:00)');
});

test('describing a row never mutates it', () => {
  const before = JSON.stringify(explicitIp);
  describeEvidencePreview(explicitIp);
  describeCandidateDetail(explicitIp);
  assert.equal(JSON.stringify(explicitIp), before);
  assert.equal(explicitIp.role, 'malicious_infrastructure');
});

test('display value prefers normalized over original and tolerates empty rows', () => {
  assert.equal(candidateDisplayValue(explicitIp), '157.185.143.150');
  assert.equal(candidateDisplayValue({ original_value: 'x' }), 'x');
  assert.equal(candidateDisplayValue(null), '');
  const d = describeCandidateDetail(null);
  assert.equal(d.value, '');
  assert.ok(Array.isArray(d.fields));
});
