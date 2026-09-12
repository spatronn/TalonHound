/**
 * Review-table helpers: evidence-filtered indicator set, provenance labels,
 * checkpoint-aware failure detail.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_REVIEW_FILTER,
  REVIEW_FILTERS,
  describeAnalysisFailureDetail,
  describeCandidateProvenance,
  isReviewIndicator,
  matchReviewFilter
} from './candidateReview.js';

const explicitUrl = {
  candidate_type: 'url',
  normalized_value: 'http://217.60.36.94/unicorn/mort.php',
  assessment: 'malicious',
  match_state: 'new',
  review_status: 'pending',
  is_ioc: true,
  source_assertion: 'explicit_c2',
  evidence: {
    source_assertion: 'explicit_c2',
    decision_source: 'deterministic',
    occurrence_count: 2,
    zones: ['report_body', 'c2_section'],
    parsed: { host: '217.60.36.94', host_kind: 'ip' },
    occurrences: [
      { page: 7, zone: 'report_body', section_heading: '2.载荷投递分析' },
      { page: 17, zone: 'c2_section', section_heading: 'C&C:' }
    ]
  }
};
const referenceUrl = {
  candidate_type: 'url',
  normalized_value: 'https://www.fortinet.com/fr/blog/threat-research/x',
  assessment: 'context_only',
  match_state: 'context_only',
  review_status: 'pending',
  is_ioc: true,
  source_assertion: 'reference_only',
  evidence: { source_assertion: 'reference_only', occurrence_count: 1, occurrences: [{ page: 17, zone: 'reference_section' }] }
};
const cve = { candidate_type: 'cve', normalized_value: 'CVE-2026-0001', assessment: 'context_only', match_state: 'context_only', is_ioc: false };
const derived = { candidate_type: 'ip', normalized_value: '217.60.36.94', assessment: 'unknown', match_state: 'needs_review', review_status: 'pending', evidence: { is_parser_derived_metadata: true } };
const bodyIp = {
  candidate_type: 'ip',
  normalized_value: '107.172.249.140',
  assessment: 'malicious',
  match_state: 'new',
  review_status: 'pending',
  source_assertion: 'explicit_c2',
  evidence: { decision_source: 'deterministic', occurrence_count: 2, parsed: { ports: [443] }, occurrences: [{ page: 11, zone: 'report_body' }, { page: 17, zone: 'c2_section', section_heading: 'C&C:' }] }
};

test('default review filter shows real IOC candidates only', () => {
  assert.equal(DEFAULT_REVIEW_FILTER, 'indicators');
  assert.equal(REVIEW_FILTERS[0].id, 'indicators');
  assert.equal(isReviewIndicator(explicitUrl), true);
  assert.equal(isReviewIndicator(bodyIp), true);
  assert.equal(isReviewIndicator(referenceUrl), false, 'bibliography stays out of the indicator table');
  assert.equal(isReviewIndicator(cve), false);
  assert.equal(isReviewIndicator(derived), false, 'parser-derived host never reaches review');
  const all = [explicitUrl, referenceUrl, cve, derived, bodyIp];
  assert.deepEqual(all.filter((c) => matchReviewFilter(c, 'indicators')).map((c) => c.normalized_value), [
    'http://217.60.36.94/unicorn/mort.php',
    '107.172.249.140'
  ]);
  assert.deepEqual(all.filter((c) => matchReviewFilter(c, 'context_only')).map((c) => c.normalized_value), [
    'https://www.fortinet.com/fr/blog/threat-research/x',
    'CVE-2026-0001'
  ]);
  assert.equal(all.filter((c) => matchReviewFilter(c, 'all')).length, 5);
  assert.equal(all.filter((c) => matchReviewFilter(c, 'needs_review')).some((c) => c === derived), false);
});

test('provenance summary explains why a candidate exists', () => {
  const p = describeCandidateProvenance(explicitUrl);
  assert.equal(p.assertion, 'Explicit C2');
  assert.equal(p.section, '2.载荷投递分析');
  assert.equal(p.pages, 'p7, p17');
  assert.equal(p.occurrences, 2);
  assert.equal(p.direct, true);
  assert.equal(p.decision, 'Report evidence');
  assert.equal(p.urlHost, '217.60.36.94');

  const ep = describeCandidateProvenance(bodyIp);
  assert.equal(ep.ports, '443');
  assert.equal(ep.urlHost, null);

  const d = describeCandidateProvenance(derived);
  assert.equal(d.direct, false);
  assert.equal(describeCandidateProvenance(referenceUrl).assertion, 'Reference');
  assert.equal(describeCandidateProvenance({ candidate_type: 'ip' }).assertion, 'Ambiguous');
});

test('deadline failure shows checkpoint progress and resume hint', () => {
  const lines = describeAnalysisFailureDetail({
    failure_code: 'total_analysis_deadline_exceeded',
    failure_details: {
      progress: { analysis_chunks_total: 10, analysis_chunks_completed: 8, analysis_chunks_remaining: 2, ai_calls: 9, elapsed_ms: 1_800_400, total_analysis_timeout_ms: 1_800_000, resumable: true }
    }
  });
  assert.deepEqual(lines, [
    'Completed semantic chunks: 8 / 10',
    'Remaining chunks: 2',
    'AI calls made: 9',
    'Elapsed 30 min of 30 min ceiling',
    'Retry Analysis will resume from completed checkpoints.'
  ]);
  assert.deepEqual(describeAnalysisFailureDetail({ failure_code: 'total_analysis_deadline_exceeded', failure_details: {} }), [
    'Retry Analysis reuses the stored document and resumes compatible checkpoints.'
  ]);
  assert.deepEqual(describeAnalysisFailureDetail({ failure_code: 'ai_validation', failure_details: {} }), []);
  assert.deepEqual(describeAnalysisFailureDetail(null), []);
});
