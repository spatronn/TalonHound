/**
 * Overview metrics, filter counts, hidden-empty metadata, entity grouping and
 * source / artifact presentation. Fixtures mirror real production payloads
 * (Infoblox "Illegal Gambling" finalized report, SOCRadar VectraRAT in review).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { REVIEW_FILTERS, filterReviewCandidates } from './candidateReview.js';
import {
  buildOverviewMetrics,
  buildReportDetails,
  buildReviewFilterCounts,
  buildSourceDetails,
  describeArtifact,
  describeOverviewPhaseNote,
  entityHasDetail,
  formatByteSize,
  groupEntitiesByType,
  isOpenableSourceUrl
} from './reportOverview.js';

let nextId = 1;
function row(overrides) {
  return {
    id: nextId++,
    candidate_type: 'domain',
    normalized_value: `host${nextId}.example`,
    assessment: 'malicious',
    role: 'command_and_control',
    review_status: 'approved',
    match_state: 'existing',
    matched_ioc_id: 100 + nextId,
    promotion_outcome: 'already_existing',
    is_ioc: true,
    source_assertion: 'explicit_ioc',
    evidence: { source_assertion: 'explicit_ioc', decision_source: 'deterministic', is_direct_source_observable: true, is_parser_derived_metadata: false, occurrence_count: 2, occurrences: [] },
    ...overrides
  };
}

// 25 review indicators (22 already existing + 3 created), 5 context-only references.
const finalizedCandidates = [
  ...Array.from({ length: 22 }, () => row({})),
  ...Array.from({ length: 3 }, () => row({ promotion_outcome: 'created' })),
  ...Array.from({ length: 5 }, () => row({
    assessment: 'context_only', role: 'reference', review_status: 'pending', match_state: 'context_only', matched_ioc_id: null, promotion_outcome: null, source_assertion: 'body_mention'
  }))
];
const finalizedReport = {
  id: 'r1',
  title: 'Illegal Gambling Sites Reveal Three Types of Cybercrime',
  source_type: 'url',
  source_name: 'www.infoblox.com',
  source_url: 'https://www.infoblox.com/blog/x/',
  source_file_name: null,
  source_sha256: null,
  published_at: null,
  language: 'en-us',
  confidence: null,
  report_type: null,
  analysis_status: 'ready',
  review_phase: 'finalized',
  indicator_count: 30,
  review_candidate_count: 25,
  matched_count: 25,
  entity_count: 8,
  created_at: '2026-09-16T00:30:21+03:00',
  finalized_at: '2026-09-17T23:39:16+03:00'
};

// Review-ready: 20 review indicators all pending (15 new, 5 existing), 31 context-only / non-IOC rows.
const reviewCandidates = [
  ...Array.from({ length: 4 }, () => row({ candidate_type: 'ip', review_status: 'pending', match_state: 'new', matched_ioc_id: null, promotion_outcome: null })),
  ...Array.from({ length: 3 }, () => row({ candidate_type: 'ip', review_status: 'pending', promotion_outcome: null })),
  ...Array.from({ length: 10 }, () => row({ candidate_type: 'sha256', role: 'malware_sample', review_status: 'pending', match_state: 'new', matched_ioc_id: null, promotion_outcome: null })),
  ...Array.from({ length: 2 }, () => row({ candidate_type: 'sha256', role: 'malware_sample', review_status: 'pending', promotion_outcome: null })),
  row({ review_status: 'pending', match_state: 'new', matched_ioc_id: null, promotion_outcome: null }),
  ...Array.from({ length: 24 }, () => row({ candidate_type: 'attack_technique', is_ioc: false, assessment: 'context_only', role: 'reference', review_status: 'pending', match_state: 'context_only', matched_ioc_id: null, promotion_outcome: null })),
  ...Array.from({ length: 3 }, () => row({ assessment: 'context_only', role: 'reference', review_status: 'pending', match_state: 'context_only', matched_ioc_id: null, promotion_outcome: null })),
  row({ candidate_type: 'cve', is_ioc: false, assessment: 'context_only', role: 'reference', review_status: 'pending', match_state: 'context_only', matched_ioc_id: null, promotion_outcome: null }),
  row({ candidate_type: 'technical_artifact', is_ioc: false, assessment: 'context_only', role: 'reference', review_status: 'pending', match_state: 'context_only', matched_ioc_id: null, promotion_outcome: null }),
  row({ candidate_type: 'file_path', is_ioc: false, assessment: 'context_only', role: 'reference', review_status: 'pending', match_state: 'context_only', matched_ioc_id: null, promotion_outcome: null }),
  row({ candidate_type: 'relative_path', is_ioc: false, assessment: 'context_only', role: 'reference', review_status: 'pending', match_state: 'context_only', matched_ioc_id: null, promotion_outcome: null })
];
const reviewReport = {
  id: 'r2',
  title: 'VectraRAT',
  source_type: 'url',
  source_name: 'socradar.io',
  analysis_status: 'review_required',
  review_phase: 'review_ready',
  confidence: '0.950',
  report_type: 'threat_report',
  matched_count: 5,
  entity_count: 10,
  created_at: '2026-09-15T10:00:00+03:00'
};

test('filter counts equal the row count each filter tab would show', () => {
  for (const candidates of [finalizedCandidates, reviewCandidates]) {
    const counts = buildReviewFilterCounts(candidates);
    for (const f of REVIEW_FILTERS) {
      assert.equal(counts[f.id], filterReviewCandidates(candidates, { tab: f.id }).length, `filter ${f.id}`);
    }
  }
});

test('finalized report metrics: 25 candidates, 0 new, 25 existing, 0 needs review, 25/25 reviewed', () => {
  const m = buildOverviewMetrics(finalizedCandidates, finalizedReport);
  assert.equal(m.available, true);
  assert.equal(m.candidates, 25);
  assert.equal(m.new, 0);
  assert.equal(m.existing, 25);
  assert.equal(m.needsReview, 0);
  assert.equal(m.contextOnly, 5);
  assert.equal(m.all, 30);
  assert.equal(m.reviewed, 25);
  assert.equal(m.total, 25);
  assert.equal(m.progressPct, 100);
});

test('review-ready report metrics: 20 candidates, 15 new, 5 existing, 20 need review, 0/20 reviewed', () => {
  const m = buildOverviewMetrics(reviewCandidates, reviewReport);
  assert.equal(m.available, true);
  assert.equal(m.candidates, 20);
  assert.equal(m.new, 15);
  assert.equal(m.existing, 5);
  assert.equal(m.needsReview, 20);
  assert.equal(m.contextOnly, 31);
  assert.equal(m.all, 51);
  assert.equal(m.reviewed, 0);
  assert.equal(m.progressPct, 0);
});

test('partial review progress counts approved rows as reviewed', () => {
  const partial = reviewCandidates.map((c, i) => (i < 4 ? { ...c, review_status: 'approved' } : c));
  const m = buildOverviewMetrics(partial, reviewReport);
  assert.equal(m.total, 20);
  assert.equal(m.needsReview, 16);
  assert.equal(m.reviewed, 4);
  assert.equal(m.progressPct, 20);
});

test('metrics are unavailable while the candidate set is preliminary or failed', () => {
  assert.equal(buildOverviewMetrics(reviewCandidates, { analysis_status: 'analyzing' }).available, false);
  assert.equal(buildOverviewMetrics(reviewCandidates, { analysis_status: 'failed' }).available, false);
  assert.equal(buildOverviewMetrics([], null).available, false);
  assert.match(describeOverviewPhaseNote({ analysis_status: 'analyzing' }), /when analysis completes/);
  assert.match(describeOverviewPhaseNote({ analysis_status: 'failed' }), /failed/i);
  assert.equal(describeOverviewPhaseNote(finalizedReport), null);
});

test('report details hide empty fields and keep only real values', () => {
  const items = buildReportDetails(finalizedReport, {
    documentMeta: { title: 'x', block_count: 163 },
    artifacts: [{}, {}],
    entityCount: 8,
    indicatorCount: { label: 'Indicators', value: 25 },
    formatDateTime: (v) => `fmt(${v})`
  });
  const labels = items.map((i) => i.label);
  assert.deepEqual(labels, ['Source', 'Source type', 'Language', 'Imported', 'Finalized', 'Document', 'Artifacts', 'Entities', 'Indicators', 'Matched', 'Status']);
  assert.ok(!labels.includes('Published'));
  assert.ok(!labels.includes('Confidence'));
  assert.ok(!labels.includes('Report type'));
  assert.ok(!labels.includes('File name'));
  assert.ok(!labels.includes('SHA-256'));
  assert.ok(items.every((i) => i.value !== '—' && i.value !== '' && i.value !== 'null'));
  assert.equal(items.find((i) => i.label === 'Document').value, '163 blocks');
  assert.equal(items.find((i) => i.label === 'Source type').value, 'URL');
  assert.equal(items.find((i) => i.label === 'Status').value, 'Ready');
  assert.equal(items.find((i) => i.label === 'Imported').value, 'fmt(2026-09-16T00:30:21+03:00)');
});

test('report details render confidence and report type as friendly values', () => {
  const items = buildReportDetails(reviewReport, {});
  assert.equal(items.find((i) => i.label === 'Confidence').value, '95%');
  assert.equal(items.find((i) => i.label === 'Report type').value, 'Threat report');
  assert.equal(items.find((i) => i.label === 'Status').value, 'Needs review');
  assert.ok(!items.some((i) => i.label === 'Document'));
  assert.ok(!items.some((i) => i.label === 'Artifacts'));
});

test('report details for a preliminary report never expose matched / indicator counts', () => {
  const items = buildReportDetails({ ...reviewReport, analysis_status: 'analyzing', review_phase: 'preparing', matched_count: 5 }, { indicatorCount: null });
  assert.ok(!items.some((i) => i.label === 'Matched'));
  assert.equal(buildReportDetails(null).length, 0);
});

test('entities group by canonical type in a fixed order with friendly headings', () => {
  const entities = [
    { id: '1', entity_type: 'campaign', name: 'PeckBirdy' },
    { id: '2', entity_type: 'campaign', name: 'PeckBirdy APT campaigns' },
    { id: '3', entity_type: 'malware', name: 'PeckBirdy' },
    { id: '4', entity_type: 'organization', name: 'UNODC' },
    { id: '5', entity_type: 'organization', name: 'Infoblox Threat Intel' },
    { id: '6', entity_type: 'threat_actor', name: 'Sable Squirrel' },
    { id: '7', entity_type: 'threat_actor', name: 'China-aligned APT actors' },
    { id: '8', entity_type: 'threat_actor', name: 'PeckBirdy operators' },
    { id: '9', entity_type: 'sector', name: 'Gambling' }
  ];
  const groups = groupEntitiesByType(entities);
  assert.deepEqual(groups.map((g) => g.type), ['threat_actor', 'malware', 'campaign', 'organization', 'sector']);
  assert.deepEqual(groups.map((g) => g.label), ['Threat actors', 'Malware', 'Campaigns', 'Organizations', 'Sectors']);
  assert.deepEqual(groups[0].items.map((e) => e.name), ['China-aligned APT actors', 'PeckBirdy operators', 'Sable Squirrel']);
  assert.equal(groups.reduce((n, g) => n + g.items.length, 0), entities.length);
  // Canonical type on each row is untouched.
  assert.ok(groups.every((g) => g.items.every((e) => e.entity_type === g.type)));
  assert.deepEqual(groupEntitiesByType([]), []);
});

test('entity detail is only claimed when evidence / description / confidence exists', () => {
  assert.equal(entityHasDetail({ name: 'X', confidence: null, evidence_text: null, description: null }), false);
  assert.equal(entityHasDetail({ name: 'X', confidence: 0.8 }), true);
  assert.equal(entityHasDetail({ name: 'X', evidence_text: 'seen in section 2' }), true);
  assert.equal(entityHasDetail({ name: 'X', description: '   ' }), false);
});

test('only http(s) source URLs are openable', () => {
  assert.equal(isOpenableSourceUrl('https://www.infoblox.com/blog/x/'), true);
  assert.equal(isOpenableSourceUrl('http://example.org'), true);
  assert.equal(isOpenableSourceUrl('javascript:alert(1)'), false);
  assert.equal(isOpenableSourceUrl('file:///etc/passwd'), false);
  assert.equal(isOpenableSourceUrl('js.cache-mcp.com/layer.js'), false);
  assert.equal(isOpenableSourceUrl(''), false);
  assert.equal(isOpenableSourceUrl(null), false);
});

test('source details hide null file name / sha256 and show document + artifact facts', () => {
  const items = buildSourceDetails(finalizedReport, {
    documentMeta: { title: finalizedReport.title, language: 'en-us', block_count: 163 },
    artifacts: [{ artifact_type: 'url_fetch' }, { artifact_type: 'canonical_document' }],
    formatDateTime: (v) => v
  });
  const labels = items.map((i) => i.label);
  assert.deepEqual(labels, ['Source type', 'Language', 'Imported', 'Document', 'Artifacts']);
  assert.equal(items.find((i) => i.label === 'Document').value, '163 blocks');
  assert.equal(items.find((i) => i.label === 'Artifacts').value, '2');

  const pdf = buildSourceDetails({ source_type: 'pdf', source_file_name: 'report.pdf', source_sha256: 'ab'.repeat(32) }, {});
  assert.equal(pdf.find((i) => i.label === 'File name').value, 'report.pdf');
  assert.equal(pdf.find((i) => i.label === 'SHA-256').mono, true);
});

test('artifact description exposes only user-facing facts', () => {
  const d = describeArtifact({
    id: '30',
    public_id: 'd3aa91a9',
    artifact_type: 'url_fetch',
    file_name: 'source.html',
    mime_type: 'text/html; charset=UTF-8',
    size_bytes: '319626',
    sha256: 'ed8cac92',
    fetched_at: '2026-09-16T00:30:22+03:00',
    storage_key: 'threat-library/30/source.html'
  }, { formatDateTime: (v) => `fmt(${v})` });
  assert.equal(d.typeLabel, 'Fetched source');
  assert.equal(d.name, 'source.html');
  assert.deepEqual(d.facts, ['312.1 KB', 'text/html', 'fetched fmt(2026-09-16T00:30:22+03:00)']);
  assert.equal(d.sha256, 'ed8cac92');
  assert.ok(!JSON.stringify(d).includes('storage_key'));
  assert.ok(!JSON.stringify(d).includes('threat-library/30'));

  const canonical = describeArtifact({ artifact_type: 'canonical_document', file_name: null, size_bytes: null, mime_type: 'application/json', created_at: '2026-09-16T00:30:22+03:00' });
  assert.equal(canonical.typeLabel, 'Canonical document');
  assert.equal(canonical.name, null);
  assert.deepEqual(canonical.facts, ['application/json', '2026-09-16T00:30:22+03:00']);
});

test('byte sizes are human readable', () => {
  assert.equal(formatByteSize(0), '0 B');
  assert.equal(formatByteSize(1023), '1023 B');
  assert.equal(formatByteSize(319626), '312.1 KB');
  assert.equal(formatByteSize(5 * 1024 * 1024), '5.0 MB');
  assert.equal(formatByteSize(null), null);
  assert.equal(formatByteSize('abc'), null);
});
