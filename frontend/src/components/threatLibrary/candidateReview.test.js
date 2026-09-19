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
  matchReviewFilter,
  DEFAULT_PAGE_SIZE,
  PAGE_SIZES,
  filterReviewCandidates,
  paginateRows,
  parseReviewTableUrlState,
  serializeReviewTableUrlState,
  iocResultLabel,
  applyPromotionResults,
  formatCreateIocSummary,
  describeReviewFeedback,
  describeCreateIocFeedback,
  describePromoteBlocker,
  describePromoteFeedback,
  describeReviewToolbar,
  isContextOnlyCandidate,
  selectionForAction
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

test('table-row provenance: description, declared type and row position are surfaced; explicit rows are source-asserted, not a percentage', async () => {
  const { confidenceLabel, isSourceAsserted } = await import('./candidateReview.js');
  const tableHash = {
    candidate_type: 'sha256',
    normalized_value: '005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f',
    assessment: 'malicious',
    confidence: 0.9,
    source_assertion: 'explicit_ioc',
    evidence: {
      source_assertion: 'explicit_ioc',
      decision_source: 'deterministic',
      occurrence_count: 1,
      zones: ['explicit_ioc_section'],
      parsed: {},
      table_rows: [{ table_id: 'p46-b317', page: 46, row_index: 5, declared_type: 'sha256', type_cell: 'SHA256', raw_value: '005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f', description: 'PivotC2 client (encoded) on 46.151.29[.]58:8443', explicit: true, related_values: ['46.151.29.58:8443'] }],
      occurrences: [{ page: 46, zone: 'explicit_ioc_section', section_heading: 'Host Indicators', form: 'table_row', table_row: 5 }]
    }
  };
  const p = describeCandidateProvenance(tableHash);
  assert.equal(p.assertion, 'Explicit IOC');
  assert.equal(p.description, 'PivotC2 client (encoded) on 46.151.29[.]58:8443');
  assert.equal(p.declaredType, 'SHA256');
  assert.equal(p.tableRow, 'table p46-b317 row 6');
  assert.equal(p.section, 'Host Indicators');
  assert.equal(p.sourceAsserted, true);
  assert.equal(confidenceLabel(tableHash), 'Source asserted');
  assert.equal(isSourceAsserted(explicitUrl), true);
  // AI-classified body mention keeps its percentage; missing confidence shows a dash
  assert.equal(confidenceLabel({ confidence: 0.85, source_assertion: 'body_mention', evidence: { decision_source: 'ai' } }), '85%');
  assert.equal(confidenceLabel({ confidence: null, source_assertion: 'body_mention', evidence: {} }), '—');
  // A reviewer / AI decision on an explicit row still shows the number it produced
  assert.equal(confidenceLabel({ confidence: 0.95, source_assertion: 'explicit_ioc', evidence: { decision_source: 'ai' } }), '95%');
});

test('CIDR appendix rows stay in the review set; provider-service domains do not', () => {
  const cidr = {
    candidate_type: 'cidr',
    normalized_value: '36.35.56.0/24',
    assessment: 'malicious',
    match_state: 'new',
    review_status: 'pending',
    is_ioc: true,
    source_assertion: 'explicit_operational_infrastructure',
    evidence: {
      source_assertion: 'explicit_operational_infrastructure',
      decision_source: 'deterministic',
      occurrence_count: 1,
      zones: ['operational_infrastructure']
    }
  };
  const provider = {
    candidate_type: 'domain',
    normalized_value: 'residentialvps.example',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    is_ioc: true,
    source_assertion: 'provider_service',
    evidence: { source_assertion: 'provider_service', decision_source: 'deterministic' }
  };
  assert.equal(isReviewIndicator(cidr), true);
  assert.equal(isReviewIndicator(provider), false);
  assert.equal(describeCandidateProvenance(cidr).assertion, 'Operational infrastructure');
  assert.equal(describeCandidateProvenance(provider).assertion, 'Provider/service');
});

test('search, type filter, pagination, and URL state', () => {
  const rows = [
    { id: 1, candidate_type: 'ip', normalized_value: '38.92.47.91', original_value: '38.92.47.91', match_state: 'new', review_status: 'pending', is_ioc: true, assessment: 'malicious' },
    { id: 2, candidate_type: 'domain', normalized_value: 'recordedfuture.com', original_value: 'RecordedFuture.com', match_state: 'new', review_status: 'approved', is_ioc: true, assessment: 'malicious' },
    { id: 3, candidate_type: 'sha256', normalized_value: 'bb167fc8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', original_value: 'BB167FC8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', match_state: 'new', review_status: 'pending', is_ioc: true, assessment: 'malicious' },
    { id: 4, candidate_type: 'cidr', normalized_value: '36.35.56.0/24', original_value: '36.35.56.0/24', match_state: 'new', review_status: 'approved', is_ioc: true, assessment: 'malicious' },
    { id: 5, candidate_type: 'url', normalized_value: 'https://example.com/x', match_state: 'context_only', review_status: 'context_only', assessment: 'context_only', is_ioc: true }
  ];
  assert.equal(DEFAULT_PAGE_SIZE, 50);
  assert.deepEqual(PAGE_SIZES, [25, 50, 100]);
  assert.equal(filterReviewCandidates(rows, { tab: 'indicators', q: '38.92.47.91' }).map((c) => c.id).join(), '1');
  assert.equal(filterReviewCandidates(rows, { tab: 'indicators', q: 'recordedfuture' }).map((c) => c.id).join(), '2');
  assert.equal(filterReviewCandidates(rows, { tab: 'indicators', q: 'bb167fc8' }).map((c) => c.id).join(), '3');
  assert.equal(filterReviewCandidates(rows, { tab: 'indicators', q: '/24' }).map((c) => c.id).join(), '4');
  assert.equal(filterReviewCandidates(rows, { tab: 'indicators', type: 'cidr' }).map((c) => c.id).join(), '4');
  assert.equal(filterReviewCandidates(rows, { tab: 'indicators', type: 'hash' }).map((c) => c.id).join(), '3');
  assert.equal(filterReviewCandidates(rows, { tab: 'indicators', q: 'no-such-value' }).length, 0);

  const paged = paginateRows(Array.from({ length: 120 }, (_, i) => ({ id: i })), 3, 50);
  assert.equal(paged.page, 3);
  assert.equal(paged.total, 120);
  assert.equal(paged.totalPages, 3);
  assert.equal(paged.rows.length, 20);
  assert.equal(paged.rows[0].id, 100);

  const parsed = parseReviewTableUrlState('page=3&pageSize=50&type=ip&q=38.92&tab=needs_review');
  assert.equal(parsed.page, 3);
  assert.equal(parsed.pageSize, 50);
  assert.equal(parsed.type, 'ip');
  assert.equal(parsed.q, '38.92');
  assert.equal(parsed.tab, 'needs_review');
  const serial = serializeReviewTableUrlState(parsed);
  assert.equal(serial.get('page'), '3');
  assert.equal(serial.get('q'), '38.92');
  assert.equal(serial.get('type'), 'ip');
});

test('IOC Result labels stay separate from review and match', () => {
  assert.equal(iocResultLabel({ promotion_outcome: null, review_status: 'pending', match_state: 'new' }), '—');
  assert.equal(iocResultLabel({ promotion_outcome: 'created', review_status: 'approved', match_state: 'existing' }), 'Created');
  assert.equal(iocResultLabel({ promotion_outcome: 'already_existing' }), 'Already exists');
  assert.equal(iocResultLabel({ promotion_outcome: 'unsupported', promotion_detail: 'CIDR' }), 'Not supported');
  const merged = applyPromotionResults(
    [{ id: 9, match_state: 'new', promotion_outcome: null }],
    [{ candidate_id: 9, outcome: 'created', ioc_id: 123 }]
  );
  assert.equal(merged[0].promotion_outcome, 'created');
  assert.equal(merged[0].matched_ioc_id, 123);
  assert.equal(merged[0].match_state, 'existing');
  const text = formatCreateIocSummary({
    selected: 40,
    eligible: 12,
    already_existing: 20,
    not_approved: 6,
    unsupported: 2
  });
  assert.match(text, /Selected: 40/);
  assert.match(text, /Approved \+ new \+ supported: 12/);
  assert.match(text, /Only the 12 eligible approved indicators will be created/);
});

test('non-IOC artifacts are excluded from the review set and explain their resolution', () => {
  const mutex = {
    id: 90,
    candidate_type: 'technical_artifact',
    normalized_value: 'LocalFoo.Client.SingleInstance',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    is_ioc: false,
    source_assertion: 'non_ioc',
    evidence: {
      resolved_type: 'technical_artifact',
      artifact_kind: 'mutex',
      typing_reason: 'mutex_label',
      type_resolution: { syntax_guess: 'domain', resolved_type: 'technical_artifact', reason: 'mutex_label', promotion: 'excluded' },
      table_rows: [{ table_id: 'b142', row_index: 0, type_cell: 'Mutex' }],
      occurrences: [{ zone: 'report_body', section_heading: 'Host and Network Artifacts' }]
    }
  };
  const path = {
    id: 91,
    candidate_type: 'relative_path',
    normalized_value: '/clickfix/abc/file',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    is_ioc: false,
    evidence: {
      resolved_type: 'relative_path',
      type_resolution: { syntax_guess: 'url', resolved_type: 'relative_path', reason: 'relative_path_without_scheme_or_host', promotion: 'excluded', normalized_path: '/clickfix/abc/file', port: 8081 }
    }
  };
  const ioc = { id: 92, candidate_type: 'domain', normalized_value: 'c2.evil-example.com', assessment: 'malicious', match_state: 'new', review_status: 'pending', is_ioc: true, evidence: { resolved_type: 'domain' } };
  assert.equal(isReviewIndicator(mutex), false);
  assert.equal(isReviewIndicator(path), false);
  assert.equal(isReviewIndicator(ioc), true);
  assert.deepEqual(filterReviewCandidates([mutex, path, ioc], { tab: 'indicators' }).map((c) => c.id), [92]);
  assert.deepEqual(filterReviewCandidates([mutex, path, ioc], { tab: 'context_only' }).map((c) => c.id), [90, 91]);
  const m = describeCandidateProvenance(mutex);
  assert.equal(m.assertion, 'Not an IOC');
  assert.equal(m.resolution.label, 'Not a network IOC · Mutex / single-instance name · mutex label');
  assert.equal(m.resolution.syntaxGuess, 'domain');
  const p = describeCandidateProvenance(path);
  assert.equal(p.resolution.label, 'Relative path (no scheme / host) · relative path without scheme or host');
  assert.equal(p.resolution.detail, 'port 8081');
  assert.equal(describeCandidateProvenance(ioc).resolution, null);
});

test('review feedback is action-specific and count-aware', () => {
  assert.equal(describeReviewFeedback('approve', { count: 1 }), 'Indicator approved.');
  assert.equal(describeReviewFeedback('approve', { count: 4 }), '4 indicators approved.');
  assert.equal(describeReviewFeedback('context_only', { count: 1 }), 'Indicator marked as Context Only.');
  assert.equal(describeReviewFeedback('context_only', { count: 3 }), '3 indicators marked as Context Only.');
  assert.equal(describeReviewFeedback('ignore', { count: 1 }), 'Indicator ignored.');
  assert.equal(describeReviewFeedback('ignore', { count: 2 }), '2 indicators ignored.');
  assert.equal(describeReviewFeedback('approve_high_confidence_malicious', { count: 1 }), '1 high-confidence malicious indicator approved.');
  assert.equal(describeReviewFeedback('approve_high_confidence_malicious', { count: 7 }), '7 high-confidence malicious indicators approved.');
  assert.equal(describeReviewFeedback('approve_high_confidence_malicious', { count: null }), 'High-confidence malicious indicators approved.');
  assert.equal(describeReviewFeedback('approve', { count: 0 }), '0 indicators approved.');
});

test('review feedback never claims success when the backend reported errors', () => {
  assert.equal(describeReviewFeedback('approve', { count: 4, errors: 1 }), 'Completed with 1 error.');
  assert.equal(describeReviewFeedback('ignore', { count: 2, errors: 3 }), 'Completed with 3 errors.');
  assert.equal(describeReviewFeedback('unknown_action', { count: 1 }), 'Review action applied.');
});

test('create IOC feedback names what happened', () => {
  assert.equal(describeCreateIocFeedback({ created: 1, existing: 0 }), 'IOC created.');
  assert.equal(describeCreateIocFeedback({ created: 3, existing: 2 }), '3 IOCs created. 2 already existed.');
  assert.equal(describeCreateIocFeedback({ created: 0, existing: 1 }), '0 IOCs created. 1 already existed.');
  assert.equal(describeCreateIocFeedback({ created: 2, existing: 0, errors: 1 }), '2 IOCs created. 1 error.');
  assert.equal(describeCreateIocFeedback({}), '0 IOCs created.');
});

// --- Context Only != IOC candidate -----------------------------------------

const ctxAmazon = { id: 101, candidate_type: 'domain', normalized_value: 'amazon.com', assessment: 'context_only', match_state: 'context_only', review_status: 'pending', role: 'legitimate_service', is_ioc: true };
const ctxTrustpilot = { id: 102, candidate_type: 'domain', normalized_value: 'trustpilot.com', assessment: 'context_only', match_state: 'context_only', review_status: 'pending', role: 'reference', is_ioc: true };
const ctxTechnique = { id: 103, candidate_type: 'attack_technique', normalized_value: 'T1059', assessment: 'context_only', match_state: 'context_only', review_status: 'pending', is_ioc: false };
const ctxCidr = { id: 104, candidate_type: 'cidr', normalized_value: '10.0.0.0/8', assessment: 'context_only', match_state: 'context_only', review_status: 'pending', is_ioc: true };
const iocA = { id: 201, candidate_type: 'domain', normalized_value: 'evil.example', assessment: 'malicious', match_state: 'new', review_status: 'pending', is_ioc: true };
const iocB = { id: 202, candidate_type: 'ip', normalized_value: '1.2.3.4', assessment: 'malicious', match_state: 'new', review_status: 'approved', is_ioc: true };
const ids = (t) => t.actions.map((a) => a.id);
const enabled = (t) => t.actions.filter((a) => a.enabled).map((a) => a.id);

test('isContextOnlyCandidate mirrors the backend rule and matches the Context Only filter', () => {
  for (const c of [ctxAmazon, ctxTrustpilot, ctxTechnique, ctxCidr]) {
    assert.equal(isContextOnlyCandidate(c), true, c.normalized_value);
    assert.equal(matchReviewFilter(c, 'context_only'), true);
  }
  assert.equal(isContextOnlyCandidate({ ...iocA, review_status: 'context_only' }), true);
  assert.equal(isContextOnlyCandidate({ ...iocA, match_state: 'context_only' }), true);
  assert.equal(isContextOnlyCandidate(iocA), false);
  assert.equal(isContextOnlyCandidate(iocB), false);
});

test('Context Only view: no Create IOCs / Approve high-confidence malicious / Approve / redundant Context only', () => {
  const none = describeReviewToolbar({ filter: 'context_only', selectedRows: [] });
  assert.deepEqual(ids(none), ['promote_to_ioc', 'ignore']);
  assert.deepEqual(enabled(none), []);
  assert.equal(none.actions[0].hint, 'Select one Context Only indicator to promote it.');
  const one = describeReviewToolbar({ filter: 'context_only', selectedRows: [ctxAmazon] });
  assert.deepEqual(enabled(one), ['promote_to_ioc', 'ignore']);
  assert.equal(one.actions[0].label, 'Promote to IOC…');
  const many = describeReviewToolbar({ filter: 'context_only', selectedRows: [ctxAmazon, ctxTrustpilot] });
  assert.deepEqual(enabled(many), ['ignore'], 'promotion is never bulk');
  assert.match(many.actions[0].hint, /single-row/);
  const busy = describeReviewToolbar({ filter: 'context_only', selectedRows: [ctxAmazon], busy: true });
  assert.deepEqual(enabled(busy), []);
  for (const t of [none, one, many]) {
    for (const forbidden of ['create_iocs', 'approve_high_confidence_malicious', 'approve', 'context_only']) {
      assert.equal(ids(t).includes(forbidden), false, `${forbidden} is not rendered in the Context Only view`);
    }
  }
});

test('promotion blockers: unsupported types and non-context rows cannot be promoted', () => {
  assert.equal(describePromoteBlocker([ctxAmazon]), null);
  assert.match(describePromoteBlocker([ctxTechnique]), /cannot be stored as an IOC record/);
  assert.match(describePromoteBlocker([ctxCidr]), /cannot be stored as an IOC record/);
  assert.match(describePromoteBlocker([iocA]), /Only Context Only indicators/);
  assert.match(describePromoteBlocker([]), /Select one/);
});

test('IOC candidate views keep the full action set and enable it from the selection', () => {
  for (const filter of ['indicators', 'new', 'needs_review', 'existing', 'all']) {
    const t = describeReviewToolbar({ filter, selectedRows: [iocA] });
    assert.deepEqual(ids(t), ['approve', 'context_only', 'ignore', 'create_iocs', 'approve_high_confidence_malicious'], filter);
    assert.deepEqual(enabled(t), ['approve', 'context_only', 'ignore', 'create_iocs', 'approve_high_confidence_malicious'], filter);
    assert.equal(t.actions.find((a) => a.id === 'create_iocs').primary, true);
    assert.equal(ids(t).includes('promote_to_ioc'), false);
  }
  const empty = describeReviewToolbar({ filter: 'indicators', selectedRows: [] });
  assert.deepEqual(enabled(empty), ['approve_high_confidence_malicious'], 'report-wide action needs no selection');
});

test('All view with only Context Only rows selected: unsafe IOC actions stay disabled', () => {
  const t = describeReviewToolbar({ filter: 'all', selectedRows: [ctxAmazon, ctxTrustpilot] });
  assert.deepEqual(enabled(t), ['ignore', 'approve_high_confidence_malicious']);
  assert.equal(t.contextOnlySelected, 2);
  assert.equal(t.iocSelected, 0);
  for (const id of ['approve', 'context_only', 'create_iocs']) {
    const a = t.actions.find((x) => x.id === id);
    assert.equal(a.enabled, false, id);
    assert.equal(a.hint, 'Context Only rows are not IOC candidates.');
  }
});

test('mixed selection: Context Only rows never enter Approve / Context only / Create IOCs payloads', () => {
  const rows = [iocA, ctxAmazon, iocB, ctxTrustpilot];
  const t = describeReviewToolbar({ filter: 'all', selectedRows: rows });
  assert.deepEqual(enabled(t), ['approve', 'context_only', 'ignore', 'create_iocs', 'approve_high_confidence_malicious']);
  assert.equal(t.iocSelected, 2);
  assert.equal(t.contextOnlySelected, 2);
  for (const action of ['approve', 'context_only', 'create_iocs']) {
    assert.deepEqual(selectionForAction(action, rows), { ids: [201, 202], excluded: 2 }, action);
  }
  assert.deepEqual(selectionForAction('ignore', rows), { ids: [201, 101, 202, 102], excluded: 0 });
  assert.deepEqual(selectionForAction('promote_to_ioc', [ctxAmazon]), { ids: [101], excluded: 0 });
  assert.deepEqual(selectionForAction('create_iocs', [ctxAmazon, ctxTrustpilot]), { ids: [], excluded: 2 });
});

test('feedback reports rows that were left out and the promotion outcome', () => {
  assert.equal(describeReviewFeedback('approve', { count: 2, excluded: 1 }), '2 indicators approved. 1 Context Only row was not included.');
  assert.equal(describeReviewFeedback('approve', { count: 1, excluded: 2 }), 'Indicator approved. 2 Context Only rows were not included.');
  assert.equal(describeReviewFeedback('approve', { count: 3 }), '3 indicators approved.');
  assert.equal(describePromoteFeedback({ summary: { created: 1 } }, 'amazon.com'), 'amazon.com promoted to IOC. IOC created.');
  assert.equal(describePromoteFeedback({ summary: { already_existing: 1 } }, 'amazon.com'), 'amazon.com promoted to IOC. An IOC record already existed and was linked.');
  assert.match(describePromoteFeedback({ summary: { failed: 1 } }, 'amazon.com'), /creation failed; the row is now an approved IOC candidate/);
});

test('report filter counts are unchanged by the toolbar rules', () => {
  const all = [iocA, iocB, ctxAmazon, ctxTrustpilot, ctxTechnique, ctxCidr];
  const count = (tab) => filterReviewCandidates(all, { tab }).length;
  assert.equal(count('indicators'), 2);
  assert.equal(count('new'), 2);
  assert.equal(count('needs_review'), 1);
  assert.equal(count('existing'), 0);
  assert.equal(count('context_only'), 4);
  assert.equal(count('all'), 6);
});
