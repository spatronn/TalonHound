/**
 * Linked-source candidates remain reviewable on a finalized original report.
 * Extraction must not auto-approve; MODE A narrative-only stays non-actionable.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyCreateEligibility,
  isActionableReviewIndicator,
  isPendingActionableCandidate,
  isReviewActionableIndicator,
  isUnionReportIndicatorMember,
  previewCreateIocPromotion
} from '../promotion.js';
import {
  isLinkedOnlyIndicatorMember,
  isReportIndicatorMember,
  isPendingReviewActionableIndicator
} from '../indicatorMembership.js';
import { applyCandidateReviewActions } from '../reviewService.js';
import {
  eligibleCandidateIds,
  matchSelectionTab,
  parseReviewSelection,
  withInferredPublisherIocScope
} from '../candidateSelection.js';
import { isReviewMutationAllowed } from '../reportPhase.js';

const FINALIZED = {
  id: 42,
  public_id: 'fin-1',
  analysis_status: 'ready',
  import_status: 'ready',
  source_url: null
};

function originalPublisher(overrides = {}) {
  return {
    id: 1,
    report_id: 42,
    candidate_type: 'ip',
    original_value: '203.0.113.10',
    normalized_value: '203.0.113.10',
    assessment: 'malicious',
    role: 'malicious_infrastructure',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    is_ioc: true,
    confidence: 0.95,
    has_original_document_occurrence: true,
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }]
    },
    updated_at: '2026-10-10T00:00:00.000Z',
    ...overrides
  };
}

function linkedPending(overrides = {}) {
  return {
    id: 7001,
    report_id: 42,
    candidate_type: 'md5',
    original_value: 'c5ed005bed369b4cb1aa07280fc13f7f',
    normalized_value: 'c5ed005bed369b4cb1aa07280fc13f7f',
    assessment: 'malicious',
    role: 'malware_sample',
    review_status: 'pending',
    match_state: 'new',
    matched_ioc_id: null,
    is_ioc: true,
    confidence: 0.9,
    has_original_document_occurrence: false,
    source_assertion: 'linked_source_ioc',
    document_has_authoritative_scope: false,
    sources: [{
      id: '9824a627-5183-4645-9ed8-1d30746ad3cf',
      source_type: 'github_dir',
      canonical_url: 'https://github.com/gendigitalinc/ioc/tree/master/WardenStealer',
      lifecycle_status: 'extracted',
      repo_revision: '08c0b6e89c41be2dfaee90788610f5dab7ddb22c',
      file_path: 'md5.txt'
    }],
    evidence: {
      document_has_authoritative_scope: false,
      source_assertion: 'linked_source_ioc',
      is_direct_source_observable: true,
      occurrence_count: 0,
      occurrences: [],
      zones: ['report_body']
    },
    updated_at: '2026-10-10T00:00:00.000Z',
    ...overrides
  };
}

function modeANarrative(overrides = {}) {
  return originalPublisher({
    id: 99,
    review_status: 'pending',
    source_assertion: 'body_mention',
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'body_mention',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
    },
    ...overrides
  });
}

function statefulPool(report, candidates) {
  const rows = candidates.map((c) => ({ ...c, evidence: { ...(c.evidence || {}) } }));
  const writes = [];
  const byIds = (ids) => rows.filter((r) => ids.map(Number).includes(Number(r.id)));
  return {
    rows,
    writes,
    async query(sql, params) {
      if (/FROM threat_reports WHERE id = \$1/.test(sql) && /^\s*SELECT/i.test(sql)) {
        return { rows: report ? [report] : [] };
      }
      if (/^\s*SELECT/i.test(sql) && /FROM threat_report_candidates/.test(sql)) {
        const ids = Array.isArray(params?.[1]) ? params[1] : null;
        return { rows: (ids ? byIds(ids) : rows).map((r) => ({ ...r })) };
      }
      if (/FROM ioc_sources WHERE name/.test(sql)) return { rows: [{ id: 4 }] };
      writes.push({ sql, params });
      if (/^\s*UPDATE threat_report_candidates/.test(sql) && /SET review_status = 'approved'/.test(sql)) {
        const targets = byIds(params[1]).filter((r) => isReviewActionableIndicator(r));
        targets.forEach((r) => { r.review_status = 'approved'; });
        return { rows: [], rowCount: targets.length };
      }
      if (/^\s*UPDATE threat_report_candidates/.test(sql) && /review_status = 'ignored'/.test(sql)) {
        const targets = byIds(params[1]);
        targets.forEach((r) => { r.review_status = 'ignored'; });
        return { rows: [], rowCount: targets.length };
      }
      if (/^\s*UPDATE threat_reports/.test(sql)) return { rows: [report], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }
  };
}

test('finalized report still allows review mutations', () => {
  assert.equal(isReviewMutationAllowed(FINALIZED), true);
  assert.equal(isReviewMutationAllowed({ analysis_status: 'review_required' }), true);
  assert.equal(isReviewMutationAllowed({ analysis_status: 'analyzing' }), false);
});

test('linked-only pending is union-actionable but not original MODE A member', () => {
  const linked = linkedPending();
  const original = originalPublisher();
  const narrative = modeANarrative();

  assert.equal(isReportIndicatorMember(linked), false);
  assert.equal(isActionableReviewIndicator(linked), false, 'historical alias stays original-only');
  assert.equal(isLinkedOnlyIndicatorMember(linked), true);
  assert.equal(isUnionReportIndicatorMember(linked), true);
  assert.equal(isReviewActionableIndicator(linked), true);
  assert.equal(isPendingReviewActionableIndicator(linked), true);
  assert.equal(isPendingActionableCandidate(linked), true);

  assert.equal(isReportIndicatorMember(original), true);
  assert.equal(isReviewActionableIndicator(original), true);
  assert.equal(isPendingActionableCandidate(original), false, 'already approved');

  assert.equal(isReportIndicatorMember(narrative), false);
  assert.equal(isReviewActionableIndicator(narrative), false);
  assert.equal(isPendingActionableCandidate(narrative), false);
});

test('MODE A inference must not stamp linked-only rows', () => {
  const list = withInferredPublisherIocScope([originalPublisher(), linkedPending()]);
  const linked = list.find((c) => c.id === 7001);
  assert.equal(linked.document_has_authoritative_scope, false);
  assert.equal(linked.evidence.document_has_authoritative_scope, false);
  assert.equal(isReviewActionableIndicator(linked), true);
});

test('selection tabs and approve eligibility include linked-only', () => {
  const linked = linkedPending();
  const original = originalPublisher({ review_status: 'pending' });
  const narrative = modeANarrative();

  assert.equal(matchSelectionTab(linked, 'indicators'), false);
  assert.equal(matchSelectionTab(linked, 'linked_only'), true);
  assert.equal(matchSelectionTab(linked, 'total_unique'), true);
  assert.equal(matchSelectionTab(linked, 'needs_review'), true);
  assert.equal(matchSelectionTab(linked, 'source:9824a627-5183-4645-9ed8-1d30746ad3cf'), true);
  assert.equal(matchSelectionTab(linked, 'source:other'), false);
  assert.equal(matchSelectionTab(narrative, 'needs_review'), false);

  assert.deepEqual(
    eligibleCandidateIds('approve', [linked, original, narrative]),
    [7001, 1]
  );

  const parsed = parseReviewSelection({
    selection: {
      mode: 'all_matching',
      filters: { tab: 'linked_only', type: 'all', result: 'all', search: '' },
      excluded_candidate_ids: []
    }
  });
  assert.equal(parsed.ok, true);
  // Legacy linked_only tab expands to All Indicators + Linked only source.
  assert.equal(parsed.filters.tab, 'total_unique');
  assert.equal(parsed.filters.source, 'linked_only');
  assert.equal(matchSelectionTab(linked, 'linked_only'), true);
});

test('approve linked-only on finalized report; original approved rows untouched', async () => {
  const original = originalPublisher();
  const linked = linkedPending();
  const narrative = modeANarrative();
  const pool = statefulPool(FINALIZED, [original, linked, narrative]);

  const result = await applyCandidateReviewActions(pool, FINALIZED.id, {
    action: 'approve',
    candidateIds: [linked.id, original.id, narrative.id]
  });
  assert.equal(result.ok, true);
  // Linked pending + already-approved original both match the approve UPDATE;
  // MODE A narrative-only is skipped and left pending.
  assert.equal(result.updated, 2);
  assert.equal(result.skipped_context_only, 1);
  assert.equal(pool.rows.find((r) => r.id === 7001).review_status, 'approved');
  assert.equal(pool.rows.find((r) => r.id === 1).review_status, 'approved', 'pre-approved original unchanged');
  assert.equal(pool.rows.find((r) => r.id === 99).review_status, 'pending', 'MODE A narrative not approved');
  assert.equal(FINALIZED.analysis_status, 'ready', 'report stays finalized');
});

test('create eligibility after linked approve; extraction does not auto-approve', () => {
  const pending = linkedPending();
  assert.equal(classifyCreateEligibility(pending).outcome, 'not_approved');
  assert.equal(classifyCreateEligibility(pending).eligible, false);

  const approved = linkedPending({ review_status: 'approved' });
  const created = classifyCreateEligibility(approved);
  assert.equal(created.eligible, true);
  assert.equal(created.outcome, 'will_create');

  const existing = linkedPending({
    review_status: 'approved',
    match_state: 'existing',
    matched_ioc_id: 555
  });
  assert.equal(classifyCreateEligibility(existing).outcome, 'already_existing');

  const preview = previewCreateIocPromotion([approved, existing, pending]);
  assert.equal(preview.summary.eligible, 1);
  assert.equal(preview.summary.already_existing, 1);
  assert.equal(preview.summary.not_approved, 1);
});

test('unasserted / failed linked provenance is not actionable', () => {
  const bare = linkedPending({
    source_assertion: 'body_mention',
    sources: [],
    evidence: {
      document_has_authoritative_scope: false,
      source_assertion: 'body_mention',
      is_direct_source_observable: true,
      occurrences: []
    }
  });
  assert.equal(isLinkedOnlyIndicatorMember(bare), false);
  assert.equal(isReviewActionableIndicator(bare), false);

  // Discovered-only source without linked_source_ioc assertion and without sources[].
  const discovered = linkedPending({
    source_assertion: null,
    sources: undefined,
    evidence: {
      document_has_authoritative_scope: false,
      is_direct_source_observable: true
    }
  });
  assert.equal(isReviewActionableIndicator(discovered), false);
});

test('original publisher Indicators remain creatable as before', () => {
  const approved = originalPublisher({ review_status: 'approved', match_state: 'new' });
  assert.equal(classifyCreateEligibility(approved).eligible, true);
  const pending = originalPublisher({ review_status: 'pending' });
  assert.equal(classifyCreateEligibility(pending).outcome, 'not_approved');
});
