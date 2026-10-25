import test from 'node:test';
import assert from 'node:assert/strict';
import { describeMembershipDecision } from './membershipExplanationUi.js';
import { isNeedsAttentionCandidate, matchReviewFilter } from './candidateReview.js';

test('explicit publisher IOC is explained as indicator', () => {
  const c = {
    candidate_type: 'domain',
    normalized_value: 'c2.evilvend.net',
    assessment: 'malicious',
    is_ioc: true,
    review_status: 'pending',
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    policy_decision: 'explicit_report_assertion',
    evidence: {
      source_assertion: 'explicit_ioc',
      document_has_authoritative_scope: true,
      policy_decision: 'explicit_report_assertion',
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true }]
    }
  };
  const d = describeMembershipDecision(c);
  assert.equal(d.outcome, 'indicator');
  assert.equal(d.reasonCode, 'explicit_publisher_ioc');
  assert.equal(d.mode, 'A');
  assert.equal(isNeedsAttentionCandidate(c), false);
});

test('MODE A narrative suppression is Needs Attention and explained', () => {
  const c = {
    candidate_type: 'domain',
    normalized_value: 'narrative.evilvend.net',
    assessment: 'unknown',
    is_ioc: true,
    review_status: 'pending',
    source_assertion: 'body_mention',
    document_has_authoritative_scope: true,
    policy_decision: 'context_only_narrative_with_authoritative_scope',
    match_state: 'context_only',
    evidence: {
      source_assertion: 'body_mention',
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_narrative_with_authoritative_scope',
      occurrences: [{ zone: 'report_body', row_shape: true }]
    }
  };
  const d = describeMembershipDecision(c);
  assert.equal(d.outcome, 'context_only');
  assert.equal(d.reasonCode, 'insufficient_publisher_assertion');
  assert.equal(isNeedsAttentionCandidate(c), true);
  assert.equal(matchReviewFilter(c, 'needs_attention'), true);
  assert.equal(matchReviewFilter(c, 'total_unique'), false);
});

test('Indicators never appear in Needs Attention', () => {
  const c = {
    candidate_type: 'ip',
    normalized_value: '203.0.113.10',
    assessment: 'malicious',
    is_ioc: true,
    review_status: 'pending',
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    ai_needed: true,
    evidence: {
      source_assertion: 'explicit_ioc',
      document_has_authoritative_scope: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true }]
    }
  };
  assert.equal(isNeedsAttentionCandidate(c), false);
});
