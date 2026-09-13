import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeCandidateValue } from './candidateValue.js';
import {
  CIDR_UNSUPPORTED_DETAIL,
  classifyCreateEligibility,
  previewCreateIocPromotion,
  summarizePromotionResults,
  canExecutePromotion,
  isNoneEligibleBlock,
  isPendingActionableCandidate,
  PROMOTION_OUTCOMES
} from './promotion.js';

function cand(overrides) {
  return {
    id: 1,
    candidate_type: 'ip',
    original_value: '38.92.47.91',
    normalized_value: '38.92.47.91',
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    is_ioc: true,
    ...overrides
  };
}

test('approved new supported IP is eligible for create', () => {
  const r = classifyCreateEligibility(cand());
  assert.equal(r.eligible, true);
  assert.equal(r.outcome, PROMOTION_OUTCOMES.WILL_CREATE);
});

test('pending is not eligible and does not create', () => {
  const r = classifyCreateEligibility(cand({ review_status: 'pending' }));
  assert.equal(r.eligible, false);
  assert.equal(r.outcome, PROMOTION_OUTCOMES.NOT_APPROVED);
});

test('approved existing match is already_existing, not a new create', () => {
  const r = classifyCreateEligibility(cand({
    matched_ioc_id: 99,
    match_state: 'existing',
    matched_ioc_observable_type: 'ip'
  }));
  assert.equal(r.eligible, false);
  assert.equal(r.outcome, PROMOTION_OUTCOMES.ALREADY_EXISTING);
  assert.equal(r.ioc_id, 99);
});

test('ignored and context-only are not eligible', () => {
  assert.equal(classifyCreateEligibility(cand({ review_status: 'ignored' })).outcome, PROMOTION_OUTCOMES.NOT_APPLICABLE);
  assert.equal(classifyCreateEligibility(cand({ review_status: 'context_only', assessment: 'context_only' })).outcome, PROMOTION_OUTCOMES.NOT_APPLICABLE);
  assert.equal(classifyCreateEligibility(cand({ is_ioc: false })).outcome, PROMOTION_OUTCOMES.NOT_APPLICABLE);
});

test('CIDR is unsupported, prefix preserved, never eligible', () => {
  const cidr = cand({
    candidate_type: 'cidr',
    original_value: '36.35.56.0/24',
    normalized_value: '36.35.56.0/24',
    review_status: 'approved'
  });
  const r = classifyCreateEligibility(cidr);
  assert.equal(r.eligible, false);
  assert.equal(r.outcome, PROMOTION_OUTCOMES.UNSUPPORTED);
  assert.equal(r.detail, CIDR_UNSUPPORTED_DETAIL);
  assert.equal(cidr.normalized_value, '36.35.56.0/24');
});

test('mixed selection preview reports exact eligibility counts', () => {
  const preview = previewCreateIocPromotion([
    cand({ id: 1, review_status: 'approved' }),
    cand({ id: 2, review_status: 'pending', original_value: '1.1.1.1' }),
    cand({ id: 3, matched_ioc_id: 7, match_state: 'existing' }),
    cand({
      id: 4,
      candidate_type: 'cidr',
      original_value: '36.49.207.0/24',
      normalized_value: '36.49.207.0/24',
      review_status: 'approved'
    }),
    cand({ id: 5, review_status: 'ignored' })
  ]);
  assert.equal(preview.summary.selected, 5);
  assert.equal(preview.summary.eligible, 1);
  assert.equal(preview.summary.not_approved, 1);
  assert.equal(preview.summary.already_existing, 1);
  assert.equal(preview.summary.unsupported, 1);
  assert.equal(preview.summary.not_applicable, 1);
  assert.equal(canExecutePromotion(preview.summary), true);
  assert.equal(isNoneEligibleBlock(preview.summary), false);
});

test('all pending selection is a blocking none-eligible set', () => {
  const preview = previewCreateIocPromotion([
    cand({ id: 1, review_status: 'pending' }),
    cand({ id: 2, review_status: 'pending', original_value: '2.2.2.2' })
  ]);
  assert.equal(preview.summary.eligible, 0);
  assert.equal(preview.summary.not_approved, 2);
  assert.equal(isNoneEligibleBlock(preview.summary), true);
  assert.equal(canExecutePromotion(preview.summary), false);
});

test('summarize created vs already_existing after execute', () => {
  const summary = summarizePromotionResults([
    { outcome: 'created' },
    { outcome: 'created' },
    { outcome: 'already_existing' },
    { outcome: 'unsupported' },
    { outcome: 'not_approved' }
  ]);
  assert.equal(summary.created, 2);
  assert.equal(summary.already_existing, 1);
  assert.equal(summary.unsupported, 1);
  assert.equal(summary.not_approved, 1);
  assert.equal(summary.eligible, 0);
});

test('CIDR canonicalization never explodes /24 or drops the prefix', () => {
  const a = normalizeCandidateValue('36.35.56.0/24', 'cidr');
  assert.equal(a.ok, true);
  assert.equal(a.candidateType, 'cidr');
  assert.equal(a.normalizedValue, '36.35.56.0/24');
  assert.equal(a.normalizedValue.includes('/24'), true);
  assert.notEqual(a.normalizedValue, '36.35.56.0');

  const hostBits = normalizeCandidateValue('36.35.56.1/24', 'cidr');
  assert.equal(hostBits.normalizedValue, '36.35.56.0/24', 'network address normalized, prefix kept');

  const v6 = normalizeCandidateValue('2001:db8::/32', 'cidr');
  assert.equal(v6.ok, true);
  assert.equal(v6.candidateType, 'cidr');
  assert.match(v6.normalizedValue, /\/32$/);
  assert.equal(v6.normalizedValue.includes(':'), true);
});

test('pending actionable candidates block finalize; context-only does not', () => {
  assert.equal(isPendingActionableCandidate(cand({ review_status: 'pending' })), true);
  assert.equal(isPendingActionableCandidate(cand({ review_status: 'approved' })), false);
  assert.equal(isPendingActionableCandidate(cand({
    review_status: 'pending',
    assessment: 'context_only',
    match_state: 'context_only'
  })), false);
  assert.equal(isPendingActionableCandidate(cand({
    candidate_type: 'cve',
    is_ioc: false,
    review_status: 'pending'
  })), false);
});
