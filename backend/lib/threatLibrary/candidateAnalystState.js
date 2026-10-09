/**
 * Analyst-owned candidate state, shared by Refresh extraction, Retry and
 * Re-run AI.
 *
 * Identity is (candidate_type, normalized_value). State never moves to a
 * different identity. A new identity starts pending. A removed identity is
 * deleted with its row.
 *
 * Ownership on a surviving identity:
 *   extraction / matching  recomputed by the caller before this merge
 *   AI                     recomputed by the caller (a new model result, or a
 *                          replay of the stored one). This module does not
 *                          call a model.
 *   analyst                re-applied here and wins where it conflicts:
 *                          review_status, the Context Only decision, the
 *                          Context Only → IOC promotion, and a Create-IOC
 *                          outcome that must not be demoted back to non-IOC
 *
 * Row id, public id, portable id and promotion_outcome / promotion_detail /
 * promoted_at are kept by reconcileReportCandidates (it updates the surviving
 * row in place and does not write those columns).
 */

import { isContextOnlyCandidate } from './promotion.js';

export const candidateKey = (c) => `${c.candidate_type}\0${c.normalized_value}`;

/**
 * Columns whose change is review-relevant after a deterministic refresh.
 * Occurrence / evidence metadata (evidence, evidence_text, section, block
 * pointers, original spelling, confidence) is deliberately absent: those
 * refreshes must not unfinalize a report.
 */
export const REVIEW_RELEVANT_CANDIDATE_COLUMNS = Object.freeze([
  'assessment',
  'role',
  'review_status',
  'match_state',
  'matched_ioc_id',
  'matched_ioc_observable_type',
  'is_ioc',
  'source_assertion'
]);

const REVIEW_RELEVANT_COLUMN_SET = new Set(REVIEW_RELEVANT_CANDIDATE_COLUMNS);
const CREATED_IOC_OUTCOMES = new Set(['created', 'already_existing']);
/**
 * Analyst decisions that take an indicator out of the IOC set. They are made
 * after (and so override) an earlier Create IOCs outcome: an analyst may mark
 * a created / linked identity Context Only or Ignore it on a finalized report.
 */
const ANALYST_EXCLUSION_REVIEWS = new Set(['context_only', 'ignored', 'rejected']);

function evidenceOf(row) {
  return row?.evidence && typeof row.evidence === 'object' ? row.evidence : {};
}

/**
 * Whether a reconcileReportCandidates() diff changed review-relevant report
 * semantics. Added or removed canonical identities always count. An update
 * counts only when a review-relevant column changed — not because a row was
 * rewritten, the extractor version moved, or occurrence metadata was refreshed.
 * @param {{ added?: object[], removed?: object[], updated?: { columns?: string[] }[] }|null|undefined} diff
 */
export function requiresReviewAfterExtractionRefresh(diff) {
  if (!diff || typeof diff !== 'object') return false;
  if ((diff.added || []).length > 0 || (diff.removed || []).length > 0) return true;
  return (diff.updated || []).some((row) =>
    (row.columns || []).some((col) => REVIEW_RELEVANT_COLUMN_SET.has(col))
  );
}

/**
 * Re-apply analyst decisions recorded on the surviving row of the same
 * canonical identity (mutates and returns `candidate`). New identities start
 * pending. Does not copy the prior row.
 * @param {object} candidate resolved candidate (already extracted / matched)
 * @param {object|null} prior persisted row with the same identity
 */
export function applyAnalystState(candidate, prior) {
  if (!prior) {
    candidate.review_status = 'pending';
    return candidate;
  }
  const review = prior.review_status || 'pending';
  candidate.review_status = review;
  if (review === 'context_only') {
    // reviewService `context_only` action.
    candidate.assessment = 'context_only';
    candidate.match_state = 'context_only';
  }
  const promotedFrom = evidenceOf(prior).promoted_from;
  if (promotedFrom && typeof promotedFrom === 'object') {
    candidate.promoted_from = promotedFrom;
    if (review === 'approved' && (isContextOnlyCandidate(candidate) || candidate.is_ioc === false)) {
      // reviewService promote_to_ioc override, re-applied after extraction / AI.
      candidate.assessment = 'suspicious';
      if (['reference', 'legitimate_service', 'hosting_platform'].includes(String(candidate.role))) {
        candidate.role = 'unknown';
      }
      candidate.is_ioc = true;
      candidate.match_state = candidate.matched_ioc_id != null ? 'existing' : 'new';
      candidate.decision_source = 'analyst';
      candidate.policy_decision = 'analyst_promoted_from_context_only';
    }
  }
  // Create-IOC / link outcome. The catalog match is the linkage; this stops a
  // new extraction or AI pass from demoting that identity back to non-IOC and
  // making the stored outcome look reset. It does not freeze an AI assessment
  // that is still an IOC, and it never overrides a LATER analyst exclusion
  // (Context Only / Ignore / Reject of the created identity): that decision
  // stands, exactly as the review action left it.
  if (CREATED_IOC_OUTCOMES.has(String(prior.promotion_outcome || '')) && !ANALYST_EXCLUSION_REVIEWS.has(review)) {
    if (isContextOnlyCandidate(candidate) || candidate.is_ioc === false) {
      candidate.is_ioc = true;
      if (!candidate.assessment || candidate.assessment === 'context_only' || candidate.assessment === 'invalid') {
        candidate.assessment = 'suspicious';
      }
      if (['reference', 'legitimate_service', 'hosting_platform'].includes(String(candidate.role))) {
        candidate.role = 'unknown';
      }
      candidate.match_state = candidate.matched_ioc_id != null ? 'existing' : 'new';
      if (candidate.review_status === 'pending') candidate.review_status = 'approved';
    }
  }
  return candidate;
}

/**
 * Analyst merge for a whole candidate set. `carryStoredMatch` is for the
 * pre-match checkpoint only: the fresh extraction has not consulted the
 * catalog yet, so the stored IOC link is kept until matching recomputes it.
 * After matching, leave it false — a catalog miss must not resurrect a stale id.
 * @param {object[]} candidates
 * @param {object[]} previousRows
 * @param {{ carryStoredMatch?: boolean }} [opts]
 */
export function preserveAnalystCandidates(candidates, previousRows, { carryStoredMatch = false } = {}) {
  const priorByKey = new Map((previousRows || []).map((row) => [candidateKey(row), row]));
  return (candidates || []).map((candidate) => {
    const prior = priorByKey.get(candidateKey(candidate)) || null;
    const next = { ...candidate };
    if (carryStoredMatch && prior && next.matched_ioc_id == null && prior.matched_ioc_id != null) {
      next.matched_ioc_id = prior.matched_ioc_id;
      next.matched_ioc_observable_type = prior.matched_ioc_observable_type || null;
    }
    return applyAnalystState(next, prior);
  });
}
