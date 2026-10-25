/**
 * Analyst-facing membership decision summary derived from existing candidate
 * fields. Mirrors backend membershipExplanation.js reason codes without
 * importing backend modules (frontend stays browser-safe).
 *
 * Must agree with isReviewIndicator / Context Only predicates in candidateReview.js.
 */

import {
  isContextOnlyCandidate,
  isLinkedOnlyReviewIndicator,
  isReviewIndicator,
  isUnionReviewIndicator
} from './candidateReview.js';

const EXPLICIT = new Set(['explicit_ioc', 'explicit_c2', 'explicit_operational_infrastructure']);

function evidenceOf(c) {
  return c?.evidence && typeof c.evidence === 'object' ? c.evidence : {};
}

function policyOf(c) {
  const ev = evidenceOf(c);
  return String(c?.policy_decision || ev.policy_decision || '').toLowerCase();
}

function assertionOf(c) {
  const ev = evidenceOf(c);
  return String(c?.source_assertion || ev.source_assertion || '').toLowerCase();
}

/**
 * @param {object} candidate
 * @returns {{
 *   outcome: string,
 *   reasonCode: string,
 *   summary: string,
 *   mode: 'A'|'B'|null,
 *   policyDecision: string|null,
 *   sourceAssertion: string|null
 * }}
 */
export function describeMembershipDecision(candidate) {
  if (!candidate) {
    return {
      outcome: 'excluded',
      reasonCode: 'unknown',
      summary: 'No candidate.',
      mode: null,
      policyDecision: null,
      sourceAssertion: null
    };
  }
  const ev = evidenceOf(candidate);
  const member = isReviewIndicator(candidate);
  const linkedOnly = isLinkedOnlyReviewIndicator(candidate);
  const contextOnly = isContextOnlyCandidate(candidate);
  const modeA = candidate.document_has_authoritative_scope === true || ev.document_has_authoritative_scope === true;
  const policy = policyOf(candidate);
  const assertion = assertionOf(candidate);
  const review = String(candidate.review_status || 'pending').toLowerCase();
  const ai = candidate.ai_classification || ev.ai_classification || null;

  let outcome = 'excluded';
  if (linkedOnly) outcome = 'linked_only_indicator';
  else if (member) outcome = 'indicator';
  else if (contextOnly) outcome = 'context_only';

  let reasonCode = 'unknown';
  let summary = 'Not a report Indicator under the current membership contract.';

  if (linkedOnly) {
    reasonCode = 'linked_source_ioc';
    summary = 'Indicator via an approved linked IOC Source (not asserted in the original document).';
  } else if (review === 'context_only' && !member) {
    reasonCode = 'analyst_context_only';
    summary = 'Not an Indicator: an analyst marked this Context Only.';
  } else if (ev.promoted_from && member) {
    reasonCode = 'analyst_promoted';
    summary = 'Report Indicator because an analyst explicitly promoted it.';
  } else if (member && EXPLICIT.has(assertion)) {
    reasonCode = 'explicit_publisher_ioc';
    summary = 'Report Indicator: publisher asserted this value in an authoritative IOC / C2 / sample / operational section.';
  } else if (member && !modeA) {
    reasonCode = 'mode_b_body_member';
    summary = 'Report Indicator under MODE B (no publisher IOC appendix): remaining membership gates passed.';
  } else if (member) {
    reasonCode = 'authoritative_table_or_row';
    summary = 'Report Indicator under the current membership contract.';
  } else if (
    ai &&
    ai.applied === true &&
    String(ai.assessment || '').toLowerCase() === 'context_only'
  ) {
    reasonCode = 'ai_grounded_demotion';
    summary = 'Not an Indicator: a grounded AI classification set Context Only.';
  } else if (
    !member &&
    modeA &&
    !EXPLICIT.has(assertion) &&
    (policy === 'context_only_narrative_with_authoritative_scope' ||
      policy === 'context_only_contextual_mention_in_indicator_section' ||
      policy === 'pass' ||
      policy === 'ai_needed_authoritative_narrative' ||
      policy === 'ai_needed_prose_sample_hash' ||
      !policy)
  ) {
    reasonCode = 'insufficient_publisher_assertion';
    summary = 'Not an Indicator: MODE A requires a publisher assertion; this occurrence is narrative-only.';
  } else if (policy.includes('provider') || policy.includes('benign') || policy.includes('legitimate')) {
    reasonCode = 'benign_or_provider';
    summary = 'Not an Indicator: publisher describes this as legitimate, dual-use, or a provider/service.';
  } else if (policy.includes('reference') || policy.includes('rfc_example') || policy.includes('email_domain')) {
    reasonCode = 'reference_only';
    summary = 'Not an Indicator: reference / contact / documentation / example context.';
  } else if (policy.startsWith('ioc_excluded')) {
    reasonCode = 'unsupported_or_non_ioc';
    summary = 'Excluded from IOC review: unsupported type, invalid canonical shape, or non-network artifact.';
  } else if (policy.startsWith('context_only') || policy.startsWith('demoted_')) {
    reasonCode = 'context_only_policy';
    summary = `Not an Indicator (${policy}).`;
  } else if (candidate.ai_needed === true || ev.ai_needed === true) {
    reasonCode = 'ai_needed_pending';
    summary = 'Classification still needs model review; not yet a settled Indicator.';
  }

  // Keep outcome consistent with union membership for linked-only display.
  if (linkedOnly && isUnionReviewIndicator(candidate)) {
    outcome = 'linked_only_indicator';
  }

  return {
    outcome,
    reasonCode,
    summary,
    mode: modeA ? 'A' : 'B',
    policyDecision: policy || null,
    sourceAssertion: assertion || null
  };
}
