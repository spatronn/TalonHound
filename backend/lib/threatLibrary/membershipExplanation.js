/**
 * Explainable IOC membership decisions.
 *
 * Derives a stable, machine-readable explanation from the authoritative
 * candidate fields and `isReportIndicatorMember` / Context Only contracts.
 * This is NOT a second membership engine: outcome always mirrors the
 * canonical predicates. Free-text summaries are for humans; reason_code is
 * the stable diagnostic key.
 */

import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import {
  isContextOnlyCandidate,
  isLinkedOnlyIndicatorMember,
  isLinkedSourceIndicatorMember,
  isPublisherAssertedReportIoc,
  isReportIndicatorMember,
  hasAuthoritativePublisherIocScope,
  EXPLICIT_PUBLISHER_IOC_ASSERTIONS
} from './indicatorMembership.js';

export const MEMBERSHIP_EXPLANATION_VERSION = 'tl-membership-explanation-v1';

/** Stable outcome buckets. */
export const MEMBERSHIP_OUTCOMES = Object.freeze({
  INDICATOR: 'indicator',
  CONTEXT_ONLY: 'context_only',
  EXCLUDED: 'excluded',
  LINKED_ONLY_INDICATOR: 'linked_only_indicator'
});

/**
 * Reason codes derived from existing policy_decision / assertion / AI fields.
 * Prefer mapping known policy_decision strings 1:1; invent new codes only when
 * the existing field is absent or too coarse.
 */
export const MEMBERSHIP_REASON_CODES = Object.freeze({
  EXPLICIT_PUBLISHER_IOC: 'explicit_publisher_ioc',
  AUTHORITATIVE_TABLE_OR_ROW: 'authoritative_table_or_row',
  OPERATIONAL_MALICIOUS_CONTEXT: 'operational_malicious_context',
  LINKED_SOURCE_IOC: 'linked_source_ioc',
  MODE_B_BODY_MEMBER: 'mode_b_body_member',
  ANALYST_PROMOTED: 'analyst_promoted',
  CONTEXT_ONLY_POLICY: 'context_only_policy',
  BENIGN_OR_PROVIDER: 'benign_or_provider',
  REFERENCE_ONLY: 'reference_only',
  INSUFFICIENT_PUBLISHER_ASSERTION: 'insufficient_publisher_assertion',
  UNSUPPORTED_OR_NON_IOC: 'unsupported_or_non_ioc',
  AI_GROUNDED_DEMOTION: 'ai_grounded_demotion',
  AI_NEEDED_PENDING: 'ai_needed_pending',
  ANALYST_CONTEXT_ONLY: 'analyst_context_only',
  UNKNOWN: 'unknown'
});

const EXPLICIT_SET = new Set(EXPLICIT_PUBLISHER_IOC_ASSERTIONS);

function evidenceOf(c) {
  return c?.evidence && typeof c.evidence === 'object' ? c.evidence : {};
}

function identityOf(c) {
  return `${String(c?.candidate_type || '').toLowerCase()}:${c?.normalized_value || ''}`;
}

function policyOf(c) {
  const ev = evidenceOf(c);
  return String(c?.policy_decision || ev.policy_decision || '').toLowerCase();
}

function assertionOf(c) {
  const ev = evidenceOf(c);
  return String(c?.source_assertion || ev.source_assertion || '').toLowerCase();
}

function occurrencesOf(c) {
  const ev = evidenceOf(c);
  if (Array.isArray(c?.occurrences) && c.occurrences.length) return c.occurrences;
  return Array.isArray(ev.occurrences) ? ev.occurrences : [];
}

function mapPolicyToReason(policy) {
  if (!policy) return null;
  if (policy === 'explicit_report_assertion') return MEMBERSHIP_REASON_CODES.EXPLICIT_PUBLISHER_IOC;
  if (policy.startsWith('context_only_benign') || policy.includes('provider_service') || policy.includes('legitimate')) {
    return MEMBERSHIP_REASON_CODES.BENIGN_OR_PROVIDER;
  }
  if (policy.includes('reference') || policy.includes('email_domain') || policy.includes('rfc_example')) {
    return MEMBERSHIP_REASON_CODES.REFERENCE_ONLY;
  }
  if (
    policy === 'context_only_narrative_with_authoritative_scope' ||
    policy === 'context_only_contextual_mention_in_indicator_section'
  ) {
    return MEMBERSHIP_REASON_CODES.INSUFFICIENT_PUBLISHER_ASSERTION;
  }
  if (policy.startsWith('ioc_excluded') || policy.includes('non_network') || policy.includes('invalid_canonical')) {
    return MEMBERSHIP_REASON_CODES.UNSUPPORTED_OR_NON_IOC;
  }
  if (policy.startsWith('context_only') || policy.startsWith('demoted_')) {
    return MEMBERSHIP_REASON_CODES.CONTEXT_ONLY_POLICY;
  }
  if (policy === 'ai_needed_authoritative_narrative' || policy === 'ai_needed_prose_sample_hash' || policy === 'pass') {
    return MEMBERSHIP_REASON_CODES.AI_NEEDED_PENDING;
  }
  if (policy === 'analyst_promoted_from_context_only') return MEMBERSHIP_REASON_CODES.ANALYST_PROMOTED;
  return null;
}

function humanSummary({ outcome, reasonCode, policy, assertion, modeA, member }) {
  if (outcome === MEMBERSHIP_OUTCOMES.LINKED_ONLY_INDICATOR) {
    return 'Indicator via an approved linked IOC Source (not asserted in the original document).';
  }
  if (member && reasonCode === MEMBERSHIP_REASON_CODES.EXPLICIT_PUBLISHER_IOC) {
    return 'Report Indicator: publisher asserted this value in an authoritative IOC / C2 / sample / operational section.';
  }
  if (member && reasonCode === MEMBERSHIP_REASON_CODES.ANALYST_PROMOTED) {
    return 'Report Indicator because an analyst explicitly promoted it.';
  }
  if (member && reasonCode === MEMBERSHIP_REASON_CODES.OPERATIONAL_MALICIOUS_CONTEXT) {
    return 'Report Indicator: publisher text asserts an operational / malicious relation for this value.';
  }
  if (member && !modeA) {
    return 'Report Indicator under MODE B (no publisher IOC appendix): remaining membership gates passed.';
  }
  if (member) {
    return 'Report Indicator under the current membership contract.';
  }
  if (reasonCode === MEMBERSHIP_REASON_CODES.INSUFFICIENT_PUBLISHER_ASSERTION) {
    return 'Not an Indicator: MODE A requires a publisher assertion; this occurrence is narrative-only.';
  }
  if (reasonCode === MEMBERSHIP_REASON_CODES.AI_GROUNDED_DEMOTION) {
    return 'Not an Indicator: a grounded AI classification set Context Only.';
  }
  if (reasonCode === MEMBERSHIP_REASON_CODES.ANALYST_CONTEXT_ONLY) {
    return 'Not an Indicator: an analyst marked this Context Only.';
  }
  if (reasonCode === MEMBERSHIP_REASON_CODES.BENIGN_OR_PROVIDER) {
    return 'Not an Indicator: publisher describes this as legitimate, dual-use, or a provider/service.';
  }
  if (reasonCode === MEMBERSHIP_REASON_CODES.REFERENCE_ONLY) {
    return 'Not an Indicator: reference / contact / documentation / example context.';
  }
  if (reasonCode === MEMBERSHIP_REASON_CODES.UNSUPPORTED_OR_NON_IOC) {
    return 'Excluded from IOC review: unsupported type, invalid canonical shape, or non-network artifact.';
  }
  if (policy) return `Not an Indicator (${policy}).`;
  if (assertion) return `Not an Indicator (assertion=${assertion}).`;
  return 'Not a report Indicator under the current membership contract.';
}

/**
 * Explain one candidate's membership / Context Only / exclusion outcome.
 * @param {object} candidate — extraction or persisted candidate row
 * @returns {object}
 */
export function explainMembershipDecision(candidate) {
  if (!candidate || typeof candidate !== 'object') {
    return {
      version: MEMBERSHIP_EXPLANATION_VERSION,
      outcome: MEMBERSHIP_OUTCOMES.EXCLUDED,
      reason_code: MEMBERSHIP_REASON_CODES.UNKNOWN,
      member: false,
      summary: 'No candidate.'
    };
  }

  const evidence = evidenceOf(candidate);
  const persisted = {
    ...candidate,
    evidence: Object.keys(evidence).length ? evidence : buildCandidateEvidenceRecord(candidate)
  };
  const member = isReportIndicatorMember(persisted);
  const contextOnly = isContextOnlyCandidate(persisted);
  const linkedOnly = isLinkedOnlyIndicatorMember(persisted);
  const linkedMember = isLinkedSourceIndicatorMember(persisted);
  const modeA = hasAuthoritativePublisherIocScope(persisted);
  const publisherAsserted = isPublisherAssertedReportIoc(persisted);
  const policy = policyOf(candidate);
  const assertion = assertionOf(candidate);
  const review = String(candidate.review_status || 'pending').toLowerCase();
  const ai = candidate.ai_classification || evidence.ai_classification || null;
  const decisionSource = String(candidate.decision_source || evidence.decision_source || '').toLowerCase();
  const relation = String(candidate.source_relation || evidence.source_relation || '').toLowerCase();
  const occs = occurrencesOf(candidate);

  let outcome = MEMBERSHIP_OUTCOMES.EXCLUDED;
  if (linkedOnly) outcome = MEMBERSHIP_OUTCOMES.LINKED_ONLY_INDICATOR;
  else if (member) outcome = MEMBERSHIP_OUTCOMES.INDICATOR;
  else if (contextOnly) outcome = MEMBERSHIP_OUTCOMES.CONTEXT_ONLY;

  let reasonCode = mapPolicyToReason(policy);
  if (review === 'context_only' && !member) reasonCode = MEMBERSHIP_REASON_CODES.ANALYST_CONTEXT_ONLY;
  else if (evidence.promoted_from && member) reasonCode = MEMBERSHIP_REASON_CODES.ANALYST_PROMOTED;
  else if (assertion === 'linked_source_ioc' || linkedMember) {
    if (linkedOnly || (!member && linkedMember)) reasonCode = MEMBERSHIP_REASON_CODES.LINKED_SOURCE_IOC;
  } else if (
    ai &&
    ai.applied === true &&
    String(ai.assessment || '').toLowerCase() === 'context_only' &&
    !member
  ) {
    reasonCode = MEMBERSHIP_REASON_CODES.AI_GROUNDED_DEMOTION;
  } else if (member && EXPLICIT_SET.has(assertion)) {
    reasonCode = MEMBERSHIP_REASON_CODES.EXPLICIT_PUBLISHER_IOC;
  } else if (member && publisherAsserted) {
    reasonCode = MEMBERSHIP_REASON_CODES.AUTHORITATIVE_TABLE_OR_ROW;
  } else if (member && relation === 'operational_malicious') {
    reasonCode = MEMBERSHIP_REASON_CODES.OPERATIONAL_MALICIOUS_CONTEXT;
  } else if (member && !modeA) {
    reasonCode = MEMBERSHIP_REASON_CODES.MODE_B_BODY_MEMBER;
  } else if (!member && modeA && !publisherAsserted) {
    // MODE A non-members without a publisher assertion — even when ai_needed
    // is still true — are suppressed by authority, not merely awaiting AI.
    reasonCode = MEMBERSHIP_REASON_CODES.INSUFFICIENT_PUBLISHER_ASSERTION;
  } else if (!reasonCode && candidate.ai_needed === true && !member) {
    reasonCode = MEMBERSHIP_REASON_CODES.AI_NEEDED_PENDING;
  } else if (!reasonCode) {
    reasonCode = MEMBERSHIP_REASON_CODES.UNKNOWN;
  }

  const blockIds = [...new Set(occs.map((o) => o.block_id).filter(Boolean))].slice(0, 12);
  const zones = [...new Set(occs.map((o) => o.zone).filter(Boolean))];
  const headings = [...new Set(occs.map((o) => o.section_heading).filter(Boolean))].slice(0, 6);

  return {
    version: MEMBERSHIP_EXPLANATION_VERSION,
    identity: identityOf(candidate),
    candidate_type: candidate.candidate_type || null,
    normalized_value: candidate.normalized_value || null,
    original_value: candidate.original_value || null,
    outcome,
    reason_code: reasonCode,
    member,
    context_only: contextOnly,
    linked_only: linkedOnly,
    linked_source_member: linkedMember,
    summary: humanSummary({ outcome, reasonCode, policy, assertion, modeA, member }),
    scope: {
      engine: candidate.scope_engine || evidence.scope_engine || null,
      engine_version: candidate.scope_engine_version || evidence.scope_engine_version || null,
      section_tree_version: candidate.section_tree_version || evidence.section_tree_version || null,
      mode: modeA ? 'A' : 'B',
      document_has_authoritative_scope: modeA,
      publisher_asserted: publisherAsserted
    },
    policy: {
      decision: policy || null,
      source_assertion: assertion || null,
      source_relation: relation || null,
      decision_source: decisionSource || null,
      evidence_strength: candidate.evidence_strength || evidence.evidence_strength || null,
      ai_needed: candidate.ai_needed === true || evidence.ai_needed === true
    },
    ai: ai
      ? {
          assessment: ai.assessment || null,
          role: ai.role || null,
          applied: ai.applied === true,
          supported: ai.supported ?? null,
          unsupported_reason: ai.unsupported_reason || null
        }
      : null,
    analyst: {
      review_status: review,
      promoted: Boolean(evidence.promoted_from),
      match_state: candidate.match_state || null
    },
    evidence: {
      block_ids: blockIds,
      zones,
      section_headings: headings,
      publisher_evidence: evidence.publisher_evidence || candidate.publisher_evidence || null,
      evidence_text: candidate.evidence_text ? String(candidate.evidence_text).slice(0, 280) : null
    }
  };
}

/**
 * Bounded explanation suitable for API / evidence persistence overlays.
 * @param {object} candidate
 */
export function compactMembershipExplanation(candidate) {
  const e = explainMembershipDecision(candidate);
  return {
    version: e.version,
    outcome: e.outcome,
    reason_code: e.reason_code,
    member: e.member,
    summary: e.summary,
    scope_mode: e.scope?.mode || null,
    policy_decision: e.policy?.decision || null,
    source_assertion: e.policy?.source_assertion || null,
    ai_applied: e.ai?.applied ?? null
  };
}
