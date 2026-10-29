/**
 * Threat Library IOC promotion eligibility.
 *
 * Approve = analyst accepts the candidate.
 * Create IOCs = materialize only approved, supported, new observables.
 * A CIDR Indicator is an `ip` / `ipv6` IOC record whose observable keeps the
 * canonical network and prefix (the ioc_items contract the EmergingThreats
 * network rows already use): never exploded into host IPs, never truncated to
 * a single address, never the same identity as a host IP.
 */

import {
  publisherAuthoritativeIocMembershipSql,
  isReportIndicatorMember,
  isUnionReportIndicatorMember,
  isPendingReviewActionableIndicator,
  isContextOnlyCandidate as isContextOnlyFromContract,
  notContextOnlySql,
  reviewActionableIndicatorSql,
  hasAuthoritativePublisherIocScope as hasPublisherScope,
  isPublisherAssertedReportIoc as isPublisherAsserted,
  isLinkedSourceAssertedIoc,
  NON_IOC_CANDIDATE_TYPES
} from './indicatorMembership.js';
import { parseNetworkObservable } from '../networkObservable.js';

export {
  hasAuthoritativePublisherIocScope,
  isPublisherAssertedReportIoc,
  isPublisherAuthoritativeReportIocMember,
  publisherAuthoritativeIocMembershipSql,
  isReportIndicatorMember,
  isReviewActionableIndicator,
  isUnionReportIndicatorMember,
  isPendingReviewActionableIndicator,
  reviewActionableIndicatorSql
} from './indicatorMembership.js';

export const PUBLISHER_AUTHORITATIVE_IOC_MEMBERSHIP_SQL = publisherAuthoritativeIocMembershipSql('c');

export const CREATABLE_IOC_TYPES = Object.freeze([
  'ip',
  'ipv6',
  'domain',
  'url',
  'md5',
  'sha1',
  'sha256',
  'cidr'
]);

const CREATABLE = new Set(CREATABLE_IOC_TYPES);
const NON_IOC_TYPES = new Set(NON_IOC_CANDIDATE_TYPES);

export const INVALID_NETWORK_DETAIL =
  'The value is not a valid IP address or network, so it cannot be stored as an IOC record.';

const NETWORK_CANDIDATE_TYPES = new Set(['ip', 'ipv6', 'cidr']);

/**
 * ioc_items identity (observable_type + canonical observable) of a creatable
 * candidate. Network values (ip / ipv6 / cidr) go through the IOC layer's
 * canonicalizer, so an IPv6 address is an `ipv6` IOC and a CIDR is an `ip` /
 * `ipv6` network IOC with its prefix; other types keep their stored value.
 * @returns {{ type: string, value: string } | null} null for an invalid network
 */
export function iocStorageIdentity(candidate) {
  const type = typeOf(candidate);
  const value = String(candidate?.normalized_value || '');
  if (!NETWORK_CANDIDATE_TYPES.has(type)) return { type, value };
  const network = parseNetworkObservable(value);
  if (!network || !network.ok) return null;
  // A cidr candidate must stay a network, a host candidate must stay a host.
  if ((type === 'cidr') !== (network.kind === 'cidr')) return null;
  return { type: network.type, value: network.value };
}

export const PROMOTION_OUTCOMES = Object.freeze({
  WILL_CREATE: 'will_create',
  CREATED: 'created',
  ALREADY_EXISTING: 'already_existing',
  UNSUPPORTED: 'unsupported',
  NOT_APPROVED: 'not_approved',
  NOT_APPLICABLE: 'not_applicable',
  FAILED: 'failed'
});

function reviewOf(candidate) {
  return String(candidate?.review_status || 'pending').toLowerCase();
}

function typeOf(candidate) {
  return String(candidate?.candidate_type || '').toLowerCase();
}

function evidenceOf(candidate) {
  return candidate?.evidence && typeof candidate.evidence === 'object' ? candidate.evidence : {};
}

export function isAnalystApproved(candidate) {
  const review = reviewOf(candidate);
  return review === 'approved' || review === 'created_ioc';
}

/**
 * Original-document Indicator membership (Indicators / Original filter).
 * Canonical implementation: indicatorMembership.isReportIndicatorMember.
 * For Approve / Create eligibility use isReviewActionableIndicator (union).
 */
export function isActionableReviewIndicator(candidate) {
  return isReportIndicatorMember(candidate);
}

export function isPendingActionableCandidate(candidate) {
  return isPendingReviewActionableIndicator(candidate);
}

/**
 * Context Only != IOC candidate. Canonical: indicatorMembership.isContextOnlyCandidate.
 */
export function isContextOnlyCandidate(candidate) {
  return isContextOnlyFromContract(candidate);
}

/** SQL predicate equivalent of isContextOnlyCandidate (negated) for `threat_report_candidates` rows. */
export const NOT_CONTEXT_ONLY_SQL = notContextOnlySql();

/**
 * Row-level Context Only -> IOC override eligibility. Only a context-only row
 * with a creatable observable type may be promoted; the analyst must confirm.
 * @returns {{ ok: boolean, code?: string, detail?: string }}
 */
export function classifyPromoteEligibility(candidate) {
  if (!candidate) return { ok: false, code: 'promote_not_found', detail: 'Candidate not found.' };
  // A MODE A narrative value outside the curated IOC set is not an IOC
  // candidate whatever its assessment, so Approve can never reach it; it is
  // promotable like a Context Only row (subject to the stance gate below).
  if (!isContextOnlyCandidate(candidate) && !isMissingFromPublisherScope(candidate)) {
    return { ok: false, code: 'promote_not_context_only', detail: 'Only Context Only indicators can be promoted; use Approve for IOC candidates.' };
  }
  const type = typeOf(candidate);
  if (!CREATABLE.has(type)) {
    return {
      ok: false,
      code: 'promote_unsupported_type',
      detail: `Type ${type || 'unknown'} cannot be stored as an IOC record.`
    };
  }
  if (!iocStorageIdentity(candidate)) {
    return { ok: false, code: 'promote_unsupported_type', detail: INVALID_NETWORK_DETAIL };
  }
  // MODE A narrative value (outside the publisher's curated IOC set): the
  // analyst may confirm it only when the publisher's own reading of it is not
  // negative — never a value the publisher called benign / a provider / a
  // reference / an example, and never one outside the original document
  // (tl-candidates-v45).
  if (isMissingFromPublisherScope(candidate)) {
    const ev = candidate.evidence && typeof candidate.evidence === 'object' ? candidate.evidence : {};
    const policy = String(ev.policy_decision || candidate.policy_decision || '');
    const flagged = candidate.is_report_source === true || ev.rfc_example === true || candidate.rfc_example === true;
    if (candidate.has_original_document_occurrence === false || flagged || !NARRATIVE_PROMOTABLE_POLICIES.has(policy)) {
      return {
        ok: false,
        code: 'promote_outside_publisher_scope',
        detail: 'The publisher curated its IOC set and describes this value as non-malicious context (provider, reference, example or benign); it cannot be promoted.'
      };
    }
  }
  // Promote re-classifies and then runs Create IOCs, which only materializes
  // report Indicators. Decide on the row as it would be after promotion, before
  // anything is written, so a promotion never half-applies.
  if (!isUnionReportIndicatorMember(asPromotedRow(candidate))) {
    return {
      ok: false,
      code: 'promote_outside_publisher_scope',
      detail: 'The publisher curated its IOC set and this value is outside it; promotion cannot create an IOC for it.'
    };
  }
  return { ok: true };
}

/** MODE A: a value neither the publisher's IOC set nor a linked IOC Source asserts. */
function isMissingFromPublisherScope(candidate) {
  return hasPublisherScope(candidate) && !isPublisherAsserted(candidate) && !isLinkedSourceAssertedIoc(candidate);
}

/**
 * MODE A narrative policy decisions an analyst may confirm: the extractor kept
 * the value as context only because it sits outside the curated IOC set (or
 * left it to the model), not because the publisher described it as benign.
 */
const NARRATIVE_PROMOTABLE_POLICIES = new Set([
  'context_only_narrative_with_authoritative_scope',
  'context_only_contextual_mention_in_indicator_section',
  'ai_needed_authoritative_narrative',
  'ai_needed_prose_sample_hash',
  'demoted_weak_evidence',
  'pass'
]);

/** The review fields promote_to_ioc writes, applied to a copy (never persisted). */
function asPromotedRow(candidate) {
  const ev = candidate.evidence && typeof candidate.evidence === 'object' ? candidate.evidence : {};
  return {
    ...candidate,
    review_status: 'approved',
    assessment: ['malicious', 'suspicious'].includes(String(candidate.assessment)) ? candidate.assessment : 'suspicious',
    is_ioc: true,
    match_state: candidate.matched_ioc_id ? 'existing' : 'new',
    evidence: { ...ev, promoted_from: ev.promoted_from || {} }
  };
}

export function isContextOrIgnored(candidate) {
  if (!candidate || candidate.is_ioc === false) return true;
  const review = reviewOf(candidate);
  const assessment = String(candidate.assessment || '').toLowerCase();
  const state = String(candidate.match_state || '').toLowerCase();
  if (review === 'ignored' || review === 'context_only') return true;
  if (assessment === 'context_only' || assessment === 'invalid') return true;
  if (state === 'context_only' || state === 'invalid') return true;
  return false;
}

function alreadyHasIocRecord(candidate) {
  if (candidate?.matched_ioc_id) return true;
  if (reviewOf(candidate) === 'created_ioc') return true;
  return String(candidate?.match_state || '').toLowerCase() === 'existing';
}

/**
 * Classify one candidate for Create IOCs. Never mutates, never explodes CIDR.
 * @returns {{
 *   eligible: boolean,
 *   outcome: string,
 *   detail?: string,
 *   ioc_id?: number|null
 * }}
 */
export function classifyCreateEligibility(candidate) {
  const type = typeOf(candidate);

  if (isContextOrIgnored(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPLICABLE,
      detail: 'No IOC creation expected for context-only or ignored indicators.'
    };
  }

  // Original publisher Indicators or authoritative linked-source Indicators.
  if (!isUnionReportIndicatorMember(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPLICABLE,
      detail: 'Not an actionable report Indicator (original publisher or linked IOC source).'
    };
  }

  if (!CREATABLE.has(type)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.UNSUPPORTED,
      detail: `Type ${type || 'unknown'} cannot be stored as an IOC record.`
    };
  }

  if (!isAnalystApproved(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPROVED,
      detail: 'Only approved indicators can be created as IOCs.'
    };
  }

  // Approve is the creation gate. `unknown` means the model did not decide —
  // analyst approval still materializes the IOC. `benign` stays blocked even
  // when approved; context_only / invalid are already excluded above.
  const assessment = String(candidate.assessment || '').toLowerCase();
  if (assessment === 'benign') {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPLICABLE,
      detail: 'Benign indicators are not created as IOC records.'
    };
  }

  if (alreadyHasIocRecord(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.ALREADY_EXISTING,
      ioc_id: candidate.matched_ioc_id ? Number(candidate.matched_ioc_id) : null,
      detail: 'An IOC record already exists for this indicator.'
    };
  }

  // Only a value with a valid ioc_items identity can be created: a malformed
  // network is reported, never truncated to a host or stored as written.
  if (!iocStorageIdentity(candidate)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.UNSUPPORTED,
      detail: INVALID_NETWORK_DETAIL
    };
  }

  return {
    eligible: true,
    outcome: PROMOTION_OUTCOMES.WILL_CREATE
  };
}

/**
 * @param {object[]} candidates
 */
export function previewCreateIocPromotion(candidates) {
  const results = (Array.isArray(candidates) ? candidates : []).map((c) => {
    const classified = classifyCreateEligibility(c);
    return {
      candidate_id: Number(c.id),
      outcome: classified.outcome,
      eligible: classified.eligible === true,
      detail: classified.detail || null,
      ioc_id: classified.ioc_id ?? null
    };
  });
  return { summary: summarizePromotionResults(results), results };
}

export function summarizePromotionResults(results) {
  const summary = {
    selected: results.length,
    eligible: 0,
    created: 0,
    already_existing: 0,
    not_approved: 0,
    unsupported: 0,
    not_applicable: 0,
    failed: 0
  };
  for (const row of results) {
    const outcome = String(row.outcome || '');
    if (outcome === PROMOTION_OUTCOMES.WILL_CREATE || row.eligible === true) summary.eligible += 1;
    if (outcome === PROMOTION_OUTCOMES.CREATED) {
      summary.created += 1;
    }
    if (outcome === PROMOTION_OUTCOMES.ALREADY_EXISTING) summary.already_existing += 1;
    if (outcome === PROMOTION_OUTCOMES.NOT_APPROVED) summary.not_approved += 1;
    if (outcome === PROMOTION_OUTCOMES.UNSUPPORTED) summary.unsupported += 1;
    if (outcome === PROMOTION_OUTCOMES.NOT_APPLICABLE) summary.not_applicable += 1;
    if (outcome === PROMOTION_OUTCOMES.FAILED) summary.failed += 1;
  }
  return summary;
}

/**
 * True when Create IOCs may run (after confirm): at least one row will be
 * created, linked as already-existing, or recorded as unsupported.
 * All-pending / all-ignored selections are blocked.
 */
export function canExecutePromotion(summary) {
  if (!summary) return false;
  return (summary.eligible || 0) > 0
    || (summary.already_existing || 0) > 0
    || (summary.unsupported || 0) > 0;
}

export function isNoneEligibleBlock(summary) {
  if (!summary || summary.selected <= 0) return true;
  return !canExecutePromotion(summary) && (summary.not_approved || 0) + (summary.not_applicable || 0) >= summary.selected;
}
