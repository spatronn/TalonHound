/**
 * Threat Library IOC promotion eligibility.
 *
 * Approve = analyst accepts the candidate.
 * Create IOCs = materialize only approved, supported, new observables.
 * CIDR is first-class in Threat Library candidates but is not an ioc_items type;
 * it is never exploded into host IPs and never truncated to a single address.
 */

export const CREATABLE_IOC_TYPES = Object.freeze([
  'ip',
  'ipv6',
  'domain',
  'url',
  'md5',
  'sha1',
  'sha256'
]);

const CREATABLE = new Set(CREATABLE_IOC_TYPES);
const NON_IOC_TYPES = new Set(['cve', 'attack_technique']);

export const CIDR_UNSUPPORTED_DETAIL =
  'CIDR indicators are preserved in Threat Library but cannot yet be created as IOC records.';

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
 * Rows that belong in the analyst review set (mirrors frontend isReviewIndicator).
 */
export function isActionableReviewIndicator(candidate) {
  if (!candidate || candidate.is_ioc === false) return false;
  if (NON_IOC_TYPES.has(typeOf(candidate))) return false;
  const ev = evidenceOf(candidate);
  if (ev.is_parser_derived_metadata === true) return false;
  if (ev.is_direct_source_observable === false) return false;
  const state = String(candidate.match_state || '').toLowerCase();
  const review = reviewOf(candidate);
  if (state === 'context_only' || review === 'context_only' || candidate.assessment === 'context_only') return false;
  if (state === 'invalid' || candidate.assessment === 'invalid') return false;
  return true;
}

export function isPendingActionableCandidate(candidate) {
  return isActionableReviewIndicator(candidate) && reviewOf(candidate) === 'pending';
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

  if (type === 'cidr') {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.UNSUPPORTED,
      detail: CIDR_UNSUPPORTED_DETAIL
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

  const assessment = String(candidate.assessment || '').toLowerCase();
  if (!['malicious', 'suspicious'].includes(assessment)) {
    return {
      eligible: false,
      outcome: PROMOTION_OUTCOMES.NOT_APPLICABLE,
      detail: 'Assessment is not malicious or suspicious.'
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
