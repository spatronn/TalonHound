/**
 * Canonical Threat Library report-Indicator membership + Context Only contracts.
 *
 * Product concepts (kept separate on purpose):
 *
 *   All                          = every persisted candidate row
 *   Report Indicator membership  = belongs in the Indicators review set / tab
 *   Context Only                 = assessment|match_state|review_status = context_only
 *   Review actionability         = membership ∧ pending (Approve / Create eligibility
 *                                  layers on top via promotion.js)
 *
 * MODE A (document_has_authoritative_scope): membership requires a publisher
 * assertion (explicit_* source_assertion or an asserted occurrence in an
 * authoritative zone). Narrative-only rows may still exist under All / Context Only.
 *
 * MODE B (no authoritative scope): this module does not restrict membership;
 * the remaining membership gates (is_ioc, type, context_only, reserved, …) still apply.
 *
 * Frontend `isReviewIndicator` and SQL `REVIEW_CANDIDATE_WHERE` MUST stay
 * behaviourally identical to `isReportIndicatorMember`. Parity is enforced by
 * `indicatorMembership.parity.test.js`.
 */

export const NON_IOC_CANDIDATE_TYPES = Object.freeze(['cve', 'attack_technique']);

export const EXPLICIT_PUBLISHER_IOC_ASSERTIONS = Object.freeze([
  'explicit_ioc',
  'explicit_c2',
  'explicit_operational_infrastructure'
]);

export const AUTHORITATIVE_PUBLISHER_OCCURRENCE_ZONES = Object.freeze([
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'operational_infrastructure'
]);

const NON_IOC_TYPE_SET = new Set(NON_IOC_CANDIDATE_TYPES);
const EXPLICIT_ASSERTION_SET = new Set(EXPLICIT_PUBLISHER_IOC_ASSERTIONS);
const AUTHORITATIVE_ZONE_SET = new Set(AUTHORITATIVE_PUBLISHER_OCCURRENCE_ZONES);

function evidenceOf(candidate) {
  return candidate?.evidence && typeof candidate.evidence === 'object' ? candidate.evidence : {};
}

function typeOf(candidate) {
  return String(candidate?.candidate_type || '').toLowerCase();
}

function reviewOf(candidate) {
  return String(candidate?.review_status || 'pending').toLowerCase();
}

function candidateOccurrences(candidate) {
  const ev = evidenceOf(candidate);
  if (Array.isArray(candidate?.occurrences) && candidate.occurrences.length) return candidate.occurrences;
  return Array.isArray(ev.occurrences) ? ev.occurrences : [];
}

export function hasAuthoritativePublisherIocScope(candidate) {
  const ev = evidenceOf(candidate);
  return candidate?.document_has_authoritative_scope === true
    || ev.document_has_authoritative_scope === true;
}

export function hasPublisherIocSectionOccurrence(candidate) {
  return candidateOccurrences(candidate).some((occ) => {
    if (!AUTHORITATIVE_ZONE_SET.has(String(occ?.zone || ''))) return false;
    if (occ?.asserted === true) return true;
    return !occ?.occurrence_kind;
  });
}

export function isPublisherAssertedReportIoc(candidate) {
  const ev = evidenceOf(candidate);
  const assertion = String(candidate?.source_assertion || ev.source_assertion || '').toLowerCase();
  if (EXPLICIT_ASSERTION_SET.has(assertion)) return true;
  return hasPublisherIocSectionOccurrence(candidate);
}

/**
 * MODE A gate only. MODE B returns true (no publisher restriction).
 */
export function isPublisherAuthoritativeReportIocMember(candidate) {
  if (!hasAuthoritativePublisherIocScope(candidate)) return true;
  return isPublisherAssertedReportIoc(candidate);
}

export function isContextOnlyCandidate(candidate) {
  if (!candidate) return false;
  const review = reviewOf(candidate);
  const assessment = String(candidate.assessment || '').toLowerCase();
  const state = String(candidate.match_state || '').toLowerCase();
  return review === 'context_only' || assessment === 'context_only' || state === 'context_only';
}

function isNonActionableLocalOrReserved(candidate) {
  const ev = evidenceOf(candidate);
  return candidate?.reserved_address === true
    || candidate?.non_actionable_local === true
    || ev.reserved_address === true
    || ev.non_actionable_local === true;
}

/**
 * Report Indicator membership — the Indicators tab / review_candidate_count set.
 * Alias history: frontend `isReviewIndicator`, backend `isActionableReviewIndicator`.
 */
export function isReportIndicatorMember(candidate) {
  if (!candidate) return false;
  if (candidate.is_ioc === false) return false;
  if (NON_IOC_TYPE_SET.has(typeOf(candidate))) return false;
  const ev = evidenceOf(candidate);
  if (ev.is_parser_derived_metadata === true) return false;
  if (ev.is_direct_source_observable === false) return false;
  if (isNonActionableLocalOrReserved(candidate)) return false;
  const state = String(candidate.match_state || '').toLowerCase();
  const review = reviewOf(candidate);
  if (state === 'context_only' || review === 'context_only' || candidate.assessment === 'context_only') return false;
  if (state === 'invalid' || candidate.assessment === 'invalid') return false;
  if (!isPublisherAuthoritativeReportIocMember(candidate)) return false;
  return true;
}

/** @deprecated Prefer isReportIndicatorMember — kept as the historical backend name. */
export function isActionableReviewIndicator(candidate) {
  return isReportIndicatorMember(candidate);
}

/**
 * Analyst review actionability: member ∧ still pending.
 * Distinct from membership (an approved/existing Indicator is still a member).
 */
export function isPendingReviewActionableIndicator(candidate) {
  return isReportIndicatorMember(candidate) && reviewOf(candidate) === 'pending';
}

/**
 * SQL equivalent of isPublisherAuthoritativeReportIocMember for
 * `threat_report_candidates` rows.
 */
export function publisherAuthoritativeIocMembershipSql(alias = 'c') {
  const p = alias ? `${alias}.` : '';
  const assertions = EXPLICIT_PUBLISHER_IOC_ASSERTIONS.map((a) => `'${a}'`).join(', ');
  const zones = AUTHORITATIVE_PUBLISHER_OCCURRENCE_ZONES.map((z) => `'${z}'`).join(', ');
  return `(
    COALESCE(${p}evidence->>'document_has_authoritative_scope', 'false') <> 'true'
    OR COALESCE(${p}source_assertion, ${p}evidence->>'source_assertion', '') IN (
      ${assertions}
    )
    OR EXISTS (
      SELECT 1
      FROM jsonb_array_elements(COALESCE(${p}evidence->'occurrences', '[]'::jsonb)) AS occ
      WHERE occ->>'zone' IN (
        ${zones}
      )
        AND (occ->>'asserted' = 'true' OR COALESCE(occ->>'occurrence_kind', '') = '')
    )
  )`;
}

/**
 * SQL equivalent of isReportIndicatorMember / isActionableReviewIndicator.
 * Reserved / loopback flags live in evidence JSONB (no dedicated columns).
 */
export function reportIndicatorMembershipSql(alias = 'c') {
  const p = alias ? `${alias}.` : '';
  const nonIoc = NON_IOC_CANDIDATE_TYPES.map((t) => `'${t}'`).join(', ');
  return `
  ${p}is_ioc <> false
  AND ${p}candidate_type NOT IN (${nonIoc})
  AND COALESCE(${p}evidence->>'is_parser_derived_metadata', 'false') <> 'true'
  AND COALESCE(${p}evidence->>'is_direct_source_observable', 'true') <> 'false'
  AND COALESCE(${p}evidence->>'reserved_address', 'false') <> 'true'
  AND COALESCE(${p}evidence->>'non_actionable_local', 'false') <> 'true'
  AND COALESCE(${p}assessment, '') NOT IN ('context_only', 'invalid')
  AND COALESCE(${p}match_state, '') NOT IN ('context_only', 'invalid')
  AND COALESCE(${p}review_status, '') <> 'context_only'
  AND ${publisherAuthoritativeIocMembershipSql(alias)}`.replace(/\s+/g, ' ').trim();
}

/** SQL equivalent of NOT isContextOnlyCandidate. */
export function notContextOnlySql(alias = '') {
  const p = alias ? `${alias}.` : '';
  return `
  COALESCE(${p}assessment, '') <> 'context_only'
  AND COALESCE(${p}match_state, '') <> 'context_only'
  AND COALESCE(${p}review_status, '') <> 'context_only'`.replace(/\s+/g, ' ').trim();
}

export function isContextOnlySql(alias = 'c') {
  const p = alias ? `${alias}.` : '';
  return `(
    COALESCE(${p}assessment, '') = 'context_only'
    OR COALESCE(${p}match_state, '') = 'context_only'
    OR COALESCE(${p}review_status, '') = 'context_only'
  )`;
}

/**
 * Bucket counts for a candidate list using the canonical predicates.
 * @returns {{ all: number, indicators: number, context_only: number }}
 */
export function countCandidateBuckets(candidates) {
  const list = Array.isArray(candidates) ? candidates : [];
  let indicators = 0;
  let contextOnly = 0;
  for (const c of list) {
    if (isReportIndicatorMember(c)) indicators += 1;
    if (isContextOnlyCandidate(c)) contextOnly += 1;
  }
  return { all: list.length, indicators, context_only: contextOnly };
}

/**
 * Compact semantic fixture matrix for parity tests (every branch, not every cartesian cell).
 * Each case: { id, candidate, expect: { member, context_only, pending_actionable } }
 */
export function membershipParityCases() {
  const base = {
    candidate_type: 'ip',
    normalized_value: '203.0.113.10',
    is_ioc: true,
    assessment: 'malicious',
    role: 'malicious_infrastructure',
    review_status: 'pending',
    match_state: 'new',
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }]
    }
  };

  const wrap = (id, patch, expect) => {
    const candidate = {
      ...base,
      ...patch,
      evidence: { ...base.evidence, ...(patch.evidence || {}) }
    };
    if (patch.evidence === null) candidate.evidence = {};
    return { id, candidate, expect };
  };

  return [
    wrap('mode_a_explicit_ioc', {}, { member: true, context_only: false, pending_actionable: true }),
    wrap('mode_a_explicit_c2', {
      source_assertion: 'explicit_c2',
      evidence: { source_assertion: 'explicit_c2' }
    }, { member: true, context_only: false, pending_actionable: true }),
    wrap('mode_a_explicit_operational', {
      source_assertion: 'explicit_operational_infrastructure',
      evidence: { source_assertion: 'explicit_operational_infrastructure' }
    }, { member: true, context_only: false, pending_actionable: true }),
    wrap('mode_a_body_mention_malicious', {
      source_assertion: 'body_mention',
      evidence: {
        source_assertion: 'body_mention',
        occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
      }
    }, { member: false, context_only: false, pending_actionable: false }),
    wrap('mode_a_body_mention_matched_existing', {
      source_assertion: 'body_mention',
      match_state: 'existing',
      matched_ioc_id: 99,
      evidence: {
        source_assertion: 'body_mention',
        occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
      }
    }, { member: false, context_only: false, pending_actionable: false }),
    wrap('mode_a_narrative_plus_explicit_occurrence', {
      source_assertion: 'body_mention',
      evidence: {
        source_assertion: 'body_mention',
        occurrences: [
          { zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' },
          { zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }
        ]
      }
    }, { member: true, context_only: false, pending_actionable: true }),
    wrap('mode_b_narrative_malicious', {
      document_has_authoritative_scope: false,
      source_assertion: 'body_mention',
      evidence: {
        document_has_authoritative_scope: false,
        source_assertion: 'body_mention',
        occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
      }
    }, { member: true, context_only: false, pending_actionable: true }),
    wrap('context_only_assessment', {
      assessment: 'context_only',
      match_state: 'context_only',
      role: 'reference',
      source_assertion: 'body_mention',
      evidence: {
        source_assertion: 'body_mention',
        occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
      }
    }, { member: false, context_only: true, pending_actionable: false }),
    wrap('cve_non_ioc_type', {
      candidate_type: 'cve',
      normalized_value: 'CVE-2024-0001',
      is_ioc: false,
      assessment: 'context_only',
      match_state: 'context_only',
      source_assertion: 'non_ioc',
      evidence: { source_assertion: 'non_ioc', is_direct_source_observable: true }
    }, { member: false, context_only: true, pending_actionable: false }),
    wrap('is_ioc_false', {
      is_ioc: false,
      assessment: 'context_only',
      match_state: 'context_only'
    }, { member: false, context_only: true, pending_actionable: false }),
    wrap('parser_derived', {
      evidence: { is_parser_derived_metadata: true, is_direct_source_observable: true }
    }, { member: false, context_only: false, pending_actionable: false }),
    wrap('not_direct_source', {
      evidence: { is_direct_source_observable: false }
    }, { member: false, context_only: false, pending_actionable: false }),
    wrap('loopback_reserved', {
      source_assertion: 'explicit_c2',
      evidence: {
        source_assertion: 'explicit_c2',
        reserved_address: true,
        non_actionable_local: true,
        occurrences: [{ zone: 'c2_section', asserted: true, occurrence_kind: 'endpoint' }]
      }
    }, { member: false, context_only: false, pending_actionable: false }),
    wrap('invalid_assessment', {
      assessment: 'invalid',
      match_state: 'invalid'
    }, { member: false, context_only: false, pending_actionable: false }),
    wrap('member_approved_not_pending', {
      review_status: 'approved',
      match_state: 'existing',
      matched_ioc_id: 42
    }, { member: true, context_only: false, pending_actionable: false }),
    wrap('sha256_explicit', {
      candidate_type: 'sha256',
      normalized_value: 'a'.repeat(64),
      role: 'malware_sample'
    }, { member: true, context_only: false, pending_actionable: true }),
    wrap('url_explicit', {
      candidate_type: 'url',
      normalized_value: 'http://203.0.113.10/path',
      role: 'command_and_control',
      source_assertion: 'explicit_c2',
      evidence: { source_assertion: 'explicit_c2' }
    }, { member: true, context_only: false, pending_actionable: true })
  ];
}
