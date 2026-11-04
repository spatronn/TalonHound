/**
 * The membership decision contract (tl-membership-decision-v1).
 *
 * One pure, ordered rule table decides what a report does with an observable:
 *
 *   member        the publisher asserts it, or the document's own evidence does
 *                 where no curated inventory exists
 *   needs_review  meaningful evidence the structure cannot settle: an analyst
 *                 decides, the model may advise
 *   context_only  kept as context: a stance, a reference, a passing mention
 *   excluded      not an IOC-type observable
 *
 * Authority is per section, not per document. A section asserts, does not
 * assert, or is uncertain. Whether the document holds any asserting section
 * only settles neutral prose: with a curated inventory elsewhere, a passing
 * mention is context, without one it goes to review. It never removes
 * structured or operational evidence.
 *
 * Nothing here approves anything. `member` means the value is in the review set;
 * an analyst still approves it through the audited review path.
 */

export const MEMBERSHIP_DECISION_VERSION = 'tl-membership-decision-v2';

export const MEMBERSHIP_OUTCOME = Object.freeze({
  MEMBER: 'member',
  NEEDS_REVIEW: 'needs_review',
  CONTEXT_ONLY: 'context_only',
  EXCLUDED: 'excluded'
});

export const SECTION_AUTHORITY = Object.freeze({
  ASSERTING: 'asserting',
  NON_ASSERTING: 'non_asserting',
  UNCERTAIN: 'uncertain'
});

const ESCALATING = new Set(['malicious', 'suspicious']);
const MAX_EVIDENCE_REFS = 8;

/**
 * @param {{
 *   excluded?: boolean, exclusion_reason?: string|null,
 *   structured_row?: boolean, operational_clause?: boolean, undecided_sample_hash?: boolean,
 *   unresolved_section_narrative?: boolean, refs?: object[]
 * }} evidence what the document shows
 * @param {{ explicit?: boolean, source_assertion?: string|null }} assertion publisher assertion
 * @param {{ role?: string|null }} role observable role
 * @param {{ blocked?: boolean, reason?: string|null }} stance publisher stance / non-actionable identity
 * @param {{ sections?: string[], document_has_asserting_section?: boolean }} authority
 * @param {{ assessment?: string|null, supported?: boolean|null, applied?: boolean|null, decision_source?: string|null }} classification model output
 * @returns {{ outcome: string, reason_code: string, rule_id: string, evidence_refs: object[], inputs: object, contract_version: string }}
 */
export function decideMembership(evidence = {}, assertion = {}, role = {}, stance = {}, authority = {}, classification = {}) {
  const sections = Array.isArray(authority.sections) ? authority.sections : [];
  const curated = authority.document_has_asserting_section === true;
  const modelAssessment = String(classification.assessment || '').toLowerCase();
  // A model verdict counts unless grounding rejected it or it was not applied.
  const modelEscalates = ESCALATING.has(modelAssessment) && classification.supported !== false && classification.applied !== false;
  // A grounded model verdict that the publisher treats the value as context.
  const modelDemotes = modelAssessment === 'context_only' && classification.applied === true;

  const decide = (outcome, reason_code, rule_id) => ({
    outcome,
    reason_code,
    rule_id,
    evidence_refs: (evidence.refs || []).slice(0, MAX_EVIDENCE_REFS),
    inputs: {
      explicit_assertion: assertion.explicit === true,
      source_assertion: assertion.source_assertion || null,
      role: role.role || null,
      stance: stance.reason || null,
      section_authority: [...new Set(sections)],
      document_has_asserting_section: curated,
      structured_row: evidence.structured_row === true,
      operational_clause: evidence.operational_clause === true,
      model_assessment: modelAssessment || null,
      model_supported: classification.supported ?? null
    },
    contract_version: MEMBERSHIP_DECISION_VERSION
  });

  if (evidence.excluded === true) {
    return decide(MEMBERSHIP_OUTCOME.EXCLUDED, evidence.exclusion_reason || 'not_an_ioc_observable', 'R01_not_an_ioc_observable');
  }
  if (assertion.explicit === true) {
    // A stance the publisher attached to its own row is applied before this
    // point by removing the assertion: reaching here means the row asserts.
    return decide(MEMBERSHIP_OUTCOME.MEMBER, 'publisher_assertion', 'R10_publisher_assertion');
  }
  if (stance.blocked === true) {
    return decide(MEMBERSHIP_OUTCOME.CONTEXT_ONLY, stance.reason || 'publisher_stance', 'R20_publisher_stance');
  }
  if (sections.length > 0 && sections.every((s) => s === SECTION_AUTHORITY.NON_ASSERTING)) {
    return decide(MEMBERSHIP_OUTCOME.CONTEXT_ONLY, 'non_asserting_section', 'R21_non_asserting_section');
  }
  if (modelDemotes) {
    return decide(MEMBERSHIP_OUTCOME.CONTEXT_ONLY, 'grounded_model_context', 'R22_grounded_model_context');
  }

  const structural = evidence.structured_row === true;
  const operational = evidence.operational_clause === true;

  if (!curated) {
    // No section of this document asserts indicators: its structured rows are the
    // publisher's only inventory. A prose statement is evidence, not an assertion:
    // on its own it goes to review, and a model verdict grounded in publisher text
    // is what can carry it further.
    if (structural) return decide(MEMBERSHIP_OUTCOME.MEMBER, 'structured_inventory_without_curated_section', 'R30_structured_inventory');
    if (modelEscalates) return decide(MEMBERSHIP_OUTCOME.MEMBER, 'grounded_model_assessment_without_curated_section', 'R32_grounded_model_assessment');
    if (operational) return decide(MEMBERSHIP_OUTCOME.NEEDS_REVIEW, 'operational_statement_without_curated_section', 'R31_operational_statement');
    // A digest names a file: with no curated list, a prose hash is the sample the report discusses.
    if (evidence.undecided_sample_hash === true) return decide(MEMBERSHIP_OUTCOME.MEMBER, 'sample_hash_without_curated_section', 'R34_sample_hash');
    return decide(MEMBERSHIP_OUTCOME.NEEDS_REVIEW, 'mention_without_curated_section', 'R33_mention_needs_review');
  }

  // A curated inventory exists elsewhere: evidence outside it is not silently dropped.
  if (structural) return decide(MEMBERSHIP_OUTCOME.NEEDS_REVIEW, 'structured_rows_outside_curated_section', 'R40_structured_rows_uncertain_section');
  if (operational) return decide(MEMBERSHIP_OUTCOME.NEEDS_REVIEW, 'operational_statement_outside_curated_section', 'R41_operational_statement');
  // Beside a curated inventory only a verdict grounded in publisher text counts.
  if (modelEscalates && classification.supported === true) return decide(MEMBERSHIP_OUTCOME.NEEDS_REVIEW, 'grounded_model_assessment_outside_curated_section', 'R42_grounded_model_assessment');
  if (evidence.undecided_sample_hash === true) return decide(MEMBERSHIP_OUTCOME.NEEDS_REVIEW, 'undecided_sample_hash', 'R43_undecided_sample_hash');
  if (evidence.unresolved_section_narrative === true) return decide(MEMBERSHIP_OUTCOME.NEEDS_REVIEW, 'unresolved_narrative_in_curated_section', 'R44_unresolved_section_narrative');
  return decide(MEMBERSHIP_OUTCOME.CONTEXT_ONLY, 'passing_mention_with_curated_inventory', 'R50_passing_mention');
}
