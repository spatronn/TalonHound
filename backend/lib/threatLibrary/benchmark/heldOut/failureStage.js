/**
 * Map a scored false negative to the earliest pipeline stage that explains it.
 * Uses existing scoreBenchmarkCase FN fields + candidate policy metadata.
 * Does not invent causes when evidence is missing.
 */

export const FAILURE_STAGES = Object.freeze({
  NOT_EXTRACTED: 'not_extracted',
  MISTYPED: 'mistyped',
  MEMBERSHIP_SUPPRESSION: 'membership_suppression',
  CONTEXT_ONLY_POLICY: 'context_only_policy',
  AI_DEMOTION: 'ai_demotion',
  ANALYST_EXCLUSION: 'analyst_exclusion',
  UNKNOWN: 'unknown'
});

/**
 * @param {{ id: string, extracted?: boolean, mistyped_as?: string|null, member?: boolean, context_only?: boolean, policy_decision?: string|null, source_assertion?: string|null, ai_needed?: boolean }} fn
 * @param {object|null} [candidate] optional full candidate for richer AI/analyst signals
 */
export function classifyFailureStage(fn, candidate = null) {
  if (!fn || typeof fn !== 'object') return { stage: FAILURE_STAGES.UNKNOWN, detail: 'missing_fn' };
  if (fn.extracted === false && fn.mistyped_as) {
    return { stage: FAILURE_STAGES.MISTYPED, detail: `extracted_as:${fn.mistyped_as}` };
  }
  if (fn.extracted === false) {
    return { stage: FAILURE_STAGES.NOT_EXTRACTED, detail: 'value_never_became_a_candidate' };
  }

  const review = String(candidate?.review_status || '').toLowerCase();
  if (review === 'context_only' || review === 'ignored') {
    return { stage: FAILURE_STAGES.ANALYST_EXCLUSION, detail: `review_status=${review}` };
  }

  const ai = candidate?.ai_classification || candidate?.evidence?.ai_classification;
  if (ai?.applied === true && String(ai.assessment || '').toLowerCase() === 'context_only') {
    return { stage: FAILURE_STAGES.AI_DEMOTION, detail: 'ai_grounded_context_only' };
  }

  const policy = String(fn.policy_decision || candidate?.policy_decision || '').toLowerCase();
  if (policy.startsWith('context_only') || policy.startsWith('demoted_') || policy.startsWith('ioc_excluded')) {
    return { stage: FAILURE_STAGES.CONTEXT_ONLY_POLICY, detail: policy };
  }

  if (fn.extracted === true && fn.member === false) {
    return { stage: FAILURE_STAGES.MEMBERSHIP_SUPPRESSION, detail: policy || fn.source_assertion || 'extracted_but_not_member' };
  }

  return { stage: FAILURE_STAGES.UNKNOWN, detail: 'unclassified' };
}

/**
 * Attach failure stages to a scoreBenchmarkCase indicators block.
 * @param {object} indicatorsScore score.indicators from scoreBenchmarkCase
 * @param {Map<string, object>} [byId] candidate identity → candidate
 */
export function annotateFalseNegativesWithStages(indicatorsScore, byId = new Map()) {
  const fns = Array.isArray(indicatorsScore?.false_negatives) ? indicatorsScore.false_negatives : [];
  const annotated = fns.map((fn) => {
    const c = byId.get(fn.id) || null;
    const { stage, detail } = classifyFailureStage(fn, c);
    return { ...fn, failure_stage: stage, failure_detail: detail };
  });
  const byStage = {};
  for (const a of annotated) {
    byStage[a.failure_stage] = (byStage[a.failure_stage] || 0) + 1;
  }
  return {
    ...indicatorsScore,
    false_negatives: annotated,
    failure_stages: byStage
  };
}
