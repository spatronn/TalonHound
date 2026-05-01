import { buildActivityModel, normalizeIocType } from './activityBuilder.js';
import { calculateBehaviorRisk } from './riskEngine.js';

export function buildLlmAdvisorPayload(incident = {}) {
  const iocType = normalizeIocType(incident?.ioc_type || incident?.observable_type);
  const activity = buildActivityModel(incident);
  const behaviorRisk = calculateBehaviorRisk(activity);

  return {
    ioc: String(incident?.ioc_value || incident?.observable_value || ''),
    ioc_type: iocType,
    activity,
    behavior_risk: {
      score: behaviorRisk.risk_score,
      breakdown: behaviorRisk.risk_breakdown
    }
  };
}
