import { calculateIncidentRisk } from './riskEngine.js';

export function computeIncidentRiskScore(row = {}) {
  const withHits = {
    ...row,
    total_hits: Math.max(Number(row.total_hits || 0), Number(row.event_count || 0))
  };
  return Number(calculateIncidentRisk(withHits).risk_score || 0);
}
