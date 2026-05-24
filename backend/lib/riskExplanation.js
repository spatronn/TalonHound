/**
 * Normalize riskEngine output + optional LLM adjustment into analyst-friendly explanation.
 */

function fmtNum(n, digits = 2) {
  const x = Number(n);
  if (!Number.isFinite(x)) return null;
  return Number(x.toFixed(digits));
}

export function buildRiskExplanation(risk = {}, llmRisk = {}, context = {}) {
  const breakdown = risk?.risk_breakdown || {};
  const components = breakdown.components || {};
  const baseScore = fmtNum(llmRisk?.risk_before_llm ?? risk?.risk_score ?? components.base_score ?? 0);
  const finalScore = fmtNum(llmRisk?.final_risk_score ?? risk?.risk_score ?? breakdown.final_score ?? 0);
  const aiDelta = llmRisk?.llm_risk_adjustment === null || llmRisk?.llm_risk_adjustment === undefined
    ? null
    : fmtNum(llmRisk.llm_risk_adjustment);

  const verdict = String(breakdown.verdict || context?.verdict || '').trim();
  const evidenceTier = breakdown.evidence_tier || breakdown.raw?.evidence_tier || null;
  const actionOutcome = breakdown.action_outcome || null;

  const notes = [
    'Risk score reflects environment impact, evidence type, action outcome, analyst verdict, and IOC type.'
  ];

  if (verdict === 'FP') {
    notes.push('False positive verdict sets deterministic risk to 0.');
  }
  if (breakdown.dns_only_dampening) {
    notes.push('DNS-only evidence caps how much volume can increase the score.');
  }
  if (breakdown.blocked_only_dampening) {
    notes.push('Blocked-only traffic dampens the action outcome contribution.');
  }
  if (String(context?.suppression?.active) === 'true' || context?.suppressed === true) {
    notes.push('This IOC is suppressed; future correlation impact may be reduced.');
  }

  const componentList = [
    {
      name: 'Base Risk',
      value: components.base_score ?? 8,
      contribution: fmtNum(components.base_score),
      explanation: 'Starting score before environment signals are applied.'
    },
    {
      name: 'Detection Hits',
      value: breakdown.total_hits ?? context?.event_count ?? context?.total_hits ?? 0,
      contribution: fmtNum(components.hits_signal),
      explanation: 'More matching telemetry events increase exposure signal.'
    },
    {
      name: 'Observed Hosts',
      value: breakdown.affected_hosts ?? context?.asset_count ?? 0,
      contribution: fmtNum(components.observed_hosts_signal),
      explanation: 'Host spread increases impact when the IOC appears on multiple assets.'
    },
    {
      name: 'Allowed / Blocked',
      value: `${breakdown.accepted_connections ?? 0} allowed / ${breakdown.blocked_connections ?? 0} blocked`,
      contribution: fmtNum(components.action_signal),
      explanation: 'Allowed connections increase risk more than blocked-only observations.'
    },
    {
      name: 'Detection Type',
      value: breakdown.raw?.detection_type || context?.detection_type || 'unknown',
      contribution: fmtNum(components.detection_type_signal),
      explanation: 'Real-time detections weigh slightly more than retroactive matches.'
    },
    {
      name: 'IOC Confidence',
      value: breakdown.raw?.confidence || context?.confidence || 'unknown',
      contribution: fmtNum(components.confidence_signal),
      explanation: 'Higher-confidence IOC sources add to the score.'
    },
    {
      name: 'Analyst Verdict',
      value: verdict || 'Unreviewed',
      contribution: fmtNum(components.verdict_signal),
      explanation: 'Confirmed true positives increase risk; suspicious verdicts add moderate weight.'
    },
    {
      name: 'IOC Type',
      value: breakdown.raw?.ioc_type || context?.ioc_type || 'unknown',
      contribution: fmtNum(components.ioc_type_bonus),
      explanation: 'File hashes and high-risk observable types carry higher base weight.'
    }
  ];

  let verdictEffect = null;
  if (verdict === 'FP') verdictEffect = 'False positive verdict — risk forced to 0.';
  else if (verdict === 'TP') verdictEffect = 'True positive verdict increases risk contribution.';
  else if (verdict === 'Suspicious') verdictEffect = 'Suspicious verdict adds moderate risk weight.';
  else if (verdict) verdictEffect = `Current verdict: ${verdict}.`;

  if (aiDelta !== null) {
    notes.push(`AI adjustment ${aiDelta >= 0 ? '+' : ''}${aiDelta} applied on top of deterministic score ${baseScore ?? '—'}.`);
  }

  return {
    base_score: baseScore,
    final_score: finalScore,
    ai_delta: aiDelta,
    ai_confidence: llmRisk?.llm_risk_confidence ?? null,
    ai_reason: llmRisk?.llm_risk_reason ?? null,
    verdict_effect: verdictEffect,
    evidence_tier: evidenceTier,
    action_outcome: actionOutcome,
    components: componentList,
    notes,
    model: breakdown.model || null,
    summary_reason: breakdown.reason || null
  };
}
