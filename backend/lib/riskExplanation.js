/**
 * Normalize riskEngine output + optional LLM adjustment into analyst-friendly explanation.
 * Evidence tier / action outcome for display are derived from detection event context,
 * not copied blindly from risk_breakdown when event distribution is available.
 */

import {
  inferEventFamilyFromRow,
  isProxyAccessObservedEvent,
  isProxyFailedEvent,
  isSubstantiveDnsEvent
} from './eventEvidenceSignals.js';

function fmtNum(n, digits = 2) {
  const x = Number(n);
  if (!Number.isFinite(x)) return null;
  return Number(x.toFixed(digits));
}

export const EVIDENCE_TIER_LABELS = {
  false_positive: 'False Positive',
  endpoint_or_file: 'Endpoint / File Evidence',
  proxy_allowed: 'Proxy Allowed Access',
  firewall_allowed: 'Firewall Allowed Access',
  multi_source_network: 'Multi-source Evidence',
  multi_source: 'Multi-source Evidence',
  dns_proxy: 'DNS + Proxy Evidence',
  proxy_only: 'Proxy Evidence',
  dns_only: 'DNS Only',
  blocked_only: 'Blocked Only',
  generic_only: 'Generic Evidence',
  unknown: 'Unknown Evidence',
  security_test: 'Security Test'
};

export const ACTION_OUTCOME_LABELS = {
  allowed: 'Allowed',
  blocked: 'Blocked',
  observed_access: 'Observed Access',
  proxy_allowed: 'Observed Access',
  dns_observed: 'DNS Observed',
  proxy_failed: 'Proxy Failed',
  proxy_error: 'Proxy Error',
  unknown: 'Unknown Outcome',
  none: 'No Outcome'
};

export function formatEvidenceTierLabel(tier) {
  const key = String(tier || '').trim().toLowerCase();
  return EVIDENCE_TIER_LABELS[key] || (key ? key.replace(/_/g, ' ') : 'Unknown Evidence');
}

export function formatActionOutcomeLabel(outcome) {
  const key = String(outcome || '').trim().toLowerCase();
  return ACTION_OUTCOME_LABELS[key] || (key ? key.replace(/_/g, ' ') : 'Unknown Outcome');
}

function normalizeEventRow(row = {}) {
  const family = inferEventFamilyFromRow(row);
  const sourceType = String(row.source_type || family || '').toLowerCase();
  return {
    family,
    source_type: sourceType === 'squid_proxy' ? 'proxy' : sourceType,
    parser_source: String(row.parser_source || '').toLowerCase(),
    method: String(row?.normalized_event_json?.method || row?.match_context?.method || '').toUpperCase(),
    status: String(row?.normalized_event_json?.status || row?.match_context?.status || row?.match_context?.http_status || ''),
    action: String(row?.match_context?.action || row?.normalized_event_json?.action || '').toLowerCase(),
    raw_sample: String(row.raw_log_snapshot || row.raw_sample || '')
  };
}

function collectEventFamilies(context = {}) {
  const sourceTypes = context?.event_summary?.source_types && typeof context.event_summary.source_types === 'object'
    ? context.event_summary.source_types
    : {};
  const stCount = (key) => Math.max(Number(sourceTypes[key] || 0), 0);

  const rows = [];
  if (Array.isArray(context?.explanation_events)) rows.push(...context.explanation_events);
  if (Array.isArray(context?.sample_events)) rows.push(...context.sample_events);

  let hasDns = false;
  let hasProxy = false;
  let hasFirewall = false;
  let hasEndpoint = false;

  if (rows.length) {
    for (const raw of rows) {
      const family = inferEventFamilyFromRow(raw);
      if (family === 'dns' && isSubstantiveDnsEvent(raw)) hasDns = true;
      if (family === 'proxy') hasProxy = true;
      if (family === 'firewall') hasFirewall = true;
      if (/(endpoint|edr|xdr|sysmon|process|file|hash)/.test(family)) hasEndpoint = true;
    }
  } else {
    hasDns = Boolean(context?.has_dns_evidence) || stCount('dns') > 0;
    hasProxy = Boolean(context?.has_proxy_evidence) || stCount('proxy') > 0 || stCount('squid_proxy') > 0;
    hasFirewall = Boolean(context?.has_firewall_evidence) || stCount('firewall') > 0;
    hasEndpoint = Boolean(context?.has_endpoint_evidence) || stCount('endpoint') > 0;

    const iocType = String(context?.ioc_type || '').toLowerCase();
    if (['sha256', 'md5', 'sha1', 'imphash', 'tlsh', 'ssdeep'].includes(iocType)) hasEndpoint = true;
  }

  const sourceFamilies = [hasEndpoint, hasProxy, hasDns, hasFirewall].filter(Boolean).length;

  return { hasDns, hasProxy, hasFirewall, hasEndpoint, sourceFamilies };
}

export function deriveExplanationEvidenceTier(context = {}, breakdown = {}) {
  const verdict = String(breakdown?.verdict || context?.verdict || '').trim();
  if (verdict === 'FP' || String(breakdown?.evidence_tier || '').toLowerCase() === 'false_positive') {
    return { tier: 'false_positive', label: formatEvidenceTierLabel('false_positive') };
  }
  if (String(breakdown?.evidence_tier || '').toLowerCase() === 'security_test') {
    return { tier: 'security_test', label: formatEvidenceTierLabel('security_test') };
  }

  const f = collectEventFamilies(context);

  if (f.hasEndpoint) {
    return { tier: 'endpoint_or_file', label: formatEvidenceTierLabel('endpoint_or_file') };
  }
  if (f.hasDns && f.hasProxy && !f.hasFirewall) {
    return { tier: 'dns_proxy', label: formatEvidenceTierLabel('dns_proxy') };
  }
  if (f.sourceFamilies >= 2) {
    return { tier: 'multi_source', label: formatEvidenceTierLabel('multi_source') };
  }
  if (f.hasProxy) {
    return { tier: 'proxy_only', label: formatEvidenceTierLabel('proxy_only') };
  }
  if (f.hasDns) {
    return { tier: 'dns_only', label: formatEvidenceTierLabel('dns_only') };
  }
  if (f.hasFirewall) {
    return { tier: 'firewall_allowed', label: 'Firewall Evidence' };
  }

  const fallback = breakdown?.evidence_tier || breakdown?.raw?.evidence_tier || 'unknown';
  return { tier: fallback, label: formatEvidenceTierLabel(fallback) };
}

function isBlockedAction(ev = {}) {
  const action = String(ev.action || '').toLowerCase();
  return ['deny', 'denied', 'drop', 'dropped', 'block', 'blocked', 'reject', 'rejected'].includes(action);
}

export function deriveExplanationActionOutcome(context = {}, breakdown = {}) {
  const accepted = Math.max(Number(context?.accepted_connections ?? breakdown?.accepted_connections ?? 0), 0);
  const blocked = Math.max(Number(context?.blocked_connections ?? breakdown?.blocked_connections ?? 0), 0);
  const f = collectEventFamilies(context);

  const eventRows = [];
  if (Array.isArray(context?.explanation_events)) eventRows.push(...context.explanation_events);
  if (Array.isArray(context?.sample_events)) eventRows.push(...context.sample_events);

  const proxyAccessObserved = eventRows.some((row) => isProxyAccessObservedEvent(row));
  const proxyFailed = eventRows.some((row) => isProxyFailedEvent(row));
  const blockedObserved = eventRows.some((row) => isBlockedAction(normalizeEventRow(row)));

  if (accepted > 0) return { outcome: 'allowed', label: formatActionOutcomeLabel('allowed') };
  if (blocked > 0 || (blockedObserved && accepted === 0)) {
    return { outcome: 'blocked', label: formatActionOutcomeLabel('blocked') };
  }
  if (proxyFailed) {
    return { outcome: 'proxy_failed', label: formatActionOutcomeLabel('proxy_failed') };
  }
  if (proxyAccessObserved || (f.hasProxy && accepted > 0)) {
    return { outcome: 'observed_access', label: formatActionOutcomeLabel('observed_access') };
  }
  if (f.hasDns && !f.hasProxy && accepted === 0 && blocked === 0) {
    return { outcome: 'dns_observed', label: formatActionOutcomeLabel('dns_observed') };
  }
  if (f.hasProxy) {
    return { outcome: 'unknown', label: formatActionOutcomeLabel('unknown') };
  }

  const fallback = breakdown?.action_outcome || 'unknown';
  return { outcome: fallback, label: formatActionOutcomeLabel(fallback) };
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
  const evidence = deriveExplanationEvidenceTier(context, breakdown);
  const action = deriveExplanationActionOutcome(context, breakdown);

  const notes = [
    'Risk score reflects environment impact, evidence type, action outcome, analyst verdict, and IOC type.'
  ];

  if (evidence.tier === 'dns_proxy' || evidence.tier === 'multi_source') {
    notes.push(`Evidence summary: ${evidence.label} based on detection event source types in this incident.`);
  }
  if (action.outcome === 'observed_access') {
    notes.push('Proxy telemetry indicates successful or allowed access was observed.');
  } else if (action.outcome === 'proxy_failed') {
    notes.push('Proxy telemetry indicates a failed or error response; this is not confirmed allowed access.');
  } else if (action.outcome === 'dns_observed') {
    notes.push('Only DNS query/resolution activity was observed without confirmed allowed network access.');
  }

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
      explanation: action.label === 'Observed Access'
        ? 'Observed proxy or allowed access increases risk more than blocked-only observations.'
        : 'Allowed connections increase risk more than blocked-only observations.'
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
    evidence_tier: evidence.tier,
    evidence_tier_label: evidence.label,
    action_outcome: action.outcome,
    action_outcome_label: action.label,
    components: componentList,
    notes,
    model: breakdown.model || null,
    summary_reason: breakdown.reason || null
  };
}
