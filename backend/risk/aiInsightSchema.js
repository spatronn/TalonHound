export const THREAT_CLASSES = Object.freeze([
  'phishing',
  'malware',
  'c2',
  'scanner',
  'suspicious_infra',
  'brute_force',
  'exfiltration',
  'ransomware',
  'crypto_mining',
  'test',
  'unknown'
]);

export const PRIMARY_THREAT_CLASSES = Object.freeze([
  'phishing',
  'malware',
  'c2',
  'scanner',
  'suspicious_infra',
  'test',
  'unknown'
]);

export const IMPACT_LEVELS = Object.freeze(['low', 'medium', 'high', 'critical', 'unknown']);
export const EVIDENCE_STRENGTHS = Object.freeze(['weak', 'moderate', 'strong']);

export const MISSING_CONTEXT_VALUES = Object.freeze([
  'vt_missing',
  'rdap_missing',
  'proxy_action_unknown',
  'no_related_logs',
  'no_endpoint_context',
  'low_source_confidence',
  'no_tags',
  'unknown_threat_class'
]);

export const RECOMMENDED_CONTROLS = Object.freeze([
  'user_awareness',
  'email_gateway',
  'web_gateway',
  'dns_security',
  'endpoint_detection',
  'firewall_egress',
  'waf_hardening',
  'threat_intel_coverage',
  'log_quality',
  'incident_response_process'
]);

export const SAFE_RECOMMENDED_ACTIONS = Object.freeze([
  'review_related_logs',
  'refresh_virustotal',
  'refresh_rdap',
  'run_retro_search',
  'search_same_root_domain',
  'review_proxy_allow_block',
  'review_host_history',
  'review_email_gateway_logs'
]);

export const POSTURE_LEVELS = Object.freeze(['low', 'moderate', 'elevated', 'high', 'critical']);
export const RECOMMENDATION_PRIORITIES = Object.freeze(['low', 'medium', 'high']);

const DISALLOWED_ACTION_RE = /\b(suppress|close|block|delete|expire|isolate|quarantine|disable|remove|auto|automatically)\b/i;

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value == null || value === '') return [];
  return [value];
}

function cleanText(value, max = 220) {
  if (value == null || typeof value === 'object' || typeof value === 'function') return '';
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

function normalizeEnum(value, allowed, fallback) {
  const raw = String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
  return allowed.includes(raw) ? raw : fallback;
}

function uniqueControlled(values, allowed, max = 12) {
  const out = [];
  for (const value of asArray(values)) {
    const normalized = normalizeEnum(value, allowed, null);
    if (normalized && !out.includes(normalized)) out.push(normalized);
    if (out.length >= max) break;
  }
  return out;
}

function uniqueStrings(values, max = 8) {
  const out = [];
  for (const value of asArray(values)) {
    const text = cleanText(value, 120);
    if (text && !DISALLOWED_ACTION_RE.test(text) && !out.includes(text)) out.push(text);
    if (out.length >= max) break;
  }
  return out;
}

export function normalizePrimaryThreatClass(value) {
  return normalizeEnum(value, PRIMARY_THREAT_CLASSES, 'unknown');
}

export function deriveThreatClassFromContext(context = {}) {
  const direct = normalizeEnum(
    context?.ioc_metadata?.primary_threat_classification
      || context?.primary_threat_classification
      || context?.playbook_coverage?.ti_classification,
    THREAT_CLASSES,
    null
  );
  if (direct) return direct;
  const haystack = [
    context?.ioc_metadata?.category,
    ...(asArray(context?.ioc_metadata?.tags)),
    ...(asArray(context?.tags)),
    context?.ioc,
    context?.ioc_type
  ].join(' ').toLowerCase();
  if (/\bphish|credential|login\b/.test(haystack)) return 'phishing';
  if (/\bmalware|trojan|loader|stealer\b/.test(haystack)) return 'malware';
  if (/\bc2\b|command.?and.?control|botnet/.test(haystack)) return 'c2';
  if (/\bscan|scanner|recon\b/.test(haystack)) return 'scanner';
  if (/\btest|smoke\b/.test(haystack)) return 'test';
  if (/\bsuspicious|infra|hosting\b/.test(haystack)) return 'suspicious_infra';
  return 'unknown';
}

export function deriveMissingContext(context = {}) {
  const missing = new Set();
  const tags = asArray(context?.ioc_metadata?.tags || context?.tags);
  const threatClass = deriveThreatClassFromContext(context);
  if (!tags.length) missing.add('no_tags');
  if (threatClass === 'unknown') missing.add('unknown_threat_class');
  if (!context?.threat_intel?.virustotal?.available) missing.add('vt_missing');
  if ((context?.ioc_type === 'domain' || context?.ioc_type === 'url') && !context?.threat_intel?.rdap?.available) missing.add('rdap_missing');
  const env = context?.environment_impact || {};
  if (Number(env.detection_events_count || 0) <= 0) missing.add('no_related_logs');
  if (Number(env.unknown_count || 0) > 0 && Number(env.allowed_count || 0) === 0 && Number(env.blocked_count || 0) === 0) missing.add('proxy_action_unknown');
  if (!context?.playbook_coverage?.endpoint_process_evidence && !context?.playbook_coverage?.has_endpoint_evidence) missing.add('no_endpoint_context');
  if (String(context?.ioc_metadata?.confidence || '').toLowerCase() === 'low') missing.add('low_source_confidence');
  return [...missing].filter((x) => MISSING_CONTEXT_VALUES.includes(x));
}

export function normalizeStructuredAiInsight(raw = {}, context = {}) {
  const source = raw?.ai_insight && typeof raw.ai_insight === 'object' ? raw.ai_insight : raw;
  const threatClass = normalizeEnum(source?.threat_class, THREAT_CLASSES, deriveThreatClassFromContext(context));
  const confidenceRaw = Number(source?.confidence_score ?? (Number(source?.confidence) * 100));
  const missing = new Set([
    ...deriveMissingContext(context),
    ...uniqueControlled(source?.missing_context, MISSING_CONTEXT_VALUES)
  ]);
  if (threatClass === 'unknown') missing.add('unknown_threat_class');
  return {
    summary: cleanText(source?.summary || source?.reason || raw?.reason || 'AI insight generated from available IOC and environment context.', 520),
    threat_class: threatClass,
    confidence_score: Math.max(0, Math.min(100, Number.isFinite(confidenceRaw) ? Math.round(confidenceRaw) : 0)),
    impact_level: normalizeEnum(source?.impact_level || source?.ai_risk_level, IMPACT_LEVELS, 'unknown'),
    evidence_strength: normalizeEnum(source?.evidence_strength, EVIDENCE_STRENGTHS, 'weak'),
    risk_drivers: uniqueStrings(source?.risk_drivers || source?.main_risk_drivers, 8),
    risk_reducers: uniqueStrings(source?.risk_reducers || source?.risk_reducing_factors, 8),
    missing_context: [...missing],
    recommended_controls: uniqueControlled(source?.recommended_controls, RECOMMENDED_CONTROLS, 8),
    recommended_actions: uniqueControlled(source?.recommended_actions, SAFE_RECOMMENDED_ACTIONS, 8)
  };
}

export function normalizeEnvironmentInsightOutput(raw = {}, inputSummary = {}) {
  const source = raw && typeof raw === 'object' ? raw : {};
  const topRecommendations = asArray(source.top_recommendations).map((item) => ({
    control_area: normalizeEnum(item?.control_area, RECOMMENDED_CONTROLS, 'log_quality'),
    recommendation: cleanText(item?.recommendation, 220),
    reason: cleanText(item?.reason, 220),
    priority: normalizeEnum(item?.priority, RECOMMENDATION_PRIORITIES, 'medium')
  })).filter((item) => item.recommendation).slice(0, 5);

  const threatDist = inputSummary?.threat_class_distribution || [];
  const dominantThreat = threatDist[0]?.key || threatDist[0]?.threat_class || 'unknown';
  return {
    executive_summary: cleanText(source.executive_summary || 'Environment insight generated from aggregate detection, incident, and AI insight metrics.', 900),
    posture_level: normalizeEnum(source.posture_level, POSTURE_LEVELS, 'moderate'),
    primary_exposure: cleanText(source.primary_exposure || `${dominantThreat}-weighted environment`, 180),
    key_findings: uniqueStrings(source.key_findings, 8),
    risk_score_explanation: {
      why_score_is_high_or_low: cleanText(source?.risk_score_explanation?.why_score_is_high_or_low, 500),
      main_risk_drivers: uniqueStrings(source?.risk_score_explanation?.main_risk_drivers, 6),
      main_risk_reducers: uniqueStrings(source?.risk_score_explanation?.main_risk_reducers, 6)
    },
    top_recommendations: topRecommendations,
    visibility_gaps: uniqueStrings(source.visibility_gaps, 8),
    trend_notes: cleanText(source.trend_notes || 'Insufficient trend data for prior-period comparison.', 260)
  };
}
