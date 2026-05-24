function clamp(value, min = 0, max = 100) {
  return Math.min(Math.max(Number(value) || 0, min), max);
}
const MAX_REASON_LENGTH = Math.max(Number(process.env.LLM_RISK_REASON_MAX_LENGTH || 1200), 240);

const LOW_EVIDENCE_TIERS = new Set(['dns_only', 'blocked_only', 'generic_only', 'unknown']);

export function normalizeVerdict(v) {
  const s = String(v || '').trim().toLowerCase().replace(/_/g, ' ');
  if (s === 'fp' || s === 'false positive') return 'FP';
  if (s === 'tp') return 'TP';
  if (s === 'suspicious') return 'Suspicious';
  if (s === 'in progress') return 'In Progress';
  return 'Unreviewed';
}

function verdictBoost(verdict) {
  const v = normalizeVerdict(verdict);
  if (v === 'TP') return 8;
  if (v === 'Suspicious') return 3;
  if (v === 'In Progress') return 1;
  return 0;
}

function confidenceSignal(confidenceRaw) {
  const c = String(confidenceRaw || '').trim().toLowerCase();
  if (c === 'high') return 1;
  if (c === 'medium') return 0.6;
  if (c === 'low') return 0.3;
  return 0.4;
}

function evidenceStrengthLabel(tier) {
  const map = {
    false_positive: 'none',
    generic_only: 'very_low',
    unknown: 'very_low',
    dns_only: 'low',
    blocked_only: 'low',
    proxy_only: 'medium',
    proxy_allowed: 'medium_high',
    firewall_allowed: 'high',
    multi_source_network: 'high',
    endpoint_or_file: 'very_high'
  };
  return map[tier] || 'medium';
}

export function collectEvidenceSignals(incident = {}) {
  const iocType = String(incident?.ioc_type || '').toLowerCase();
  const accepted = Math.max(Number(incident?.accepted_connections || 0), 0);
  const blocked = Math.max(Number(incident?.blocked_connections || 0), 0);
  const hosts = Math.max(Number(incident?.asset_count || 0), 0);

  const src = String(incident?.source_type || incident?.dominant_source_type || '').toLowerCase();
  const parser = String(incident?.parser_source || incident?.dominant_parser_source || '').toLowerCase();
  const haystack = `${src} ${parser}`;

  const sourceTypes = incident?.event_summary?.source_types && typeof incident.event_summary.source_types === 'object'
    ? incident.event_summary.source_types
    : {};
  const stCount = (key) => Math.max(Number(sourceTypes[key] || 0), 0);

  const hasEndpoint = Boolean(incident?.has_endpoint_evidence)
    || /(endpoint|edr|xdr|sysmon|process|file|hash)/.test(haystack)
    || ['sha256', 'md5', 'sha1', 'imphash', 'tlsh', 'ssdeep'].includes(iocType);
  const hasProxy = Boolean(incident?.has_proxy_evidence)
    || /(proxy|squid|web|url)/.test(haystack)
    || stCount('proxy') > 0
    || stCount('squid_proxy') > 0
    || iocType === 'url';
  const hasDns = Boolean(incident?.has_dns_evidence)
    || /(dns|bind_dns|resolver|dns_kv)/.test(haystack)
    || stCount('dns') > 0
    || iocType === 'domain';
  const hasFirewall = Boolean(incident?.has_firewall_evidence)
    || /(firewall|forti|palo|pan-os|checkpoint|traffic|netflow)/.test(haystack)
    || stCount('firewall') > 0
    || iocType === 'ip'
    || iocType === 'ip6';

  const unknownHeavy = (!src || src === 'generic' || src === 'unknown')
    && (!parser || parser === 'unknown')
    && !hasEndpoint
    && !hasProxy
    && !hasDns
    && !hasFirewall;

  const sourceFamilies = [hasEndpoint, hasProxy, hasDns, hasFirewall].filter(Boolean).length;

  return {
    iocType,
    accepted,
    blocked,
    hosts,
    hasEndpoint,
    hasProxy,
    hasDns,
    hasFirewall,
    unknownHeavy,
    sourceFamilies
  };
}

export function deriveActionOutcome(accepted, blocked) {
  if (accepted > 0) return 'allowed';
  if (blocked > 0) return 'blocked';
  return 'unknown';
}

export function inferEvidenceTier(incident = {}) {
  const verdict = normalizeVerdict(incident?.verdict);
  if (verdict === 'FP') return 'false_positive';

  const s = collectEvidenceSignals(incident);
  const conf = String(incident?.confidence || '').toLowerCase();
  const hits = Math.max(Number(incident?.total_hits || 0), 0);

  if (s.hasEndpoint) return 'endpoint_or_file';
  if (s.accepted > 0 && s.hasProxy) return 'proxy_allowed';
  if (s.accepted > 0 && s.hasFirewall) return 'firewall_allowed';
  if (s.accepted > 0 && (s.hasDns || s.sourceFamilies >= 2 || s.hosts >= 2)) return 'multi_source_network';
  if (s.accepted > 0) return 'firewall_allowed';
  if (s.sourceFamilies >= 2) return 'multi_source_network';
  if (s.hasDns && s.hasProxy && !s.hasFirewall && !s.hasEndpoint) return 'multi_source_network';
  if (s.hasProxy && s.accepted === 0 && s.blocked === 0) return 'proxy_only';
  if (s.hasDns && !s.hasProxy && !s.hasFirewall && s.accepted === 0 && s.blocked === 0) return 'dns_only';
  if (s.blocked > 0 && s.accepted === 0) return 'blocked_only';
  if (s.unknownHeavy && conf !== 'high' && hits > 0) return 'generic_only';
  if (s.unknownHeavy) return 'unknown';
  if (s.hasProxy) return 'proxy_only';
  if (s.hasDns) return 'dns_only';
  return 'unknown';
}

function getHitContribution(totalHits, tier) {
  const raw = Math.log1p(Math.max(Number(totalHits || 0), 0)) * 3.2;
  const caps = {
    dns_only: 10,
    generic_only: 6,
    unknown: 6,
    blocked_only: 8,
    proxy_only: 15,
    proxy_allowed: 22,
    firewall_allowed: 20,
    multi_source_network: 25,
    endpoint_or_file: 30
  };
  return Math.min(raw, caps[tier] ?? 10);
}

function getLowEvidenceCap(tier, verdict) {
  const isTP = normalizeVerdict(verdict) === 'TP';
  const base = {
    false_positive: 0,
    generic_only: 15,
    unknown: 20,
    dns_only: 25,
    blocked_only: 25,
    proxy_only: 35,
    proxy_allowed: 45,
    firewall_allowed: 45,
    multi_source_network: 60,
    endpoint_or_file: 85
  }[tier] ?? 30;
  return isTP ? Math.min(90, base + 10) : base;
}

function isSecurityTestIncident(incident) {
  const verdict = String(incident?.verdict || '').trim().toLowerCase();
  if (verdict === 'security test' || verdict === 'security_test') return true;

  const haystack = [
    incident?.ioc_value,
    incident?.ioc_type,
    incident?.note,
    incident?.source_name
  ].map((v) => String(v || '').toLowerCase()).join(' ');

  return /\b(eicar|security[\s_-]?test|red[\s_-]?team|purple[\s_-]?team|tabletop|simulation|test[-\s]?ioc)\b/.test(haystack);
}

function buildFpBreakdown(verdict, incident, totalHits, observedHosts) {
  return {
    model: 'incident-risk-central-2026-05-calibrated',
    bounded_range: '0-90',
    verdict,
    evidence_tier: 'false_positive',
    evidence_strength: 'none',
    action_outcome: 'none',
    accepted_connections: 0,
    blocked_connections: 0,
    affected_hosts: observedHosts,
    total_hits: totalHits,
    dns_only_dampening: false,
    blocked_only_dampening: false,
    ai_delta_effective: 0,
    final_score: 0,
    reason: 'false_positive',
    components: {
      base_score: 0,
      hits_signal: 0,
      observed_hosts_signal: 0,
      action_signal: 0,
      detection_type_signal: 0,
      confidence_signal: 0,
      verdict_signal: 0,
      ioc_type_bonus: 0
    },
    raw: {
      total_hits: totalHits,
      observed_hosts: observedHosts,
      ioc_type: incident?.ioc_type || null,
      confidence: incident?.confidence || null,
      detection_type: incident?.detection_type || null
    }
  };
}

export function calculateIncidentRisk(incident) {
  const verdict = normalizeVerdict(incident?.verdict);
  const totalHits = Math.max(Number(incident?.total_hits || 0), 0);
  const observedHosts = Math.max(Number(incident?.asset_count || 0), 0);

  if (verdict === 'FP') {
    return {
      risk_score: 0,
      risk_breakdown: buildFpBreakdown(verdict, incident, totalHits, observedHosts)
    };
  }

  if (isSecurityTestIncident(incident)) {
    const fixed = 8;
    return {
      risk_score: fixed,
      risk_breakdown: {
        model: 'incident-risk-central-2026-05-calibrated',
        bounded_range: '0-90',
        verdict,
        evidence_tier: 'security_test',
        evidence_strength: 'very_low',
        action_outcome: 'unknown',
        accepted_connections: Math.max(Number(incident?.accepted_connections || 0), 0),
        blocked_connections: Math.max(Number(incident?.blocked_connections || 0), 0),
        affected_hosts: observedHosts,
        total_hits: totalHits,
        dns_only_dampening: false,
        blocked_only_dampening: false,
        ai_delta_effective: 0,
        final_score: fixed,
        reason: 'security_test_low_fixed',
        components: {
          base_score: fixed,
          hits_signal: 0,
          observed_hosts_signal: 0,
          action_signal: 0,
          detection_type_signal: 0,
          confidence_signal: 0,
          verdict_signal: 0,
          ioc_type_bonus: 0
        }
      }
    };
  }

  const evidenceTier = inferEvidenceTier(incident);
  const evidenceStrength = evidenceStrengthLabel(evidenceTier);
  const baseScore = 8;
  const hitsSignal = getHitContribution(totalHits, evidenceTier);
  const observedHostsSignal = Math.min(Math.log1p(observedHosts) * 8, evidenceTier === 'endpoint_or_file' ? 14 : 10);

  const acceptedConnections = Math.max(Number(incident?.accepted_connections || 0), 0);
  const blockedConnections = Math.max(Number(incident?.blocked_connections || 0), 0);
  const actionOutcome = deriveActionOutcome(acceptedConnections, blockedConnections);
  const actionSignal = acceptedConnections > 0 ? 10 : blockedConnections > 0 ? 3 : 0;

  const detectionTypeRaw = String(incident?.detection_type || '').trim().toLowerCase();
  const detectionTypeSignal = detectionTypeRaw === 'realtime' ? 3 : detectionTypeRaw === 'retro' ? 1 : 0;

  const confidenceRaw = String(incident?.confidence || '').trim().toLowerCase();
  const confidenceSignalScore = confidenceRaw === 'high' ? 8 : confidenceRaw === 'medium' ? 4 : confidenceRaw === 'low' ? 1 : 0;

  const verdictSignal = verdict === 'TP' ? 18 : verdict === 'Suspicious' ? 8 : verdict === 'In Progress' ? 2 : 0;

  const iocType = String(incident?.ioc_type || '').trim().toLowerCase();
  const iocTypeBonus = iocType === 'sha256' ? 20 : (iocType === 'domain' || iocType === 'url') ? 6 : 2;

  let score = baseScore + hitsSignal + observedHostsSignal + actionSignal + detectionTypeSignal + confidenceSignalScore + verdictSignal + iocTypeBonus;
  score = Math.min(score, getLowEvidenceCap(evidenceTier, verdict));
  if (!Number.isFinite(score)) score = 0;
  score = Math.min(score, 90);
  score = clamp(score, 0, 90);

  const dnsOnlyDampening = evidenceTier === 'dns_only';
  const blockedOnlyDampening = evidenceTier === 'blocked_only';

  return {
    risk_score: Number(score.toFixed(2)),
    risk_breakdown: {
      model: 'incident-risk-central-2026-05-calibrated',
      bounded_range: '0-90',
      verdict,
      evidence_tier: evidenceTier,
      evidence_strength: evidenceStrength,
      action_outcome: actionOutcome,
      accepted_connections: acceptedConnections,
      blocked_connections: blockedConnections,
      affected_hosts: observedHosts,
      total_hits: totalHits,
      dns_only_dampening: dnsOnlyDampening,
      blocked_only_dampening: blockedOnlyDampening,
      ai_delta_effective: 0,
      final_score: Number(score.toFixed(2)),
      reason: `${evidenceStrength} evidence (${evidenceTier}); outcome=${actionOutcome}`,
      components: {
        base_score: Number(baseScore.toFixed(2)),
        hits_signal: Number(hitsSignal.toFixed(2)),
        observed_hosts_signal: Number(observedHostsSignal.toFixed(2)),
        action_signal: Number(actionSignal.toFixed(2)),
        detection_type_signal: Number(detectionTypeSignal.toFixed(2)),
        confidence_signal: Number(confidenceSignalScore.toFixed(2)),
        verdict_signal: Number(verdictSignal.toFixed(2)),
        ioc_type_bonus: Number(iocTypeBonus.toFixed(2))
      },
      raw: {
        total_hits: totalHits,
        observed_hosts: observedHosts,
        ioc_type: iocType || null,
        confidence: confidenceRaw || null,
        detection_type: detectionTypeRaw || null,
        accepted_connections: acceptedConnections,
        blocked_connections: blockedConnections,
        evidence_tier: evidenceTier,
        low_evidence_cap: getLowEvidenceCap(evidenceTier, verdict),
        dominant_source_type: incident?.dominant_source_type || null,
        dominant_parser_source: incident?.dominant_parser_source || null
      }
    }
  };
}

function getClosedDecayFactor(incident, halfLifeDays = 14) {
  const closedRef = new Date(incident?.updated_at || incident?.last_seen || 0).getTime();
  if (!Number.isFinite(closedRef) || closedRef <= 0) return 0.25;

  const ageDays = Math.max((Date.now() - closedRef) / (1000 * 60 * 60 * 24), 0);
  const lambda = Math.log(2) / Math.max(Number(halfLifeDays) || 14, 1);
  const decay = Math.exp(-lambda * ageDays);
  return clamp(decay, 0, 1);
}

function mapAiAdjustmentDelta(rawAdj) {
  const n = Number(rawAdj);
  if (!Number.isFinite(n)) return 0;
  if (n <= -10) return -0.5;
  if (n < 0) return -0.25;
  if (n >= 10) return 0.5;
  if (n > 0) return 0.25;
  return 0;
}

function getRecencyMultiplier(lastSeen) {
  const t = new Date(lastSeen || 0).getTime();
  if (!Number.isFinite(t) || t <= 0) return 0.4;
  const ageDays = Math.max((Date.now() - t) / (1000 * 60 * 60 * 24), 0);
  if (ageDays <= 1) return 1.0;
  if (ageDays <= 7) return 0.7;
  if (ageDays <= 30) return 0.4;
  return 0.2;
}

function getInstitutionContribution(incident) {
  const verdict = normalizeVerdict(incident?.verdict);
  const confidence = String(incident?.confidence || '').trim().toLowerCase();
  const iocType = String(incident?.ioc_type || '').trim().toLowerCase();
  const activityType = String(incident?.activity_type || (iocType === 'domain' ? 'dns' : iocType)).trim().toLowerCase();
  const totalHits = Math.max(Number(incident?.total_hits || 0), 0);
  const observedHosts = Math.max(Number(incident?.asset_count || 0), 0);
  const acceptedCount = Math.max(Number(incident?.accepted_connections || 0), 0);
  const blockedCount = Math.max(Number(incident?.blocked_connections || 0), 0);
  const durationHours = Math.max((new Date(incident?.last_seen || 0).getTime() - new Date(incident?.first_seen || 0).getTime()) / 3600000, 0);
  const isOpen = String(incident?.status || '').toLowerCase() === 'open';

  if (verdict === 'FP') {
    return {
      contribution: 0,
      final_contribution: 0,
      bucket: 'excluded',
      reason: 'false_positive',
      recency_multiplier: 0,
      decay_factor: 0,
      caps_applied: ['fp_force_zero'],
      components: {}
    };
  }

  const evidenceTier = inferEvidenceTier(incident);
  const confidenceWeight = confidence === 'high' ? 2.2 : confidence === 'medium' ? 1.5 : 0.8;
  let activityWeight = 0.8;
  if (iocType === 'domain' || activityType === 'dns') activityWeight = 0.5;
  if (iocType === 'url' || activityType === 'url' || activityType === 'proxy') activityWeight = 1.5;
  if (acceptedCount > 0) activityWeight = 4.0;
  if (verdict === 'TP') activityWeight = 6.0;

  const hitFactor = Math.min(Math.log10(totalHits + 1), 5) * 0.25;
  const hostSpread = observedHosts >= 20 ? 2.0 : observedHosts >= 6 ? 1.2 : observedHosts >= 2 ? 0.6 : 0;
  const persistence = durationHours >= 24 * 2 ? 2 : durationHours > 24 ? 1.5 : durationHours >= 12 ? 1 : durationHours >= 1 ? 0.5 : 0;
  const verdictMultiplier = verdict === 'TP' ? 1.3 : verdict === 'Suspicious' ? 0.9 : 0.55;
  const aiDelta = mapAiAdjustmentDelta(incident?.llm_risk_adjustment);

  let raw = ((confidenceWeight + activityWeight + hitFactor + hostSpread + persistence) * verdictMultiplier) + aiDelta;
  const caps = [];

  const blockedOnly = blockedCount > 0 && acceptedCount === 0;
  const dnsOnly = evidenceTier === 'dns_only';
  const urlProxy = (iocType === 'url' || activityType === 'url' || activityType === 'proxy') || evidenceTier === 'proxy_only' || evidenceTier === 'proxy_allowed';
  const ipIoc = iocType === 'ip' || iocType === 'ip6';
  const unknownOutcome = acceptedCount === 0 && blockedCount === 0;

  if (verdict === 'Unreviewed') {
    if (dnsOnly && raw > 1.5) { raw = 1.5; caps.push('unreviewed_dns_only_cap_1_5'); }
    if (blockedOnly && raw > 2.0) { raw = 2.0; caps.push('unreviewed_blocked_only_cap_2'); }
    if (urlProxy && raw > 3.0) { raw = 3.0; caps.push('unreviewed_url_proxy_cap_3'); }
    if (ipIoc && unknownOutcome && raw > 3.0) { raw = 3.0; caps.push('unreviewed_ip_unknown_outcome_cap_3'); }
  }

  if (ipIoc) {
    if (acceptedCount > 0) {
      raw += 1.0;
      if (verdict !== 'TP' && raw > 4.0) { raw = 4.0; caps.push('ip_accepted_non_tp_cap_4'); }
      if (verdict === 'TP' && raw > 6.0) { raw = 6.0; caps.push('ip_tp_cap_6'); }
    } else if (blockedOnly) {
      raw = Math.min(raw, 1.5);
      caps.push('ip_blocked_only_cap_1_5');
    } else if (unknownOutcome) {
      raw = Math.min(raw, 2.0);
      caps.push('ip_unknown_outcome_cap_2');
    }
  }

  if (urlProxy) {
    if (acceptedCount > 0 && verdict !== 'TP') {
      raw = Math.min(raw, 2.0);
      caps.push('url_accepted_non_tp_cap_2');
    } else if (acceptedCount === 0 && verdict !== 'TP') {
      raw = Math.min(raw, 1.5);
      caps.push('url_match_only_non_tp_cap_1_5');
    }
    if (observedHosts >= 2 && durationHours >= 12 && verdict !== 'TP') {
      raw = Math.min(raw + 0.5, 2.5);
      caps.push('url_persistent_multi_host_bonus_cap_2_5');
    }
    if (verdict === 'TP') raw = Math.min(raw, 5.0);
  }

  if (dnsOnly) {
    if (verdict === 'Unreviewed') {
      raw = Math.min(raw, (observedHosts >= 2 && durationHours >= 12) ? 1.5 : 1.0);
      caps.push('dns_only_unreviewed_cap');
    } else if (verdict === 'TP') {
      raw = Math.min(raw, 4.0);
      caps.push('dns_only_tp_cap_4');
    }
  }

  const tierCaps = {
    generic_only: 0.6,
    unknown: 0.7,
    dns_only: 0.9,
    blocked_only: 1.0,
    proxy_only: 1.6,
    proxy_allowed: 2.4,
    firewall_allowed: 2.2,
    multi_source_network: 3.5,
    endpoint_or_file: 6.0
  };
  const cap = tierCaps[evidenceTier] ?? 1.2;
  if (raw > cap) { raw = cap; caps.push(`tier_cap_${evidenceTier}_${cap}`); }

  const recency = getRecencyMultiplier(incident?.last_seen);
  const decayFactor = isOpen ? 1 : getClosedDecayFactor(incident);
  const finalContribution = Math.max(0, raw * recency * decayFactor);

  return {
    contribution: raw,
    final_contribution: finalContribution,
    bucket: isOpen ? 'open' : 'closed_decay',
    reason: 'quality_weighted_contribution',
    recency_multiplier: recency,
    decay_factor: decayFactor,
    caps_applied: caps,
    components: { confidenceWeight, activityWeight, hitFactor: Number(hitFactor.toFixed(4)), hostSpread, persistence, verdictMultiplier, aiDelta, evidenceTier }
  };
}

function rootDomainLike(v) {
  const s = String(v || '').toLowerCase().trim();
  if (!s) return '';
  const noProto = s.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  const parts = noProto.split('.').filter(Boolean);
  if (parts.length >= 2) return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  return noProto;
}

function buildClusterKey(row) {
  const t = String(row?.ioc_type || '').toLowerCase();
  const ioc = String(row?.ioc_value || '').trim();
  if (t === 'ip' || t === 'ip6') return `ip:${ioc}`;
  if (t === 'domain' || t === 'url') return `domain:${rootDomainLike(ioc)}`;
  return `${t}:${ioc}`;
}

function computeInstitutionDampening(contributingRows = []) {
  const contributingCount = contributingRows.length;
  const lowIncidentDampening = contributingCount > 0 && contributingCount < 5 ? 0.6 : 1;

  const lowQualityCount = contributingRows.filter((r) => LOW_EVIDENCE_TIERS.has(inferEvidenceTier(r))).length;
  const lowQualityRatio = contributingCount > 0 ? lowQualityCount / contributingCount : 0;

  let qualityDampening = 1;
  if (lowQualityRatio >= 0.85) qualityDampening = 0.5;
  else if (lowQualityRatio >= 0.65) qualityDampening = 0.65;
  else if (lowQualityRatio >= 0.5) qualityDampening = 0.8;

  return {
    low_incident_dampening: lowIncidentDampening,
    quality_dampening: qualityDampening,
    combined_dampening: Number((lowIncidentDampening * qualityDampening).toFixed(4)),
    low_quality_incident_count: lowQualityCount,
    low_quality_ratio: Number(lowQualityRatio.toFixed(4))
  };
}

export function calculateInstitutionRisk(incidents) {
  const rows = Array.isArray(incidents) ? incidents : [];
  if (!rows.length) {
    return {
      institution_risk_score: 0,
      active_incident_count: 0,
      top_contributing_incidents: [],
      llm_adjustment_aggregate: null,
      breakdown: {
        model: 'institution-risk-central-2026-04-workflow-decoupled',
        bounded_range: '0-100',
        active_incident_count: 0,
        total_raw_contribution: 0,
        open_incident_contribution: 0,
        closed_decaying_contribution: 0,
        excluded_incident_count: 0,
        normalized_contribution_input: 0,
        normalization_formula: '1 - exp(-incident_risk/50)',
        saturation_formula: '100 * (1 - exp(-sum_normalized/5))',
        low_incident_dampening: 1,
        quality_dampening: 1,
        combined_dampening: 1,
        llm_adjustment_aggregate: null
      }
    };
  }

  const processed = rows.map((r) => {
    const riskScore = clamp(Number(r?.risk_score || 0), 0, 100);
    const meta = getInstitutionContribution({ ...r, risk_score: riskScore });
    return {
      ...r,
      risk_score: Number(riskScore.toFixed(2)),
      _contribution: meta.contribution,
      _final_contribution: Number((meta.final_contribution ?? meta.contribution ?? 0).toFixed(6)),
      _contribution_bucket: meta.bucket,
      _contribution_reason: meta.reason,
      _decay_factor: meta.decay_factor ?? 1,
      _recency_multiplier: meta.recency_multiplier ?? 1,
      _caps_applied: meta.caps_applied || [],
      _components: meta.components || {}
    };
  });

  const openContribution = processed
    .filter((r) => r._contribution_bucket === 'open')
    .reduce((acc, r) => acc + r._final_contribution, 0);
  const closedDecayContribution = processed
    .filter((r) => r._contribution_bucket === 'closed_decay')
    .reduce((acc, r) => acc + r._final_contribution, 0);
  const excludedIncidentCount = processed.filter((r) => r._contribution_bucket === 'excluded').length;

  const totalRawContribution = openContribution + closedDecayContribution;

  const contributingRows = processed.filter((r) => r._final_contribution > 0);
  const contributingCount = contributingRows.length;

  const totalIncidentContribution = contributingRows.reduce((acc, r) => acc + Number(r._final_contribution || 0), 0);

  const clustersMap = new Map();
  for (const r of contributingRows) {
    const key = buildClusterKey(r);
    if (!clustersMap.has(key)) clustersMap.set(key, []);
    clustersMap.get(key).push(r);
  }

  const clusters = [...clustersMap.entries()].map(([cluster_key, rowsIn]) => {
    const sorted = [...rowsIn].sort((a, b) => Number(b._final_contribution || 0) - Number(a._final_contribution || 0));
    const maxContribution = Number(sorted[0]?._final_contribution || 0);
    const others = sorted.slice(1).reduce((acc, r) => acc + Number(r._final_contribution || 0), 0);
    const diminishedExtra = 0.25 * others;
    return {
      cluster_key,
      incidents: sorted.map((x) => x.incident_id),
      max_contribution: Number(maxContribution.toFixed(6)),
      diminished_extra_contribution: Number(diminishedExtra.toFixed(6)),
      final_cluster_contribution: Number((maxContribution + diminishedExtra).toFixed(6)),
      caps_applied: [...new Set(sorted.flatMap((x) => Array.isArray(x._caps_applied) ? x._caps_applied : []))]
    };
  });

  const rankedClusters = [...clusters].sort((a, b) => Number(b.final_cluster_contribution || 0) - Number(a.final_cluster_contribution || 0));
  const rankWeight = (idx) => (idx === 0 ? 1 : idx === 1 ? 0.6 : idx === 2 ? 0.35 : idx <= 9 ? 0.12 : 0.03);
  const weightedClusterTotal = rankedClusters.reduce((acc, c, idx) => acc + Number(c.final_cluster_contribution || 0) * rankWeight(idx), 0);

  const activeNonFpCount = processed.filter((r) => normalizeVerdict(r?.verdict) !== 'FP').length;
  let densityBonus = Math.min(6, Math.log1p(activeNonFpCount) * 1.5);

  const dampening = computeInstitutionDampening(contributingRows);
  if (dampening.low_quality_ratio >= 0.75) {
    densityBonus = Number((densityBonus * 0.5).toFixed(6));
  }

  const clusterTotalBeforeDampening = weightedClusterTotal + densityBonus;
  const clusterTotal = Number((clusterTotalBeforeDampening * dampening.combined_dampening).toFixed(6));

  const riskScoreScale = Math.max(Number(process.env.RISK_SCORE_SCALE || 50), 1);
  let institutionRisk = 100 * (1 - Math.exp(-(clusterTotal / riskScoreScale)));

  const strongEvidenceCount = processed.filter((r) => {
    const v = normalizeVerdict(r?.verdict);
    const accepted = Number(r?.accepted_connections || 0) > 0;
    const tier = inferEvidenceTier(r);
    const highConf = String(r?.confidence || '').toLowerCase() === 'high' && Number(r?.asset_count || 0) >= 2;
    return v === 'TP' || accepted || highConf || tier === 'endpoint_or_file' || tier === 'proxy_allowed' || tier === 'firewall_allowed';
  }).length;

  if (!Number.isFinite(institutionRisk)) institutionRisk = 0;
  institutionRisk = clamp(institutionRisk, 0, 100);

  if (strongEvidenceCount === 0) {
    institutionRisk = Math.min(institutionRisk, 55);
  }
  if (dampening.low_quality_ratio >= 0.85) {
    institutionRisk = Math.min(institutionRisk, 65);
  }

  const topContributing = [...processed]
    .sort((a, b) => b._final_contribution - a._final_contribution)
    .filter((r) => r._final_contribution > 0)
    .map((r, idx) => {
      const riskBeforeLlmRaw = Number(r?.risk_before_llm);
      const llmAdjustmentRaw = Number(r?.llm_risk_adjustment);
      const llmConfidenceRaw = Number(r?.llm_risk_confidence);
      const finalRiskRaw = Number(r?.final_risk_score);

      return {
        id: r.id,
        incident_id: r.incident_id,
        ioc_value: r.ioc_value,
        risk_score: r.risk_score,
        risk_before_llm: Number.isFinite(riskBeforeLlmRaw) ? Number(riskBeforeLlmRaw.toFixed(2)) : null,
        llm_risk_adjustment: Number.isFinite(llmAdjustmentRaw) ? llmAdjustmentRaw : null,
        llm_risk_confidence: Number.isFinite(llmConfidenceRaw) ? Number(llmConfidenceRaw.toFixed(3)) : null,
        llm_risk_reason: r?.llm_risk_reason != null ? String(r.llm_risk_reason).slice(0, MAX_REASON_LENGTH) : null,
        final_risk_score: Number.isFinite(finalRiskRaw) ? Number(finalRiskRaw.toFixed(2)) : null,
        contribution: Number(r._final_contribution.toFixed(6)),
        raw_contribution: Number((r._contribution || 0).toFixed(6)),
        contribution_bucket: r._contribution_bucket,
        decay_factor: Number((r._decay_factor || 0).toFixed(6)),
        recency_multiplier: Number((r._recency_multiplier || 1).toFixed(3)),
        caps_applied: Array.isArray(r._caps_applied) ? r._caps_applied : [],
        components: r._components || {},
        total_hits: Number(r?.total_hits || 0),
        observed_hosts: Number(r?.asset_count || 0),
        activity_type: String(r?.activity_type || r?.ioc_type || ''),
        accepted_count: Number(r?.accepted_connections || 0),
        blocked_count: Number(r?.blocked_connections || 0),
        confidence: r?.confidence || null,
        verdict: normalizeVerdict(r?.verdict),
        rank: idx + 1
      };
    });

  const activeIncidentCount = processed.filter((r) => String(r.status || '').toLowerCase() === 'open').length;

  const llmRows = processed.filter((r) => Number.isFinite(Number(r?.llm_risk_adjustment)));
  const llmAdjustmentTotal = llmRows.reduce((acc, r) => acc + Number(r?.llm_risk_adjustment || 0), 0);
  const llmConfidenceAvg = llmRows.length
    ? llmRows.reduce((acc, r) => acc + Math.min(Math.max(Number(r?.llm_risk_confidence || 0), 0), 1), 0) / llmRows.length
    : null;
  const llmAdjustmentAggregate = llmRows.length
    ? {
      enabled: true,
      total_adjustment: Number(llmAdjustmentTotal.toFixed(2)),
      avg_confidence: llmConfidenceAvg == null ? null : Number(llmConfidenceAvg.toFixed(3)),
      incident_count: llmRows.length
    }
    : null;

  let institutionRiskLabel = institutionRisk >= 80 ? 'CRITICAL' : institutionRisk >= 60 ? 'HIGH' : institutionRisk >= 40 ? 'MEDIUM' : institutionRisk >= 20 ? 'GUARDED' : 'LOW';
  if (strongEvidenceCount === 0 && (institutionRiskLabel === 'HIGH' || institutionRiskLabel === 'CRITICAL')) {
    institutionRiskLabel = 'MEDIUM';
  }

  return {
    institution_risk_score: Number(institutionRisk.toFixed(2)),
    institution_risk_label: institutionRiskLabel,
    active_incident_count: activeIncidentCount,
    top_contributing_incidents: topContributing,
    llm_adjustment_aggregate: llmAdjustmentAggregate,
    breakdown: {
      model: 'institution-risk-central-2026-04-workflow-decoupled',
      bounded_range: '0-100',
      active_incident_count: activeIncidentCount,
      total_raw_contribution: Number(totalRawContribution.toFixed(6)),
      open_incident_contribution: Number(openContribution.toFixed(6)),
      closed_decaying_contribution: Number(closedDecayContribution.toFixed(6)),
      excluded_incident_count: excludedIncidentCount,
      total_raw_incident_contribution: Number(totalIncidentContribution.toFixed(6)),
      total_clustered_contribution: Number(clusterTotal.toFixed(6)),
      cluster_total_before_dampening: Number(clusterTotalBeforeDampening.toFixed(6)),
      weighted_cluster_total: Number(weightedClusterTotal.toFixed(6)),
      density_bonus: Number(densityBonus.toFixed(6)),
      cluster_count: clusters.length,
      clusters,
      normalized_contribution_input: Number(clusterTotal.toFixed(6)),
      normalization_formula: 'cluster_score = max + 0.25 * sum(others)',
      saturation_formula: '100 * (1 - exp(-cluster_total / RISK_SCORE_SCALE))',
      low_incident_dampening: dampening.low_incident_dampening,
      quality_dampening: dampening.quality_dampening,
      combined_dampening: dampening.combined_dampening,
      low_quality_incident_count: dampening.low_quality_incident_count,
      low_quality_ratio: dampening.low_quality_ratio,
      strong_evidence_count: strongEvidenceCount,
      llm_adjustment_aggregate: llmAdjustmentAggregate,
      top_contributing_incidents: topContributing
    }
  };
}
