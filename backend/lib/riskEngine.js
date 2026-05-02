function clamp(value, min = 0, max = 100) {
  return Math.min(Math.max(Number(value) || 0, min), max);
}
const MAX_REASON_LENGTH = Math.max(Number(process.env.LLM_RISK_REASON_MAX_LENGTH || 1200), 240);

function normalizeVerdict(v) {
  const s = String(v || '').trim().toLowerCase();
  if (s === 'fp') return 'FP';
  if (s === 'tp') return 'TP';
  if (s === 'suspicious') return 'Suspicious';
  if (s === 'in progress' || s === 'in_progress') return 'In Progress';
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
  return 0.4; // Unknown -> light neutral contribution
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

export function calculateIncidentRisk(incident) {
  const verdict = normalizeVerdict(incident?.verdict);
  const totalHits = Math.max(Number(incident?.total_hits || 0), 0);
  const observedHosts = Math.max(Number(incident?.asset_count || 0), 0);

  if (verdict === 'FP') {
    return {
      risk_score: 0,
      risk_breakdown: {
        model: 'incident-risk-central-2026-05-calibrated',
        bounded_range: '0-90',
        verdict,
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
          action: incident?.action || null,
          detection_type: incident?.detection_type || null
        }
      }
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

  const baseScore = 10;
  const hitsSignal = Math.log1p(totalHits) * 5;
  const observedHostsSignal = Math.log1p(observedHosts) * 10;

  const acceptedConnections = Math.max(Number(incident?.accepted_connections || 0), 0);
  const blockedConnections = Math.max(Number(incident?.blocked_connections || 0), 0);
  const actionSignal = acceptedConnections > blockedConnections ? 10 : blockedConnections > 0 ? 2 : 0;

  const detectionTypeRaw = String(incident?.detection_type || '').trim().toLowerCase();
  const detectionTypeSignal = detectionTypeRaw === 'realtime' ? 5 : detectionTypeRaw === 'retro' ? 2 : 0;

  const confidenceRaw = String(incident?.confidence || '').trim().toLowerCase();
  const confidenceSignalScore = confidenceRaw === 'high' ? 10 : confidenceRaw === 'medium' ? 5 : confidenceRaw === 'low' ? 2 : 0;

  const verdictSignal = verdict === 'TP' ? 20 : verdict === 'Suspicious' ? 10 : 0;

  const iocType = String(incident?.ioc_type || '').trim().toLowerCase();
  const iocTypeBonus = iocType === 'sha256' ? 25 : (iocType === 'domain' || iocType === 'url') ? 10 : 0;

  let score = baseScore + hitsSignal + observedHostsSignal + actionSignal + detectionTypeSignal + confidenceSignalScore + verdictSignal + iocTypeBonus;
  if (!Number.isFinite(score)) score = 0;
  score = Math.min(score, 90);
  score = clamp(score, 0, 90);

  return {
    risk_score: Number(score.toFixed(2)),
    risk_breakdown: {
      model: 'incident-risk-central-2026-05-calibrated',
      bounded_range: '0-90',
      verdict,
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
        blocked_connections: blockedConnections
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
  if (n <= -10) return -1;
  if (n < 0) return -0.5;
  if (n >= 10) return 1;
  if (n > 0) return 0.5;
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

  if (verdict === 'FP') {
    return { contribution: 0, final_contribution: 0, bucket: 'excluded', reason: 'false_positive', recency_multiplier: 0, caps_applied: ['fp_force_zero'], components: {} };
  }

  const confidenceWeight = confidence === 'high' ? 3 : confidence === 'medium' ? 2 : 1;
  let activityWeight = 1.0;
  if (iocType === 'domain' || activityType === 'dns') activityWeight = 0.5;
  if (iocType === 'url' || activityType === 'url' || activityType === 'proxy') activityWeight = 1.5;
  if (acceptedCount > 0) activityWeight = 4.0;
  if (verdict === 'TP') activityWeight = 6.0;

  const hitFactor = Math.min(Math.log10(totalHits + 1), 5) * 0.4;
  const hostSpread = observedHosts >= 20 ? 2.5 : observedHosts >= 6 ? 1.5 : observedHosts >= 2 ? 0.75 : 0;
  const persistence = durationHours >= 24 * 2 ? 2 : durationHours > 24 ? 1.5 : durationHours >= 12 ? 1 : durationHours >= 1 ? 0.5 : 0;
  const verdictMultiplier = verdict === 'TP' ? 1.3 : verdict === 'Suspicious' ? 0.9 : 0.55;
  const aiDelta = mapAiAdjustmentDelta(incident?.llm_risk_adjustment);

  let raw = ((confidenceWeight + activityWeight + hitFactor + hostSpread + persistence) * verdictMultiplier) + aiDelta;
  const caps = [];

  const blockedOnly = blockedCount > 0 && acceptedCount === 0;
  const dnsOnly = (iocType === 'domain' || activityType === 'dns') && acceptedCount === 0;
  const urlProxy = (iocType === 'url' || activityType === 'url' || activityType === 'proxy');
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
      raw += 1.5;
      if (raw > 6.0 && verdict !== 'TP') { raw = 6.0; caps.push('ip_accepted_non_tp_cap_6'); }
    } else if (blockedOnly) {
      raw = Math.min(raw, 2.0);
      caps.push('ip_blocked_only_cap_2');
    } else if (unknownOutcome) {
      raw = Math.min(raw, 2.5);
      caps.push('ip_unknown_outcome_cap_2_5');
    }
  }

  const recency = getRecencyMultiplier(incident?.last_seen);
  const finalContribution = Math.max(0, raw * recency);

  return {
    contribution: raw,
    final_contribution: finalContribution,
    bucket: String(incident?.status || '').toLowerCase() === 'open' ? 'open' : 'closed_decay',
    reason: 'quality_weighted_contribution',
    recency_multiplier: recency,
    caps_applied: caps,
    components: { confidenceWeight, activityWeight, hitFactor: Number(hitFactor.toFixed(4)), hostSpread, persistence, verdictMultiplier, aiDelta }
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
      _decay_factor: meta.decay_factor,
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

  const totalNormalized = contributingRows.reduce((acc, r) => acc + Number(r._final_contribution || 0), 0);
  const riskScoreScale = Math.max(Number(process.env.RISK_SCORE_SCALE || 35), 1);
  let institutionRisk = 100 * (1 - Math.exp(-(totalNormalized / riskScoreScale)));

  const strongEvidenceCount = processed.filter((r) => {
    const v = normalizeVerdict(r?.verdict);
    const accepted = Number(r?.accepted_connections || 0) > 0;
    const highConf = String(r?.confidence || '').toLowerCase() === 'high' && Number(r?.asset_count || 0) >= 2;
    return v === 'TP' || accepted || highConf;
  }).length;

  // STEP 5: safety guards
  if (!Number.isFinite(institutionRisk)) institutionRisk = 0;
  institutionRisk = clamp(institutionRisk, 0, 100);

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

  let institutionRiskLabel = institutionRisk >= 80 ? 'CRITICAL' : institutionRisk >= 60 ? 'HIGH' : institutionRisk >= 35 ? 'MEDIUM' : 'LOW';
  if (strongEvidenceCount === 0 && (institutionRiskLabel === 'HIGH' || institutionRiskLabel === 'CRITICAL')) institutionRiskLabel = 'ELEVATED';

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
      normalized_contribution_input: Number(totalNormalized.toFixed(6)),
      normalization_formula: '1 - exp(-incident_risk/50)',
      saturation_formula: '100 * (1 - exp(-sum_normalized/5))',
      low_incident_dampening: contributingCount > 0 && contributingCount < 5 ? 0.6 : 1,
      llm_adjustment_aggregate: llmAdjustmentAggregate,
      top_contributing_incidents: topContributing
    }
  };
}
