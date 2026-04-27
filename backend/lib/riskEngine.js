function clamp(value, min = 0, max = 100) {
  return Math.min(Math.max(Number(value) || 0, min), max);
}

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
  const eventCount = Math.max(Number(incident?.event_count || 0), 0);
  const assetCount = Math.max(Number(incident?.asset_count || 0), 0);
  const spreadInput = Math.max(eventCount, assetCount, 0);

  if (verdict === 'FP') {
    return {
      risk_score: 0,
      risk_breakdown: {
        model: 'incident-risk-central-2026-04',
        bounded_range: '0-100',
        verdict,
        reason: 'false_positive',
        components: {
          activity_signal: 0,
          spread_signal: 0,
          recency_signal: 0,
          confidence_signal: 0,
          verdict_boost: 0
        },
        raw: {
          total_hits: totalHits,
          event_count: eventCount,
          asset_count: assetCount,
          last_seen: incident?.last_seen || null,
          confidence: incident?.confidence || null
        }
      }
    };
  }

  if (isSecurityTestIncident(incident)) {
    const fixed = 8;
    return {
      risk_score: fixed,
      risk_breakdown: {
        model: 'incident-risk-central-2026-04',
        bounded_range: '0-100',
        verdict,
        reason: 'security_test_low_fixed',
        components: {
          activity_signal: 0,
          spread_signal: 0,
          recency_signal: 0,
          confidence_signal: 0,
          verdict_boost: 0
        },
        raw: {
          total_hits: totalHits,
          event_count: eventCount,
          asset_count: assetCount,
          last_seen: incident?.last_seen || null,
          confidence: incident?.confidence || null
        }
      }
    };
  }

  const activityNorm = clamp(Math.log1p(totalHits) / Math.log1p(500), 0, 1);
  const spreadNorm = clamp(Math.log1p(spreadInput) / Math.log1p(100), 0, 1);

  const lastSeenMs = new Date(incident?.last_seen || 0).getTime();
  const ageHours = Number.isFinite(lastSeenMs) && lastSeenMs > 0
    ? Math.max((Date.now() - lastSeenMs) / (1000 * 60 * 60), 0)
    : 24 * 30;
  const recencyNorm = clamp(Math.exp(-ageHours / 72), 0, 1);

  const confidenceNorm = confidenceSignal(incident?.confidence);

  const activitySignal = activityNorm * 45;
  const spreadSignal = spreadNorm * 25;
  const recencySignal = recencyNorm * 20;
  const confidenceSignalScore = confidenceNorm * 10;
  const boost = verdictBoost(verdict);

  const rawScore = activitySignal + spreadSignal + recencySignal + confidenceSignalScore + boost;
  const riskScore = clamp(rawScore, 0, 100);

  return {
    risk_score: Number(riskScore.toFixed(2)),
    risk_breakdown: {
      model: 'incident-risk-central-2026-04',
      bounded_range: '0-100',
      verdict,
      components: {
        activity_signal: Number(activitySignal.toFixed(2)),
        spread_signal: Number(spreadSignal.toFixed(2)),
        recency_signal: Number(recencySignal.toFixed(2)),
        confidence_signal: Number(confidenceSignalScore.toFixed(2)),
        verdict_boost: Number(boost.toFixed(2))
      },
      normalized: {
        activity: Number(activityNorm.toFixed(4)),
        spread: Number(spreadNorm.toFixed(4)),
        recency: Number(recencyNorm.toFixed(4)),
        confidence: Number(confidenceNorm.toFixed(4))
      },
      raw: {
        total_hits: totalHits,
        event_count: eventCount,
        asset_count: assetCount,
        age_hours: Number(ageHours.toFixed(2)),
        last_seen: incident?.last_seen || null,
        confidence: incident?.confidence || null
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

function getInstitutionContribution(incident) {
  const status = String(incident?.status || '').trim().toLowerCase();
  const verdict = normalizeVerdict(incident?.verdict);
  const riskScore = clamp(Number(incident?.risk_score || 0), 0, 100);

  if (verdict === 'FP') {
    return { contribution: 0, bucket: 'excluded', reason: 'false_positive', decay_factor: 0 };
  }

  if (isSecurityTestIncident(incident)) {
    return { contribution: 0.02, bucket: status === 'open' ? 'open' : 'closed_decay', reason: 'security_test', decay_factor: status === 'closed' ? getClosedDecayFactor(incident) : 1 };
  }

  const normalizedRisk = riskScore / 100;
  const base = Math.pow(normalizedRisk, 2);

  if (status === 'open') {
    return { contribution: base, bucket: 'open', reason: 'open_incident', decay_factor: 1 };
  }

  if (status === 'closed' && (verdict === 'TP' || verdict === 'Suspicious')) {
    const decay = getClosedDecayFactor(incident);
    return { contribution: base * decay, bucket: 'closed_decay', reason: 'closed_with_decay', decay_factor: Number(decay.toFixed(6)) };
  }

  return { contribution: 0, bucket: 'excluded', reason: 'closed_non_risky_or_unreviewed', decay_factor: 0 };
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
        exponent: 2,
        normalization_lambda: 2.4,
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
      _contribution_bucket: meta.bucket,
      _contribution_reason: meta.reason,
      _decay_factor: meta.decay_factor
    };
  });

  const openContribution = processed
    .filter((r) => r._contribution_bucket === 'open')
    .reduce((acc, r) => acc + r._contribution, 0);
  const closedDecayContribution = processed
    .filter((r) => r._contribution_bucket === 'closed_decay')
    .reduce((acc, r) => acc + r._contribution, 0);
  const excludedIncidentCount = processed.filter((r) => r._contribution_bucket === 'excluded').length;

  const totalRawContribution = openContribution + closedDecayContribution;

  const contributingCount = Math.max(processed.length - excludedIncidentCount, 1);
  const normalizedContributionInput = totalRawContribution / Math.sqrt(contributingCount);
  const lambda = 2.4;
  const institutionRisk = clamp(100 * (1 - Math.exp(-lambda * normalizedContributionInput)), 0, 100);

  const topContributing = [...processed]
    .sort((a, b) => b._contribution - a._contribution)
    .filter((r) => r._contribution > 0)
    .slice(0, 5)
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
        llm_risk_reason: r?.llm_risk_reason != null ? String(r.llm_risk_reason).slice(0, 240) : null,
        final_risk_score: Number.isFinite(finalRiskRaw) ? Number(finalRiskRaw.toFixed(2)) : null,
        contribution: Number(r._contribution.toFixed(6)),
        contribution_bucket: r._contribution_bucket,
        decay_factor: Number((r._decay_factor || 0).toFixed(6)),
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

  return {
    institution_risk_score: Number(institutionRisk.toFixed(2)),
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
      normalized_contribution_input: Number(normalizedContributionInput.toFixed(6)),
      exponent: 2,
      normalization_lambda: lambda,
      llm_adjustment_aggregate: llmAdjustmentAggregate,
      top_contributing_incidents: topContributing
    }
  };
}
