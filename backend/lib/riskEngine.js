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

export function calculateInstitutionRisk(incidents) {
  const rows = Array.isArray(incidents) ? incidents : [];
  if (!rows.length) {
    return {
      institution_risk_score: 0,
      active_incident_count: 0,
      top_contributing_incidents: [],
      breakdown: {
        model: 'institution-risk-central-2026-04',
        bounded_range: '0-100',
        weighted_top_risk: 0,
        density_factor: 0,
        composition: {
          weighted_top_component: 0,
          density_component: 0
        }
      }
    };
  }

  const scored = rows.map((r) => {
    const incidentRisk = calculateIncidentRisk(r);
    return { ...r, ...incidentRisk };
  }).sort((a, b) => b.risk_score - a.risk_score);

  let weightedNumerator = 0;
  let weightDenominator = 0;
  for (let i = 0; i < scored.length; i += 1) {
    const w = 1 / Math.pow(i + 1, 0.75);
    weightedNumerator += scored[i].risk_score * w;
    weightDenominator += w;
  }
  const weightedTopRisk = weightDenominator > 0 ? (weightedNumerator / weightDenominator) : 0;

  const activeCount = scored.length;
  const densityNorm = clamp(1 - Math.exp(-activeCount / 15), 0, 1);

  const weightedTopComponent = weightedTopRisk * 0.85;
  const densityComponent = densityNorm * 15;
  const institutionRisk = clamp(weightedTopComponent + densityComponent, 0, 100);

  const topContributing = scored.slice(0, 5).map((r, idx) => ({
    id: r.id,
    incident_id: r.incident_id,
    ioc_value: r.ioc_value,
    risk_score: r.risk_score,
    rank: idx + 1
  }));

  return {
    institution_risk_score: Number(institutionRisk.toFixed(2)),
    active_incident_count: activeCount,
    top_contributing_incidents: topContributing,
    breakdown: {
      model: 'institution-risk-central-2026-04',
      bounded_range: '0-100',
      weighted_top_risk: Number(weightedTopRisk.toFixed(2)),
      density_factor: Number(densityNorm.toFixed(4)),
      composition: {
        weighted_top_component: Number(weightedTopComponent.toFixed(2)),
        density_component: Number(densityComponent.toFixed(2))
      }
    }
  };
}
