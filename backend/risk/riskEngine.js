function clamp(value, min = 0, max = 100) {
  return Math.min(Math.max(Number(value) || 0, min), max);
}

function safe(value) {
  return Math.max(Number(value) || 0, 0);
}

function volumeSignal(volume, hasExecution, hasSpread, hasPersistence) {
  const base = Math.log1p(safe(volume)) * 6;
  if (hasExecution || hasSpread || hasPersistence) return base;
  return base * 0.35;
}

export function calculateBehaviorRisk(activity = {}) {
  const type = String(activity?.type || '').toLowerCase();
  const volume = safe(activity?.volume);
  const uniqueHosts = safe(activity?.unique_hosts);
  const persistence = safe(activity?.persistence);
  const hasExecution = Boolean(activity?.has_execution);
  const isBlocked = Boolean(activity?.is_blocked);

  const hasSpread = uniqueHosts >= 3;
  const hasPersistence = persistence >= 60;

  const baseScore = 15;
  const executionSignal = hasExecution ? 30 : 0;
  const blockedSignal = isBlocked ? -18 : 0;
  const volumeScore = volumeSignal(volume, hasExecution, hasSpread, hasPersistence);
  const spreadSignal = uniqueHosts > 1 ? Math.min((uniqueHosts - 1) * 4, 18) : 0;
  const persistenceSignal = Math.min(Math.log1p(persistence) * 3, 20);

  let dnsSpecificSignal = 0;
  if (type === 'dns') {
    if (!hasExecution) dnsSpecificSignal -= 8;
    if (hasExecution) dnsSpecificSignal += 15;
    if (isBlocked) dnsSpecificSignal -= 10;
  }

  const rawScore = baseScore
    + executionSignal
    + blockedSignal
    + volumeScore
    + spreadSignal
    + persistenceSignal
    + dnsSpecificSignal;

  const riskScore = clamp(rawScore, 0, 100);
  return {
    risk_score: Number(riskScore.toFixed(2)),
    risk_breakdown: {
      model: 'ioc-behavior-risk-v1',
      components: {
        base_score: Number(baseScore.toFixed(2)),
        execution_signal: Number(executionSignal.toFixed(2)),
        blocked_signal: Number(blockedSignal.toFixed(2)),
        volume_signal: Number(volumeScore.toFixed(2)),
        spread_signal: Number(spreadSignal.toFixed(2)),
        persistence_signal: Number(persistenceSignal.toFixed(2)),
        dns_specific_signal: Number(dnsSpecificSignal.toFixed(2))
      },
      activity: {
        type,
        volume,
        unique_hosts: uniqueHosts,
        persistence,
        has_execution: hasExecution,
        is_blocked: isBlocked
      }
    }
  };
}
