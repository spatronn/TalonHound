export function normalizeVerdict(v) {
  const s = String(v || '').trim().toLowerCase();
  if (s === 'fp') return 'FP';
  if (s === 'tp') return 'TP';
  if (s === 'suspicious') return 'Suspicious';
  if (s === 'in progress' || s === 'in_progress') return 'In Progress';
  return 'Unreviewed';
}

export function getVerdictWeight(verdict) {
  const v = normalizeVerdict(verdict);
  if (v === 'FP') return 0;
  if (v === 'TP') return 1;
  if (v === 'Suspicious') return 0.7;
  return 0.5;
}

export function calculateIncidentRiskV1(incident) {
  const hits = Math.max(Number(incident?.total_hits || 0), 0);
  const weight = getVerdictWeight(incident?.verdict);
  if (weight === 0 || hits <= 0) return 0;
  return Math.log1p(hits) * weight;
}
