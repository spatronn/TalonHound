export const REFERENCE_TYPE_LABELS = Object.freeze({
  social: 'Social / X',
  free_ti: 'Free TI platform',
  vendor_report: 'Vendor report',
  sandbox: 'Sandbox',
  blog: 'Blog',
  internal_note: 'Internal note',
  other: 'Other'
});

export const ASSESSMENT_IMPACT_LABELS = Object.freeze({
  supports_malicious: 'Supports malicious',
  supports_benign: 'Supports benign / FP',
  context_only: 'Context only',
  needs_review: 'Needs review'
});

export const TLP_LABELS = Object.freeze({
  clear: 'TLP:CLEAR',
  green: 'TLP:GREEN',
  amber: 'TLP:AMBER',
  red: 'TLP:RED'
});

export const CONFIDENCE_LABELS = Object.freeze({
  unknown: 'Unknown',
  low: 'Low',
  medium: 'Medium',
  high: 'High'
});

export function normalizeTlpLabel(value) {
  const v = String(value || 'clear').trim().toLowerCase();
  if (v === 'white') return 'clear';
  return v;
}

export function referenceTypeLabel(value) {
  return REFERENCE_TYPE_LABELS[String(value || 'other')] || REFERENCE_TYPE_LABELS.other;
}

export function assessmentImpactLabel(value) {
  return ASSESSMENT_IMPACT_LABELS[String(value || 'context_only')] || ASSESSMENT_IMPACT_LABELS.context_only;
}

export function tlpLabel(value) {
  return TLP_LABELS[normalizeTlpLabel(value)] || TLP_LABELS.clear;
}

export function analystConfidenceLabel(value) {
  return CONFIDENCE_LABELS[String(value || 'unknown')] || CONFIDENCE_LABELS.unknown;
}

export function assessmentImpactStyle(value) {
  const v = String(value || 'context_only');
  if (v === 'supports_malicious') return { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  if (v === 'supports_benign') return { border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' };
  if (v === 'needs_review') return { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  return { border: '#475569', bg: 'rgba(71,85,105,0.18)', color: '#cbd5e1' };
}

export function tlpBadgeStyle(value) {
  const v = normalizeTlpLabel(value);
  if (v === 'red') return { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  if (v === 'amber') return { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  if (v === 'green') return { border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' };
  return { border: '#1d4ed8', bg: 'rgba(37,99,235,0.14)', color: '#93c5fd' };
}

export function confidenceBadgeStyleAnalyst(value) {
  const v = String(value || 'unknown');
  if (v === 'high') return { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  if (v === 'medium') return { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  if (v === 'low') return { border: '#1d4ed8', bg: 'rgba(37,99,235,0.14)', color: '#93c5fd' };
  return { border: '#475569', bg: 'rgba(71,85,105,0.18)', color: '#94a3b8' };
}

export function referenceTypeBadgeStyle(value) {
  const v = String(value || 'other');
  if (v === 'social') return { border: '#1d4ed8', bg: 'rgba(37,99,235,0.14)', color: '#93c5fd' };
  if (v === 'free_ti') return { border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' };
  if (v === 'vendor_report') return { border: '#6d28d9', bg: 'rgba(109,40,217,0.14)', color: '#c4b5fd' };
  return { border: '#475569', bg: 'rgba(71,85,105,0.18)', color: '#cbd5e1' };
}

export function renderBadge(label, style) {
  return { label, style };
}
