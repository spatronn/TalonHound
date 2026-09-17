/**
 * Manual TLP editing on the report page: canonical option set, provenance
 * labels and the downgrade confirmation rule. Pure — mirrors
 * backend/lib/threatLibrary/tlpPolicy.js (TLP_VALUES + rank).
 */

import { normalizeTlp, tlpDisplay } from './tlpValues.js';

/** Canonical TalonHound TLP set (matches backend TLP_VALUES / DB CHECK). */
export const TLP_OPTIONS = Object.freeze([
  { value: 'clear', label: 'TLP:CLEAR' },
  { value: 'green', label: 'TLP:GREEN' },
  { value: 'amber', label: 'TLP:AMBER' },
  { value: 'amber_strict', label: 'TLP:AMBER+STRICT' },
  { value: 'red', label: 'TLP:RED' }
]);

const RANK = Object.freeze({ clear: 0, green: 1, amber: 2, amber_strict: 3, red: 4 });

const SOURCE_LABELS = Object.freeze({
  explicit: 'Marked in the source document',
  default: 'Default for this source (no marking found)',
  manual: 'Set manually'
});

const SOURCE_SHORT = Object.freeze({
  explicit: 'Source-marked',
  default: 'Default',
  manual: 'Manual'
});

export function tlpSourceLabel(source) {
  return SOURCE_LABELS[String(source || '').toLowerCase()] || SOURCE_LABELS.default;
}

export function tlpSourceShortLabel(source) {
  return SOURCE_SHORT[String(source || '').toLowerCase()] || SOURCE_SHORT.default;
}

export function isTlpDowngrade(from, to) {
  return (RANK[normalizeTlp(to)] ?? 0) < (RANK[normalizeTlp(from)] ?? 0);
}

/** Only the existing report-edit permission (canWrite: analyst / admin) may change TLP. */
export function canEditTlp({ canWrite, report }) {
  return Boolean(canWrite) && Boolean(report);
}

/**
 * Confirmation to show before saving, or null when the change is harmless.
 * Only loosening the restriction (e.g. AMBER -> CLEAR) asks for confirmation.
 */
export function describeTlpChangeConfirm(from, to) {
  const a = normalizeTlp(from);
  const b = normalizeTlp(to);
  if (a === b || !isTlpDowngrade(a, b)) return null;
  return {
    title: 'Reduce the sharing restriction?',
    description: `${tlpDisplay(a)} → ${tlpDisplay(b)} reduces this report's sharing restriction. THIB exports and downstream consumers will use the new value.`,
    confirmLabel: `Set ${tlpDisplay(b)}`,
    cancelLabel: 'Cancel',
    variant: 'warning'
  };
}

/** Success banner after a manual change. */
export function describeTlpSavedFeedback(to) {
  return `TLP set to ${tlpDisplay(normalizeTlp(to))}.`;
}
