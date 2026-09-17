/** Pure TLP value helpers (no React) shared by tlp.jsx and tlpEdit.js. */

export const TLP_LABELS = Object.freeze({
  clear: 'TLP:CLEAR',
  green: 'TLP:GREEN',
  amber: 'TLP:AMBER',
  amber_strict: 'TLP:AMBER+STRICT',
  red: 'TLP:RED',
  white: 'TLP:CLEAR'
});

export function normalizeTlp(value) {
  const raw = String(value || 'clear').trim().toLowerCase().replace(/^tlp:/, '').replace(/\s+/g, '_');
  if (raw === 'white') return 'clear';
  if (raw === 'amber+strict' || raw === 'amber-strict') return 'amber_strict';
  return raw || 'clear';
}

export function tlpDisplay(value, fallbackDisplay) {
  if (fallbackDisplay) return fallbackDisplay;
  const v = normalizeTlp(value);
  return TLP_LABELS[v] || `TLP:${String(value || '').toUpperCase()}`;
}
