import React from 'react';
import { badgeStyle } from './styles.js';
import { TLP_LABELS, normalizeTlp, tlpDisplay } from './tlpValues.js';

export { TLP_LABELS, normalizeTlp, tlpDisplay };

export function tlpColors(value) {
  const v = normalizeTlp(value);
  if (v === 'red') return { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  if (v === 'amber' || v === 'amber_strict') {
    return { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  }
  if (v === 'green') return { border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' };
  return { border: '#1d4ed8', bg: 'rgba(37,99,235,0.14)', color: '#93c5fd' };
}

export function isElevatedTlp(value) {
  const v = normalizeTlp(value);
  return v === 'amber' || v === 'amber_strict' || v === 'red';
}

export function TlpBadge({ tlp, display }) {
  const colors = tlpColors(tlp);
  return <span style={badgeStyle(colors)}>{tlpDisplay(tlp, display)}</span>;
}
