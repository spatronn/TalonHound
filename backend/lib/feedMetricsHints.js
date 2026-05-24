/**
 * Secondary hints for feed last-run metrics (does not replace health_state).
 */
export function buildFeedMetricsHints(lastRunMetrics) {
  const hints = [];
  const m = lastRunMetrics || {};
  const processed = Number(m.processed || 0);

  if (m.available === false && processed > 0) {
    hints.push('legacy_metrics');
    return hints;
  }

  if (!m.available || processed <= 0) return hints;

  const inserted = Number(m.inserted || 0);
  const duplicate = Number(m.duplicate || 0);
  const skipped = Number(m.skipped || 0);
  const failed = Number(m.failed || 0);

  if (inserted === 0 && duplicate === 0 && skipped / processed >= 0.95) {
    hints.push('no_delta');
  } else if (skipped / processed >= 0.8 && inserted === 0) {
    hints.push('high_skipped');
  }

  if (failed > 0 && failed / processed >= 0.1) {
    hints.push('high_failed');
  }

  return hints;
}

export function feedMetricsHintPresentation(hint) {
  const map = {
    legacy_metrics: { label: 'Legacy metrics', color: '#fcd34d', title: 'Import breakdown unavailable until the feed runs again with granular metrics.' },
    no_delta: { label: 'No delta', color: '#94a3b8', title: 'Last run processed records but did not insert or update IOCs — often normal when the feed content is unchanged.' },
    high_skipped: { label: 'High skipped', color: '#fdba74', title: 'Most records were skipped (unchanged, filtered, or already known). Review if unexpected.' },
    high_failed: { label: 'High failed', color: '#fca5a5', title: 'A significant share of records failed to import.' }
  };
  return map[hint] || { label: hint, color: '#94a3b8', title: hint };
}
