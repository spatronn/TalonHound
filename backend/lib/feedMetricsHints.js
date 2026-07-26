/**
 * Secondary hints for feed last-run metrics (does not replace health_state).
 *
 * no_delta / high_unchanged are informational only — empty or unchanged feeds are healthy.
 * high_failed / partial_fetch may feed into health as Warning.
 */

export function buildFeedMetricsHints(lastRunMetrics, opts = {}) {
  const hints = [];
  const m = lastRunMetrics || {};
  const processed = Number(m.processed || 0);

  if (m.available === false && processed > 0) {
    hints.push('legacy_metrics');
    return hints;
  }

  const runDetails = opts.runDetails || null;
  if (
    runDetails?.truncated === true
    || runDetails?.partial === true
    || runDetails?.summary?.truncated === true
  ) {
    hints.push('partial_fetch');
  }

  if (!m.available || processed <= 0) return hints;

  const inserted = Number(m.inserted || 0);
  const updated = Number(m.updated || 0);
  const unchanged = Number(m.unchanged ?? m.duplicate ?? 0);
  const skipped = Number(m.skipped || 0);
  const failed = Number(m.failed || 0);

  // Informational: run checked records but made no inserts/updates.
  if (inserted === 0 && updated === 0 && (unchanged + skipped) / processed >= 0.95) {
    hints.push('no_delta');
  }

  if (failed > 0 && failed / processed >= 0.1) {
    hints.push('high_failed');
  }

  return hints;
}

export function feedMetricsHintPresentation(hint) {
  const map = {
    legacy_metrics: {
      label: 'Legacy metrics',
      color: '#fcd34d',
      title: 'Import breakdown unavailable until the feed runs again with granular metrics.'
    },
    no_delta: {
      label: 'No changes',
      color: '#94a3b8',
      title: 'Last run checked records but did not insert or update IOCs — normal when feed content is unchanged.'
    },
    high_skipped: {
      label: 'High skipped',
      color: '#fdba74',
      title: 'Most records were skipped (filtered or not importable). Review if unexpected.'
    },
    high_failed: {
      label: 'High failed',
      color: '#fca5a5',
      title: 'A significant share of records failed to import.'
    },
    partial_fetch: {
      label: 'Partial fetch',
      color: '#fcd34d',
      title: 'Provider returned a truncated or partial result; some pages may be missing.'
    }
  };
  return map[hint] || { label: hint, color: '#94a3b8', title: hint };
}
