/**
 * Presentational helpers for Feeds "Last Result" column.
 * Pure functions — unit-tested without loading the React app.
 */

export const FEED_RESULT_METRIC_TOOLTIPS = Object.freeze({
  checked: 'Checked: records evaluated from the provider during the last run.',
  new: 'New: records that did not previously exist in the system.',
  updated: 'Updated: existing records whose source content changed.',
  unchanged: 'Unchanged: previously known records with identical source content.',
  rejected: 'Rejected: records that could not be imported due to validation or technical issues.',
  expired: 'Expired/removed: records no longer present in a successful full snapshot.',
  suppressed: 'Suppressed: matched an active suppression policy.',
  reactivated: 'Reactivated: previously removed/expired records that reappeared.'
});

function n(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : 0;
}

function fmt(value) {
  return n(value).toLocaleString();
}

/**
 * Normalize API last_result or fall back from last_run_metrics + status.
 * @param {object|null} feed
 */
export function resolveFeedLastResult(feed) {
  const raw = feed?.last_result;
  if (raw && typeof raw === 'object' && raw.status) {
    return {
      status: String(raw.status),
      outcome: raw.outcome || null,
      checked: n(raw.checked),
      new: n(raw.new),
      updated: n(raw.updated),
      unchanged: n(raw.unchanged),
      rejected: n(raw.rejected),
      expired: n(raw.expired),
      suppressed: n(raw.suppressed),
      reactivated: n(raw.reactivated),
      message: raw.message || null,
      available: raw.available !== false,
      duration_ms: raw.duration_ms ?? null,
      started_at: raw.started_at || null,
      finished_at: raw.finished_at || null
    };
  }

  // Fallback for older API payloads without last_result.
  const m = feed?.last_run_metrics || {};
  const statusRaw = String(feed?.last_status || feed?.status || 'never').toLowerCase();
  const checked = n(m.processed);
  const neu = n(m.inserted);
  const updated = n(m.updated);
  const unchanged = n(m.unchanged ?? m.duplicate);
  const skipped = n(m.skipped);
  const failed = n(m.failed);
  const rejected = skipped + failed;
  const errorMessage = feed?.last_error || null;

  if (statusRaw === 'running' || statusRaw === 'queued') {
    return {
      status: statusRaw,
      outcome: null,
      checked, new: neu, updated, unchanged, rejected,
      expired: n(m.removed), suppressed: n(m.suppressed), reactivated: n(m.reactivated),
      message: null, available: m.available !== false, duration_ms: null, started_at: null, finished_at: null
    };
  }
  if (statusRaw === 'failed' || statusRaw === 'fail') {
    return {
      status: 'failed',
      outcome: null,
      checked, new: neu, updated, unchanged, rejected,
      expired: n(m.removed), suppressed: n(m.suppressed), reactivated: n(m.reactivated),
      message: errorMessage || 'Sync failed',
      available: m.available !== false, duration_ms: null, started_at: null, finished_at: null
    };
  }
  if (statusRaw === 'never' || !statusRaw) {
    return {
      status: 'never',
      outcome: null,
      checked: 0, new: 0, updated: 0, unchanged: 0, rejected: 0,
      expired: 0, suppressed: 0, reactivated: 0,
      message: 'No successful run',
      available: false, duration_ms: null, started_at: null, finished_at: null
    };
  }

  let status = 'completed';
  let outcome = 'changes';
  let message = null;
  if (rejected > 0) {
    status = 'completed_with_warnings';
    outcome = 'partial';
    message = `${rejected.toLocaleString()} rejected`;
  } else if (checked === 0 && neu === 0 && updated === 0) {
    outcome = 'no_new_data';
    message = 'No new data';
  } else if (neu === 0 && updated === 0) {
    outcome = 'no_changes';
    message = 'No changes';
  }

  return {
    status,
    outcome,
    checked,
    new: neu,
    updated,
    unchanged: unchanged || (neu === 0 && updated === 0 && failed === 0 ? skipped : unchanged),
    rejected: unchanged === 0 && neu === 0 && updated === 0 && failed === 0 ? 0 : rejected,
    expired: n(m.removed),
    suppressed: n(m.suppressed),
    reactivated: n(m.reactivated),
    message,
    available: m.available !== false,
    duration_ms: null,
    started_at: null,
    finished_at: null
  };
}

/**
 * Build primary + secondary presentation lines for the Last Result cell.
 * @param {object} result  from resolveFeedLastResult
 */
export function presentFeedLastResult(result) {
  const r = result || resolveFeedLastResult(null);

  if (r.status === 'running') {
    return {
      primary: 'Running',
      primaryTone: 'neutral',
      secondary: null,
      secondaryTone: 'neutral',
      title: 'Import job is currently running'
    };
  }
  if (r.status === 'queued') {
    return {
      primary: 'Queued',
      primaryTone: 'neutral',
      secondary: null,
      secondaryTone: 'neutral',
      title: 'Import job is queued'
    };
  }
  if (r.status === 'never') {
    return {
      primary: 'No successful run',
      primaryTone: 'neutral',
      secondary: null,
      secondaryTone: 'neutral',
      title: 'This feed has not completed a successful sync yet'
    };
  }
  if (r.status === 'failed') {
    return {
      primary: `Failed${r.message ? ` · ${truncate(r.message, 42)}` : ''}`,
      primaryTone: 'danger',
      secondary: null,
      secondaryTone: 'neutral',
      title: r.message || 'Sync failed'
    };
  }

  if (r.status === 'completed_with_warnings') {
    const primaryBits = ['Completed with warnings'];
    if (r.rejected > 0) primaryBits.push(`${fmt(r.rejected)} rejected`);
    else if (r.message) primaryBits.push(truncate(r.message, 36));
    const secondary = buildSecondaryLine(r, { includeRejected: false });
    return {
      primary: primaryBits.join(' · '),
      primaryTone: 'warning',
      secondary,
      secondaryTone: 'neutral',
      title: buildTitle(r)
    };
  }

  // completed
  if (r.outcome === 'no_new_data') {
    return {
      primary: 'Completed · No new data',
      primaryTone: 'success',
      secondary: r.checked > 0 ? `${fmt(r.checked)} checked` : null,
      secondaryTone: 'neutral',
      title: buildTitle(r)
    };
  }
  if (r.outcome === 'no_changes') {
    return {
      primary: 'Completed · No changes',
      primaryTone: 'success',
      secondary: buildSecondaryLine(r),
      secondaryTone: 'neutral',
      title: buildTitle(r)
    };
  }

  const primaryBits = ['Completed'];
  if (r.new > 0) primaryBits.push(`${fmt(r.new)} new`);
  if (r.updated > 0) primaryBits.push(`${fmt(r.updated)} updated`);
  if (r.reactivated > 0) primaryBits.push(`${fmt(r.reactivated)} reactivated`);

  return {
    primary: primaryBits.join(' · '),
    primaryTone: 'success',
    secondary: buildSecondaryLine(r),
    secondaryTone: 'neutral',
    title: buildTitle(r)
  };
}

function buildSecondaryLine(r, { includeRejected = true } = {}) {
  const parts = [];
  if (r.checked > 0) parts.push(`${fmt(r.checked)} checked`);
  if (r.unchanged > 0) parts.push(`${fmt(r.unchanged)} unchanged`);
  if (includeRejected && r.rejected > 0) parts.push(`${fmt(r.rejected)} rejected`);
  if (r.suppressed > 0) parts.push(`${fmt(r.suppressed)} suppressed`);
  if (r.expired > 0) parts.push(`${fmt(r.expired)} removed`);
  return parts.length ? parts.join(' · ') : null;
}

function buildTitle(r) {
  const lines = [
    FEED_RESULT_METRIC_TOOLTIPS.checked,
    FEED_RESULT_METRIC_TOOLTIPS.new,
    FEED_RESULT_METRIC_TOOLTIPS.updated,
    FEED_RESULT_METRIC_TOOLTIPS.unchanged,
    FEED_RESULT_METRIC_TOOLTIPS.rejected
  ];
  if (r.message) lines.unshift(r.message);
  return lines.join('\n');
}

function truncate(text, max) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  if (raw.length <= max) return raw;
  return `${raw.slice(0, max - 1)}…`;
}

export const FEED_RESULT_TONE_COLORS = Object.freeze({
  success: '#86efac',
  warning: '#fcd34d',
  danger: '#fca5a5',
  neutral: '#94a3b8'
});
