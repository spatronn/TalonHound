/**
 * Presentational helpers for Feeds table "Last Result" column.
 *
 * Table summary shows only operator-meaningful change signals (new/updated)
 * or short success/failure messages — not technical counters.
 */

export const FEED_RESULT_METRIC_TOOLTIPS = Object.freeze({
  checked: 'Checked: records evaluated from the provider during the last run.',
  new: 'New: records that did not previously exist in the system.',
  updated: 'Updated: existing records whose source content changed.',
  unchanged: 'Unchanged: Existing record whose semantic source content did not change',
  filtered: 'Filtered: Record intentionally not imported because it was unsupported, invalid for this importer, or outside accepted scope',
  rejected: 'Rejected/Failed: Record that could not be processed because of validation, persistence, or technical failure',
  failed: 'Rejected/Failed: Record that could not be processed because of validation, persistence, or technical failure',
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
    const failed = n(raw.failed ?? raw.rejected);
    const filtered = n(raw.filtered);
    return {
      status: String(raw.status),
      outcome: raw.outcome || null,
      checked: n(raw.checked),
      new: n(raw.new),
      updated: n(raw.updated),
      unchanged: n(raw.unchanged),
      filtered,
      rejected: n(raw.rejected ?? raw.failed),
      failed,
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
  const jobType = String(feed?.job_type || feed?.integration_job_type || '').toLowerCase();
  const checked = n(m.processed);
  const neu = n(m.inserted);
  const updated = n(m.updated);
  const unchangedRaw = n(m.unchanged ?? m.duplicate);
  const skipped = n(m.skipped);
  const failed = n(m.failed);
  const errorMessage = feed?.last_error || null;

  const legacyNoopJobs = jobType === 'urlhaus_import' || jobType === 'malwarebazaar_import';
  const healthy = ['success', 'skipped', 'skipped_unchanged'].includes(statusRaw)
    || (statusRaw !== 'failed' && statusRaw !== 'fail' && statusRaw !== 'never' && statusRaw !== 'running' && statusRaw !== 'queued');

  let unchanged = unchangedRaw;
  let filtered = 0;
  let rejected = failed;

  if (statusRaw === 'skipped_unchanged') {
    unchanged = unchangedRaw + skipped;
  } else if (
    healthy
    && failed === 0
    && unchangedRaw === 0
    && skipped > 0
    && (
      (neu === 0 && updated === 0)
      || (legacyNoopJobs && (checked > 0 ? skipped / checked >= 0.5 : true))
    )
  ) {
    // Legacy existing/no-op parked in skipped — present as unchanged, never rejected.
    unchanged = skipped;
  } else {
    filtered = skipped;
    rejected = failed;
  }

  if (statusRaw === 'running' || statusRaw === 'queued') {
    return {
      status: statusRaw,
      outcome: null,
      checked,
      new: neu,
      updated,
      unchanged,
      filtered,
      rejected,
      failed,
      expired: n(m.removed),
      suppressed: n(m.suppressed),
      reactivated: n(m.reactivated),
      message: null,
      available: m.available !== false,
      duration_ms: null,
      started_at: null,
      finished_at: null
    };
  }
  if (statusRaw === 'failed' || statusRaw === 'fail') {
    return {
      status: 'failed',
      outcome: null,
      checked,
      new: neu,
      updated,
      unchanged: unchangedRaw,
      filtered: skipped,
      rejected: failed,
      failed,
      expired: n(m.removed),
      suppressed: n(m.suppressed),
      reactivated: n(m.reactivated),
      message: errorMessage || 'Sync failed',
      available: m.available !== false,
      duration_ms: null,
      started_at: null,
      finished_at: null
    };
  }
  if (statusRaw === 'never' || !statusRaw) {
    return {
      status: 'never',
      outcome: null,
      checked: 0,
      new: 0,
      updated: 0,
      unchanged: 0,
      filtered: 0,
      rejected: 0,
      failed: 0,
      expired: 0,
      suppressed: 0,
      reactivated: 0,
      message: 'No successful run',
      available: false,
      duration_ms: null,
      started_at: null,
      finished_at: null
    };
  }

  // Healthy terminal runs: never escalate on legacy skipped/filtered alone.
  let outcome = 'changes';
  let message = null;
  if (checked === 0 && neu === 0 && updated === 0) {
    outcome = 'no_new_data';
    message = 'No new data';
  } else if (neu === 0 && updated === 0) {
    outcome = 'no_changes';
    message = 'No changes';
  } else if (unchangedRaw === 0 && skipped > 0 && failed === 0 && filtered === 0) {
    message = 'Legacy skipped counts presented as unchanged';
  }

  return {
    status: 'completed',
    outcome,
    checked,
    new: neu,
    updated,
    unchanged,
    filtered,
    rejected,
    failed,
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
 * Health signal the Last Result column must reconcile against.
 *
 * The Last Result column reflects the latest run's own outcome. USOM full-reconciliation
 * health is a *separate* operational signal, surfaced independently in the Health column
 * (badge + reconciliation_warning). It must never rewrite the Last Result — otherwise a
 * successful incremental is shown as "Failed · Sync failed" only because an older, unrelated
 * full reconciliation failed. Prefer the backend-provided run-level health; fall back to the
 * overlaid health_state for older payloads that predate run_health_state.
 * @param {object|null} feed
 * @returns {string|null}
 */
export function resolveLastResultHealthState(feed) {
  if (feed && typeof feed === 'object' && feed.run_health_state != null) {
    return feed.run_health_state;
  }
  return feed?.health_state ?? null;
}

/**
 * Align Last Result presentation with feed health_state.
 * Healthy feeds must not render as "Completed with warnings".
 * @param {object} result
 * @param {string|null|undefined} healthState
 */
export function reconcileLastResultWithHealth(result, healthState) {
  const r = result && typeof result === 'object'
    ? { ...result }
    : resolveFeedLastResult(null);
  const health = String(healthState || '').toLowerCase();

  if (health === 'failed' || health === 'degraded') {
    if (r.status !== 'failed') {
      return {
        ...r,
        status: 'failed',
        outcome: null,
        message: r.message || 'Sync failed'
      };
    }
    return r;
  }

  if (health === 'warning') {
    if (r.status === 'completed' || r.status === 'completed_with_warnings') {
      return {
        ...r,
        status: 'completed_with_warnings',
        outcome: 'partial',
        message: summarizeWarningMessage(r.message)
      };
    }
    return r;
  }

  if (health === 'success' || health === 'healthy' || health === '') {
    if (r.status === 'completed_with_warnings') {
      if (n(r.new) === 0 && n(r.updated) === 0 && n(r.checked) === 0) {
        return {
          ...r,
          status: 'completed',
          outcome: 'no_new_data',
          message: 'No new data'
        };
      }
      if (n(r.new) === 0 && n(r.updated) === 0) {
        return {
          ...r,
          status: 'completed',
          outcome: 'no_changes',
          message: 'No changes'
        };
      }
      return {
        ...r,
        status: 'completed',
        outcome: 'changes',
        message: null
      };
    }
  }

  if (health === 'never') {
    return {
      ...r,
      status: 'never',
      outcome: null,
      message: 'No successful run'
    };
  }

  if (health === 'disabled') {
    return {
      ...r,
      status: 'disabled',
      outcome: null,
      message: null
    };
  }

  return r;
}

function summarizeWarningMessage(message) {
  const raw = String(message || '').trim();
  if (!raw) return 'Partial result';
  const lower = raw.toLowerCase();
  if (lower.includes('partial fetch') || lower.includes('truncated')) return 'Partial fetch';
  if (lower.includes('partial')) return 'Partial result';
  if (lower.includes('rate limit')) return 'Rate limited';
  if (/^[\d,]+\s+rejected$/i.test(raw)) return 'Partial result';
  return truncate(raw, 42);
}

function shortenFailureMessage(message) {
  const raw = String(message || '').trim();
  if (!raw) return 'Sync failed';
  const lower = raw.toLowerCase();
  if (lower.includes('auth')) return truncate(raw.includes('Authentication') ? raw : 'Authentication error', 42);
  if (lower.includes('timeout') || lower.includes('timed out')) return 'Provider request timed out';
  if (lower.includes('database') || lower.includes('persist')) return 'Database write failed';
  return truncate(raw, 42);
}

/**
 * Build compact Last Result lines for the Feeds table.
 * @param {object} result  from resolveFeedLastResult
 * @param {{ healthState?: string|null }} [opts]
 */
export function presentFeedLastResult(result, opts = {}) {
  const reconciled = reconcileLastResultWithHealth(
    result || resolveFeedLastResult(null),
    opts.healthState
  );
  const r = reconciled;

  if (r.status === 'disabled') {
    return {
      primary: 'Disabled',
      primaryTone: 'neutral',
      secondary: null,
      secondaryTone: 'neutral',
      title: 'Feed is disabled'
    };
  }
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
    const short = shortenFailureMessage(r.message);
    return {
      primary: `Failed · ${short}`,
      primaryTone: 'danger',
      secondary: null,
      secondaryTone: 'neutral',
      title: r.message || short
    };
  }

  if (r.status === 'completed_with_warnings') {
    const detail = summarizeWarningMessage(r.message);
    return {
      primary: `Completed with warnings · ${detail}`,
      primaryTone: 'warning',
      secondary: null,
      secondaryTone: 'neutral',
      title: r.message || detail
    };
  }

  // completed
  if (r.outcome === 'no_new_data') {
    return {
      primary: 'Completed · No new data',
      primaryTone: 'success',
      secondary: null,
      secondaryTone: 'neutral',
      title: 'Provider returned no importable records'
    };
  }
  if (r.outcome === 'no_changes' || (n(r.new) === 0 && n(r.updated) === 0)) {
    return {
      primary: 'Completed · No changes',
      primaryTone: 'success',
      secondary: null,
      secondaryTone: 'neutral',
      title: 'Sync completed with no new or updated records'
    };
  }

  const primaryBits = ['Completed'];
  if (n(r.new) > 0) primaryBits.push(`${fmt(r.new)} new`);
  if (n(r.updated) > 0) primaryBits.push(`${fmt(r.updated)} updated`);

  return {
    primary: primaryBits.join(' · '),
    primaryTone: 'success',
    secondary: null,
    secondaryTone: 'neutral',
    title: [
      n(r.new) > 0 ? `${fmt(r.new)} new` : null,
      n(r.updated) > 0 ? `${fmt(r.updated)} updated` : null
    ].filter(Boolean).join(' · ') || 'Sync completed'
  };
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
