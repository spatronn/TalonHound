/**
 * Normalize last-run metrics into a shared operational result model for the Feeds UI.
 *
 * Provider-specific counters remain on last_run_metrics; this layer is for display.
 */

import { resolveRunCounters } from './integrationRunCounters.js';
import { FEED_HEALTHY_STATUSES, FEED_RUNTIME_STATUSES } from './feedHealth.js';

function metricInt(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
}

function finiteOrNull(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function jtIsUsom(jobType) {
  return String(jobType || '').toLowerCase() === 'usom_import';
}

/**
 * Decide whether legacy `records_skipped` should display as Unchanged vs Rejected.
 *
 * Evidence:
 * - USOM writes true rejects into skipped and persists unchanged separately → never remap.
 * - Fingerprint importers historically bumped skipped via noteUnchanged without persisting
 *   unchanged → remap when the run looks like a pure no-delta success.
 * - AlienVault historically used noteSkipped for same-source unchanged.
 *
 * @param {object} counters
 * @param {string} status
 * @param {string|null} jobType
 */
export function splitSkippedSemantics(counters, status, jobType = null) {
  const skipped = metricInt(counters.skipped);
  const unchanged = metricInt(counters.unchanged);
  const failed = metricInt(counters.failed);
  const inserted = metricInt(counters.inserted);
  const updated = metricInt(counters.updated);
  const st = String(status || '').toLowerCase();
  const jt = String(jobType || '').toLowerCase();

  if (jt === 'usom_import') {
    return { unchanged, rejected: skipped + failed };
  }

  // Explicit feed-level noop.
  if (st === 'skipped_unchanged') {
    return { unchanged: unchanged + skipped, rejected: failed };
  }

  // Pure no-delta success: everything landed in skipped, nothing else moved.
  // Treat skipped as unchanged (legacy fingerprint / OTX unchanged path).
  if (
    FEED_HEALTHY_STATUSES.includes(st)
    && inserted === 0
    && updated === 0
    && failed === 0
    && unchanged === 0
    && skipped > 0
  ) {
    return { unchanged: skipped, rejected: 0 };
  }

  // Mixed run: keep skipped as rejected (invalid / unsupported / filtered).
  return { unchanged, rejected: skipped + failed };
}

/**
 * @param {object|null} row  integration_runs or queue row (or null)
 * @param {{
 *   status?: string|null,
 *   jobType?: string|null,
 *   errorMessage?: string|null,
 *   startedAt?: string|null,
 *   finishedAt?: string|null,
 *   lastRunMetrics?: object|null,
 *   runDetails?: object|null
 * }} [opts]
 */
export function normalizeLastRunResult(row, opts = {}) {
  const statusRaw = String(opts.status ?? row?.status ?? 'never').toLowerCase();
  const jobType = opts.jobType ?? row?.job_type ?? null;
  const errorMessage = opts.errorMessage ?? row?.error_message ?? null;
  const startedAt = opts.startedAt ?? row?.started_at ?? null;
  const finishedAt = opts.finishedAt ?? row?.finished_at ?? null;
  const runDetails = opts.runDetails ?? row?.run_details ?? null;

  const metrics = opts.lastRunMetrics || null;
  const counters = metrics?.available
    ? {
        processed: metricInt(metrics.processed),
        inserted: metricInt(metrics.inserted),
        updated: metricInt(metrics.updated),
        unchanged: metricInt(metrics.unchanged ?? metrics.duplicate),
        reactivated: metricInt(metrics.reactivated),
        removed: metricInt(metrics.removed),
        skipped: metricInt(metrics.skipped),
        suppressed: metricInt(metrics.suppressed),
        failed: metricInt(metrics.failed)
      }
    : resolveRunCounters(row);

  const { unchanged, rejected } = splitSkippedSemantics(counters, statusRaw, jobType);
  const checked = metricInt(counters.processed);
  const neu = metricInt(counters.inserted);
  const updated = metricInt(counters.updated);
  const expired = metricInt(counters.removed);
  const suppressed = metricInt(counters.suppressed);
  const reactivated = metricInt(counters.reactivated);

  let durationMs = null;
  if (startedAt && finishedAt) {
    const a = Date.parse(startedAt);
    const b = Date.parse(finishedAt);
    if (Number.isFinite(a) && Number.isFinite(b) && b >= a) durationMs = b - a;
  }

  const partial = Boolean(
    runDetails?.truncated
    || runDetails?.partial
    || runDetails?.reconciliation_complete === false
    || runDetails?.summary?.truncated
  );

  let status;
  let outcome = null;
  let message = null;

  if (FEED_RUNTIME_STATUSES.includes(statusRaw)) {
    status = statusRaw;
  } else if (statusRaw === 'failed' || statusRaw === 'fail') {
    status = 'failed';
    message = errorMessage ? String(errorMessage).slice(0, 200) : 'Sync failed';
  } else if (statusRaw === 'never' || !statusRaw) {
    status = 'never';
    message = 'No successful run';
  } else if (FEED_HEALTHY_STATUSES.includes(statusRaw)) {
    const failedOnly = metricInt(counters.failed);
    const rejectRatio = checked > 0 ? rejected / checked : (rejected > 0 ? 1 : 0);
    const meaningfulRejects = failedOnly > 0
      || partial
      || (jtIsUsom(jobType) && rejected > 0)
      || (rejected > 0 && rejectRatio >= 0.1);

    if (meaningfulRejects) {
      status = 'completed_with_warnings';
      outcome = 'partial';
      if (partial) message = 'Provider returned a partial result';
      else if (rejected > 0) message = `${rejected.toLocaleString()} rejected`;
    } else if (checked === 0 && neu === 0 && updated === 0) {
      status = 'completed';
      outcome = 'no_new_data';
      message = 'No new data';
    } else if (neu === 0 && updated === 0 && reactivated === 0) {
      status = 'completed';
      outcome = 'no_changes';
      message = 'No changes';
    } else {
      status = 'completed';
      outcome = 'changes';
    }
  } else {
    status = 'completed_with_warnings';
    outcome = 'partial';
    message = errorMessage ? String(errorMessage).slice(0, 200) : `Unexpected status: ${statusRaw}`;
  }

  // Legacy metrics: processed only, no breakdown.
  if (metrics && metrics.available === false && checked > 0 && status === 'completed') {
    message = 'Metrics breakdown unavailable until next run';
  }

  return {
    status,
    outcome,
    checked: finiteOrNull(checked) ?? 0,
    new: finiteOrNull(neu) ?? 0,
    updated: finiteOrNull(updated) ?? 0,
    unchanged: finiteOrNull(unchanged) ?? 0,
    rejected: finiteOrNull(rejected) ?? 0,
    expired: finiteOrNull(expired) ?? 0,
    suppressed: finiteOrNull(suppressed) ?? 0,
    reactivated: finiteOrNull(reactivated) ?? 0,
    duration_ms: durationMs,
    started_at: startedAt || null,
    finished_at: finishedAt || null,
    message,
    available: metrics ? Boolean(metrics.available) : Boolean(row)
  };
}
