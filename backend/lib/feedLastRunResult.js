/**
 * Normalize last-run metrics into a shared operational result model for the Feeds UI.
 *
 * Provider-specific counters remain on last_run_metrics; this layer is for display.
 *
 * Semantics:
 * - records_unchanged → unchanged
 * - records_skipped (parse/map/unsupported) → filtered
 * - records_failed → failed / rejected
 * - Legacy URLHaus/MalwareBazaar runs that parked existing/no-op rows in skipped
 *   are remapped to unchanged (not rejected).
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

const LEGACY_SKIPPED_AS_UNCHANGED_JOBS = new Set([
  'urlhaus_import',
  'malwarebazaar_import'
]);

/**
 * Split legacy/modern skip counters into unchanged / filtered / rejected / failed.
 *
 * @param {object} counters
 * @param {string} status
 * @param {string|null} jobType
 * @returns {{
 *   unchanged: number,
 *   filtered: number,
 *   rejected: number,
 *   failed: number,
 *   legacySkippedRemapped: boolean
 * }}
 */
export function splitSkippedSemantics(counters, status, jobType = null) {
  const skipped = metricInt(counters.skipped);
  const unchanged = metricInt(counters.unchanged);
  const failed = metricInt(counters.failed);
  const inserted = metricInt(counters.inserted);
  const updated = metricInt(counters.updated);
  const processed = metricInt(counters.processed);
  const st = String(status || '').toLowerCase();
  const jt = String(jobType || '').toLowerCase();

  // USOM: skipped are validated rejects / unsupported-for-USOM — keep as rejected.
  if (jt === 'usom_import') {
    return {
      unchanged,
      filtered: 0,
      rejected: skipped + failed,
      failed,
      legacySkippedRemapped: false
    };
  }

  // Explicit feed-level noop.
  if (st === 'skipped_unchanged') {
    return {
      unchanged: unchanged + skipped,
      filtered: 0,
      rejected: failed,
      failed,
      legacySkippedRemapped: skipped > 0
    };
  }

  // Pure no-delta success: everything landed in skipped, nothing else moved.
  // Treat skipped as unchanged (legacy fingerprint / OTX / pre-fix writers).
  if (
    FEED_HEALTHY_STATUSES.includes(st)
    && inserted === 0
    && updated === 0
    && failed === 0
    && unchanged === 0
    && skipped > 0
  ) {
    return {
      unchanged: skipped,
      filtered: 0,
      rejected: 0,
      failed: 0,
      legacySkippedRemapped: true
    };
  }

  // Legacy URLHaus / MalwareBazaar: writers used noteSkipped for existing/no-op.
  // When unchanged was never persisted and skipped dominates a successful run,
  // present skipped as unchanged — never as rejected. True parse/invalid counts
  // cannot be separated retrospectively.
  if (
    LEGACY_SKIPPED_AS_UNCHANGED_JOBS.has(jt)
    && FEED_HEALTHY_STATUSES.includes(st)
    && failed === 0
    && unchanged === 0
    && skipped > 0
  ) {
    const checked = processed > 0 ? processed : (inserted + updated + skipped);
    const skippedDominant = checked > 0 ? skipped / checked >= 0.5 : true;
    if (skippedDominant) {
      return {
        unchanged: skipped,
        filtered: 0,
        rejected: 0,
        failed: 0,
        legacySkippedRemapped: true
      };
    }
  }

  // Modern / default: skipped = filtered (unsupported/invalid-for-importer);
  // failed = technical reject.
  return {
    unchanged,
    filtered: skipped,
    rejected: failed,
    failed,
    legacySkippedRemapped: false
  };
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

  const split = splitSkippedSemantics(counters, statusRaw, jobType);
  const { unchanged, filtered, rejected, failed, legacySkippedRemapped } = split;
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
    // Warn only on verifiable technical problems (partial fetch, meaningful failures).
    // filtered / unchanged alone never escalate to warning.
    const failRatio = checked > 0 ? failedOnly / checked : (failedOnly > 0 ? 1 : 0);
    const technicalWarning = partial || (failedOnly > 0 && failRatio >= 0.1);

    if (technicalWarning) {
      status = 'completed_with_warnings';
      outcome = 'partial';
      message = partial ? 'Partial fetch' : 'Partial result';
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
      if (legacySkippedRemapped && filtered === 0 && failedOnly === 0) {
        // Detail-only hint; main Feeds table ignores this message.
        message = 'Legacy skipped counts presented as unchanged';
      }
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
    filtered: finiteOrNull(filtered) ?? 0,
    rejected: finiteOrNull(rejected) ?? 0,
    failed: finiteOrNull(failed) ?? 0,
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
