/**
 * Duration helpers for the Job Queue Status table.
 *
 * A job's duration is:
 *   - finished job:  finished_at - started_at
 *   - running job:   now - started_at
 *   - not started:   null  (rendered as '-')
 */

/** Compute a job's duration in milliseconds, or null when it never started. */
export function computeJobDurationMs(job, now = Date.now()) {
  const startedMs = job?.started_at ? Date.parse(job.started_at) : NaN;
  if (!Number.isFinite(startedMs)) return null;
  const finishedMs = job?.finished_at ? Date.parse(job.finished_at) : NaN;
  const endMs = Number.isFinite(finishedMs) ? finishedMs : now;
  return Math.max(0, endMs - startedMs);
}

/**
 * Format a duration in milliseconds into a compact, human-readable string:
 *   850ms · 6s · 2m 14s · 1h 3m
 * Returns '-' for null / invalid / negative input.
 */
export function formatJobDuration(ms) {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return '-';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

/** Convenience: compute + format a job's duration in one call. */
export function formatJobDurationForRow(job, now = Date.now()) {
  return formatJobDuration(computeJobDurationMs(job, now));
}
