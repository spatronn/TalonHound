/**
 * Feed operational health — independent of "how many new IOCs".
 *
 * Healthy means the last terminal sync completed without a verifiable technical problem.
 * Empty / no-change provider results are healthy.
 */

/** Terminal statuses that mean the sync finished successfully (including intentional noops). */
export const FEED_HEALTHY_STATUSES = Object.freeze([
  'success',
  'skipped',
  'skipped_unchanged'
]);

/** Runtime / in-flight statuses — never used as a health outcome. */
export const FEED_RUNTIME_STATUSES = Object.freeze(['running', 'queued']);

/**
 * @param {boolean} feedActive
 * @param {string|null|undefined} lastStatus  terminal or runtime status from latest run/queue
 * @param {number} consecutiveFailures
 * @param {string[]} [metricsHints]
 * @param {{ truncated?: boolean, partial?: boolean, runDetails?: object|null }} [opts]
 * @returns {'disabled'|'failed'|'warning'|'success'|'never'}
 */
export function resolveFeedHealthState(
  feedActive,
  lastStatus,
  consecutiveFailures = 0,
  metricsHints = [],
  opts = {}
) {
  if (feedActive === false) return 'disabled';

  const st = String(lastStatus || '').toLowerCase();
  const hints = Array.isArray(metricsHints) ? metricsHints : [];

  if (st === 'failed' || st === 'fail') return 'failed';

  // Runtime is not a health outcome — fall through to last known terminal classification
  // only when we have no better signal. Callers should prefer a terminal status when available.
  if (FEED_RUNTIME_STATUSES.includes(st)) {
    if (Number(consecutiveFailures || 0) > 0) return 'warning';
    if (hints.includes('high_failed') || hints.includes('partial_fetch')) return 'warning';
    // In-flight with no prior failure: do not alarm.
    return 'success';
  }

  if (st === 'never' || !st) return 'never';

  if (hints.includes('high_failed') || hints.includes('partial_fetch')) return 'warning';
  if (opts.truncated === true || opts.partial === true) return 'warning';
  if (runDetailsIndicatesPartial(opts.runDetails)) return 'warning';
  if (Number(consecutiveFailures || 0) > 0) return 'warning';

  if (FEED_HEALTHY_STATUSES.includes(st)) return 'success';

  // Unknown terminal status — treat as warning so operators notice unexpected values.
  return 'warning';
}

function runDetailsIndicatesPartial(runDetails) {
  if (!runDetails || typeof runDetails !== 'object') return false;
  if (runDetails.truncated === true) return true;
  if (runDetails.partial === true) return true;
  if (runDetails.reconciliation_complete === false) return true;
  if (runDetails.summary && runDetails.summary.truncated === true) return true;
  return false;
}

/**
 * Separate runtime/job state from health.
 * @param {string|null|undefined} lastStatus
 * @returns {'running'|'queued'|null}
 */
export function resolveFeedRuntimeState(lastStatus) {
  const st = String(lastStatus || '').toLowerCase();
  if (st === 'running' || st === 'queued') return st;
  return null;
}

/**
 * Prefer a terminal status for health when the latest row is still in-flight.
 * @param {object|null|undefined} latestRow
 * @param {object|null|undefined} lastSuccessRow
 */
export function pickHealthStatus(latestRow, lastSuccessRow) {
  const latest = String(latestRow?.status || '').toLowerCase();
  if (FEED_RUNTIME_STATUSES.includes(latest)) {
    // Prefer last known terminal outcome from the success map or latest finished row.
    const successStatus = lastSuccessRow?.status;
    if (successStatus) return String(successStatus).toLowerCase();
    // Still running and never completed — keep runtime out of health by returning never
    // only when there is truly no prior terminal run. Callers pass lastSuccess; if absent,
    // treat as never so UI shows Never run rather than Warning.
    return 'never';
  }
  return latest || 'never';
}
