/**
 * Immutable job-queue result snapshot — shared by worker writers and Job Queue API.
 *
 * Reuses normalizeLastRunResult / splitSkippedSemantics so Feeds Last Result and
 * Job Queue Result stay semantically aligned for the same metrics.
 */

import { normalizeLastRunResult } from './feedLastRunResult.js';

export const JOB_RESULT_SCHEMA_VERSION = 1;

export const RESULT_CODES = Object.freeze({
  COMPLETED_WITH_CHANGES: 'COMPLETED_WITH_CHANGES',
  COMPLETED_NO_CHANGES: 'COMPLETED_NO_CHANGES',
  COMPLETED_NO_NEW_DATA: 'COMPLETED_NO_NEW_DATA',
  COMPLETED_WITH_WARNINGS: 'COMPLETED_WITH_WARNINGS',
  SKIPPED_UNCHANGED: 'SKIPPED_UNCHANGED',
  SKIPPED_LOCKED: 'SKIPPED_LOCKED',
  SKIPPED: 'SKIPPED',
  FAILED: 'FAILED'
});

const RESULT_DETAILS_KEYS = Object.freeze([
  'schema_version',
  'mode',
  'trigger',
  'fetched',
  'parsed',
  'checked',
  'new',
  'updated',
  'unchanged',
  'expired',
  'filtered',
  'rejected',
  'failed',
  'suppressed',
  'reactivated',
  'result_code',
  // File Artifact reconciliation (additive)
  'scanned',
  'mappings_found',
  'merged',
  'promoted_to_sha256',
  'conflicts',
  'skipped',
  'errors',
  'created_hashes',
  'created_source_observations',
  'duration_ms'
]);

const UNCHANGED_SKIP_REASONS = new Set([
  'unchanged',
  'same_hash',
  'etag',
  'canonical_unchanged',
  'content_unchanged'
]);

function metricInt(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
}

function fmtCount(value) {
  return metricInt(value).toLocaleString('en-US');
}

/**
 * Compact operator-facing summary (no "Completed ·" prefix — State carries that).
 * @param {{
 *   result_code?: string|null,
 *   outcome?: string|null,
 *   new?: number,
 *   updated?: number,
 *   expired?: number,
 *   message?: string|null
 * }} normalized
 */
export function formatJobResultSummary(normalized) {
  const code = String(normalized?.result_code || '').toUpperCase();
  if (code === RESULT_CODES.FAILED || normalized?.status === 'failed') return 'Failed';
  if (code === RESULT_CODES.SKIPPED_LOCKED) return 'Skipped · locked';
  if (code === RESULT_CODES.SKIPPED_UNCHANGED) return 'No changes';
  if (code === RESULT_CODES.SKIPPED) {
    return normalized?.message ? String(normalized.message).slice(0, 120) : 'Skipped';
  }
  if (code === RESULT_CODES.COMPLETED_WITH_WARNINGS) {
    return normalized?.message
      ? `Partial · ${String(normalized.message).slice(0, 80)}`
      : 'Partial result';
  }
  if (code === RESULT_CODES.COMPLETED_NO_NEW_DATA || normalized?.outcome === 'no_new_data') {
    return 'No new data';
  }
  if (code === RESULT_CODES.COMPLETED_NO_CHANGES || normalized?.outcome === 'no_changes') {
    return 'No changes';
  }

  const bits = [];
  if (metricInt(normalized?.new) > 0) bits.push(`${fmtCount(normalized.new)} new`);
  if (metricInt(normalized?.updated) > 0) bits.push(`${fmtCount(normalized.updated)} updated`);
  if (bits.length) return bits.join(' · ');

  if (metricInt(normalized?.expired) > 0) {
    return `${fmtCount(normalized.expired)} expired`;
  }
  return 'No changes';
}

/**
 * Map skip reason → result code.
 * @param {string|null|undefined} reason
 */
export function resolveSkipResultCode(reason) {
  const r = String(reason || '').trim().toLowerCase().replace(/^skipped:/, '');
  if (!r) return RESULT_CODES.SKIPPED;
  if (r === 'lock_not_acquired' || r === 'source_busy') return RESULT_CODES.SKIPPED_LOCKED;
  if (
    UNCHANGED_SKIP_REASONS.has(r)
    || r.includes('unchanged')
    || r === 'same_hash'
    || r.startsWith('etag')
  ) {
    return RESULT_CODES.SKIPPED_UNCHANGED;
  }
  return RESULT_CODES.SKIPPED;
}

/**
 * Map normalizeLastRunResult outcome → result_code for success paths.
 */
export function resolveSuccessResultCode(normalized) {
  if (!normalized) return RESULT_CODES.COMPLETED_NO_CHANGES;
  if (normalized.status === 'failed') return RESULT_CODES.FAILED;
  if (normalized.status === 'completed_with_warnings') return RESULT_CODES.COMPLETED_WITH_WARNINGS;
  if (normalized.outcome === 'no_new_data') return RESULT_CODES.COMPLETED_NO_NEW_DATA;
  if (normalized.outcome === 'no_changes') return RESULT_CODES.COMPLETED_NO_CHANGES;
  if (normalized.outcome === 'changes' || metricInt(normalized.new) > 0 || metricInt(normalized.updated) > 0 || metricInt(normalized.reactivated) > 0) {
    return RESULT_CODES.COMPLETED_WITH_CHANGES;
  }
  if (metricInt(normalized.checked) === 0) return RESULT_CODES.COMPLETED_NO_NEW_DATA;
  return RESULT_CODES.COMPLETED_NO_CHANGES;
}

/**
 * Normalize trigger label for snapshot (scheduled vs manual variants).
 * @param {string|null|undefined} triggeredBy
 */
export function normalizeTriggerLabel(triggeredBy) {
  const t = String(triggeredBy || '').trim().toLowerCase();
  if (!t || t === 'scheduler' || t === 'scheduled' || t === 'repeatable') return 'scheduled';
  if (t.startsWith('manual') || t.includes('manual-ui') || t.includes(':manual')) return 'manual';
  if (t.includes('full_reconciliation') || t.includes('incremental')) {
    // USOM trigger like "manual-ui-one:incremental" or "scheduler:full_reconciliation"
    if (t.startsWith('scheduler') || t.startsWith('scheduled')) return 'scheduled';
    if (t.includes('manual')) return 'manual';
  }
  return t.slice(0, 64) || 'scheduled';
}

/**
 * Build immutable snapshot fields for a completed queue job.
 *
 * @param {{
 *   status: 'success'|'skipped'|'failed',
 *   metrics?: object|null,
 *   skipReason?: string|null,
 *   errorMessage?: string|null,
 *   runMode?: string|null,
 *   triggeredBy?: string|null,
 *   jobType?: string|null,
 *   jobName?: string|null,
 *   runDetails?: object|null,
 *   fetched?: number|null,
 *   parsed?: number|null
 * }} input
 * @returns {{
 *   result_code: string,
 *   result_summary: string,
 *   result_details: object,
 *   run_mode: string|null
 * }}
 */
export function buildJobResultSnapshot(input = {}) {
  const statusRaw = String(input.status || 'success').toLowerCase();
  const metrics = input.metrics || {};
  const runMode = input.runMode
    || metrics.run_mode
    || input.runDetails?.run_mode
    || null;
  const trigger = normalizeTriggerLabel(input.triggeredBy);

  const row = {
    status: statusRaw === 'skipped' ? 'skipped' : statusRaw,
    job_type: input.jobType || null,
    error_message: input.errorMessage || null,
    records_processed: metrics.records_processed,
    records_inserted: metrics.records_inserted,
    records_updated: metrics.records_updated,
    records_unchanged: metrics.records_unchanged ?? metrics.records_duplicate,
    records_duplicate: metrics.records_duplicate,
    records_reactivated: metrics.records_reactivated,
    records_removed: metrics.records_removed,
    records_skipped: metrics.records_skipped,
    records_suppressed: metrics.records_suppressed,
    records_failed: metrics.records_failed,
    run_details: input.runDetails || null
  };

  // For skipped_unchanged semantics when queue status is skipped + unchanged reason
  let normalizeStatus = statusRaw;
  if (statusRaw === 'skipped') {
    const skipCode = resolveSkipResultCode(input.skipReason);
    if (skipCode === RESULT_CODES.SKIPPED_UNCHANGED) {
      normalizeStatus = 'skipped_unchanged';
    }
  }

  const normalized = normalizeLastRunResult(row, {
    status: normalizeStatus === 'success' ? 'success' : normalizeStatus,
    jobType: input.jobType || null,
    errorMessage: input.errorMessage || (input.skipReason ? `skipped:${input.skipReason}` : null),
    runDetails: input.runDetails || null,
    lastRunMetrics: {
      available: true,
      processed: metricInt(metrics.records_processed),
      inserted: metricInt(metrics.records_inserted),
      updated: metricInt(metrics.records_updated),
      unchanged: metricInt(metrics.records_unchanged ?? metrics.records_duplicate),
      reactivated: metricInt(metrics.records_reactivated),
      removed: metricInt(metrics.records_removed),
      skipped: metricInt(metrics.records_skipped),
      suppressed: metricInt(metrics.records_suppressed),
      failed: metricInt(metrics.records_failed)
    }
  });

  let resultCode;
  if (statusRaw === 'failed') {
    resultCode = RESULT_CODES.FAILED;
  } else if (statusRaw === 'skipped') {
    resultCode = resolveSkipResultCode(input.skipReason);
  } else {
    resultCode = resolveSuccessResultCode(normalized);
  }

  const summaryInput = {
    ...normalized,
    result_code: resultCode,
    status: statusRaw === 'failed' ? 'failed' : normalized.status,
    message: statusRaw === 'skipped'
      ? (input.skipReason ? `skipped:${input.skipReason}` : 'skipped')
      : normalized.message
  };
  const resultSummary = formatJobResultSummary(summaryInput);

  const mode = runMode
    ? String(runMode).trim().toLowerCase() || null
    : null;

  const details = {
    schema_version: JOB_RESULT_SCHEMA_VERSION,
    mode,
    trigger,
    fetched: input.fetched != null ? metricInt(input.fetched) : null,
    parsed: input.parsed != null ? metricInt(input.parsed) : null,
    checked: metricInt(normalized.checked),
    new: metricInt(normalized.new),
    updated: metricInt(normalized.updated),
    unchanged: metricInt(normalized.unchanged),
    expired: metricInt(normalized.expired),
    filtered: metricInt(normalized.filtered),
    rejected: metricInt(normalized.rejected),
    failed: metricInt(normalized.failed),
    suppressed: metricInt(normalized.suppressed),
    reactivated: metricInt(normalized.reactivated),
    result_code: resultCode
  };

  const runDetails = input.runDetails && typeof input.runDetails === 'object' ? input.runDetails : null;
  if (runDetails) {
    for (const key of [
      'scanned',
      'mappings_found',
      'merged',
      'promoted_to_sha256',
      'conflicts',
      'skipped',
      'errors',
      'created_hashes',
      'created_source_observations',
      'duration_ms'
    ]) {
      if (runDetails[key] != null) details[key] = metricInt(runDetails[key]);
    }
  }

  return {
    result_code: resultCode,
    result_summary: resultSummary,
    result_details: details,
    run_mode: mode
  };
}

/**
 * Whitelist result_details from DB/API — drop unexpected keys / secrets.
 * @param {object|null|undefined} raw
 */
export function sanitizeResultDetails(raw) {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out = {};
  for (const key of RESULT_DETAILS_KEYS) {
    if (Object.prototype.hasOwnProperty.call(raw, key)) {
      out[key] = raw[key];
    }
  }
  if (out.schema_version == null && Object.keys(out).length === 0) return null;
  return out;
}

/**
 * Map queue job row → API `result` object (legacy-safe).
 * @param {object} row
 */
export function mapQueueJobResult(row) {
  if (!row) {
    return {
      available: false,
      result_code: null,
      result_summary: null,
      result_details: null,
      run_mode: null
    };
  }
  const hasSnapshot = row.result_code != null || row.result_summary != null || row.result_details != null;
  if (!hasSnapshot) {
    return {
      available: false,
      result_code: null,
      result_summary: null,
      result_details: null,
      run_mode: row.run_mode || null
    };
  }
  return {
    available: true,
    result_code: row.result_code || null,
    result_summary: row.result_summary || null,
    result_details: sanitizeResultDetails(row.result_details),
    run_mode: row.run_mode || null
  };
}

/**
 * Normalize metrics object from importer result for persistence.
 * @param {object|null|undefined} metrics
 */
export function normalizePersistMetrics(metrics) {
  const m = metrics || {};
  const unchanged = metricInt(m.records_unchanged ?? m.records_duplicate);
  const duplicate = metricInt(m.records_duplicate ?? m.records_unchanged);
  return {
    records_processed: metricInt(m.records_processed),
    records_inserted: metricInt(m.records_inserted),
    records_updated: metricInt(m.records_updated),
    records_duplicate: duplicate || unchanged,
    records_unchanged: unchanged || duplicate,
    records_reactivated: metricInt(m.records_reactivated),
    records_removed: metricInt(m.records_removed),
    records_skipped: metricInt(m.records_skipped),
    records_suppressed: metricInt(m.records_suppressed),
    records_failed: metricInt(m.records_failed)
  };
}

/** SQL SET fragment for clearing terminal snapshot when re-queuing a job_id. */
export const QUEUE_JOB_REQUEUE_RESET_SQL = `
  records_processed = 0,
  records_inserted = 0,
  records_updated = 0,
  records_duplicate = 0,
  records_unchanged = 0,
  records_reactivated = 0,
  records_removed = 0,
  records_skipped = 0,
  records_suppressed = 0,
  records_failed = 0,
  result_code = NULL,
  result_summary = NULL,
  result_details = NULL,
  run_mode = NULL
`.replace(/\s+/g, ' ').trim();
