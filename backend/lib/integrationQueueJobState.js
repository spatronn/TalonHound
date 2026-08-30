import { FAILURE_TYPES } from './integrationQueueConfig.js';
import {
  buildJobResultSnapshot,
  normalizePersistMetrics
} from './jobResultSnapshot.js';

export function createWorkerIdentity() {
  const workerId = `${process.pid}-${Date.now().toString(36)}`;
  const hostname = process.env.HOSTNAME || process.env.COMPUTERNAME || 'unknown';
  return { workerId, hostname };
}

export function coerceQueuedAt(queuedAt) {
  if (queuedAt instanceof Date && !Number.isNaN(queuedAt.getTime())) return queuedAt.toISOString();
  if (typeof queuedAt === 'number' && Number.isFinite(queuedAt) && queuedAt > 0) {
    return new Date(queuedAt).toISOString();
  }
  if (typeof queuedAt === 'string' && queuedAt.trim()) {
    const parsed = new Date(queuedAt);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return null;
}

export async function markJobRunning(pool, {
  jobId,
  integrationKey,
  jobName,
  triggeredBy,
  workerId,
  workerHostname,
  queuedAt
}) {
  const queuedAtIso = coerceQueuedAt(queuedAt);
  await pool.query(
    `INSERT INTO integration_queue_jobs (
       job_id, integration_key, job_name, status, triggered_by,
       queued_at, started_at, heartbeat_at, worker_id, worker_hostname,
       failure_type, error_message, updated_at
     )
     VALUES ($1, $2, $3, 'running', $4, COALESCE($7::timestamptz, NOW()), NOW(), NOW(), $5, $6, NULL, NULL, NOW())
     ON CONFLICT (job_id)
     DO UPDATE SET
       status = 'running',
       started_at = COALESCE(integration_queue_jobs.started_at, NOW()),
       queued_at = COALESCE(integration_queue_jobs.queued_at, EXCLUDED.queued_at),
       heartbeat_at = NOW(),
       worker_id = EXCLUDED.worker_id,
       worker_hostname = EXCLUDED.worker_hostname,
       failure_type = NULL,
       error_message = NULL,
       finished_at = NULL,
       updated_at = NOW()`,
    [String(jobId), integrationKey, jobName, triggeredBy || 'scheduler', workerId, workerHostname, queuedAtIso]
  );
}

export async function touchJobHeartbeat(pool, jobId) {
  await pool.query(
    `UPDATE integration_queue_jobs
     SET heartbeat_at = NOW(), updated_at = NOW()
     WHERE job_id = $1 AND status = 'running'`,
    [String(jobId)]
  );
}

export function startJobHeartbeat(pool, jobId, intervalMs) {
  let stopped = false;
  const timer = setInterval(() => {
    touchJobHeartbeat(pool, jobId).catch((err) => {
      console.error(`[integration-worker] heartbeat update failed job_id=${jobId} message=${err?.message || err}`);
    });
  }, intervalMs);
  timer.unref?.();

  return () => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
  };
}

/**
 * Persist terminal success with immutable result snapshot.
 * @param {import('pg').Pool} pool
 * @param {string} jobId
 * @param {object} metrics
 * @param {{
 *   triggeredBy?: string|null,
 *   runMode?: string|null,
 *   jobType?: string|null,
 *   jobName?: string|null,
 *   runDetails?: object|null,
 *   fetched?: number|null,
 *   parsed?: number|null
 * }} [meta]
 */
export async function markJobSuccess(pool, jobId, metrics, meta = {}) {
  const m = normalizePersistMetrics(metrics);
  const snapshot = buildJobResultSnapshot({
    status: 'success',
    metrics: m,
    runMode: meta.runMode || null,
    triggeredBy: meta.triggeredBy || null,
    jobType: meta.jobType || null,
    jobName: meta.jobName || null,
    runDetails: meta.runDetails || null,
    fetched: meta.fetched,
    parsed: meta.parsed
  });

  await pool.query(
    `UPDATE integration_queue_jobs
     SET status = 'success',
         finished_at = NOW(),
         records_processed = $2,
         records_inserted = $3,
         records_updated = $4,
         records_duplicate = $5,
         records_skipped = $6,
         records_suppressed = $7,
         records_failed = $8,
         records_unchanged = $9,
         records_reactivated = $10,
         records_removed = $11,
         result_code = $12,
         result_summary = $13,
         result_details = $14::jsonb,
         run_mode = $15,
         error_message = NULL,
         failure_type = NULL,
         updated_at = NOW()
     WHERE job_id = $1`,
    [
      String(jobId),
      m.records_processed,
      m.records_inserted,
      m.records_updated,
      m.records_duplicate,
      m.records_skipped,
      m.records_suppressed,
      m.records_failed,
      m.records_unchanged,
      m.records_reactivated,
      m.records_removed,
      snapshot.result_code,
      snapshot.result_summary,
      JSON.stringify(snapshot.result_details),
      snapshot.run_mode
    ]
  );
}

/**
 * Persist intentional skip with immutable result snapshot.
 */
export async function markJobSkipped(pool, jobId, metrics, reason = null, meta = {}) {
  const m = normalizePersistMetrics(metrics);
  const note = reason ? `skipped:${String(reason).slice(0, 200)}` : 'skipped';
  const snapshot = buildJobResultSnapshot({
    status: 'skipped',
    metrics: m,
    skipReason: reason,
    errorMessage: note,
    runMode: meta.runMode || null,
    triggeredBy: meta.triggeredBy || null,
    jobType: meta.jobType || null,
    jobName: meta.jobName || null,
    runDetails: meta.runDetails || null
  });

  await pool.query(
    `UPDATE integration_queue_jobs
     SET status = 'skipped',
         finished_at = NOW(),
         records_processed = $2,
         records_inserted = $3,
         records_updated = $4,
         records_duplicate = $5,
         records_skipped = $6,
         records_suppressed = $7,
         records_failed = $8,
         records_unchanged = $9,
         records_reactivated = $10,
         records_removed = $11,
         result_code = $12,
         result_summary = $13,
         result_details = $14::jsonb,
         run_mode = $15,
         error_message = $16,
         failure_type = NULL,
         updated_at = NOW()
     WHERE job_id = $1`,
    [
      String(jobId),
      m.records_processed,
      m.records_inserted,
      m.records_updated,
      m.records_duplicate,
      m.records_skipped,
      m.records_suppressed,
      m.records_failed,
      m.records_unchanged,
      m.records_reactivated,
      m.records_removed,
      snapshot.result_code,
      snapshot.result_summary,
      JSON.stringify(snapshot.result_details),
      snapshot.run_mode,
      note
    ]
  );
}

export async function markJobFailed(pool, jobId, message, failureType = null, meta = {}) {
  const safeMsg = String(message || 'unknown error').slice(0, 4000);
  const snapshot = buildJobResultSnapshot({
    status: 'failed',
    metrics: meta.metrics || {},
    errorMessage: safeMsg,
    runMode: meta.runMode || null,
    triggeredBy: meta.triggeredBy || null,
    jobType: meta.jobType || null,
    jobName: meta.jobName || null
  });

  await pool.query(
    `UPDATE integration_queue_jobs
     SET status = 'failed',
         finished_at = NOW(),
         error_message = $2,
         failure_type = $3,
         result_code = $4,
         result_summary = $5,
         result_details = $6::jsonb,
         run_mode = COALESCE($7, run_mode),
         updated_at = NOW()
     WHERE job_id = $1`,
    [
      String(jobId),
      safeMsg,
      failureType,
      snapshot.result_code,
      snapshot.result_summary,
      JSON.stringify(snapshot.result_details),
      snapshot.run_mode
    ]
  );
}

export async function markJobQueued(pool, jobId) {
  await pool.query(
    `UPDATE integration_queue_jobs
     SET status = 'queued',
         started_at = NULL,
         heartbeat_at = NULL,
         worker_id = NULL,
         worker_hostname = NULL,
         failure_type = NULL,
         updated_at = NOW()
     WHERE job_id = $1`,
    [String(jobId)]
  );
}

export async function markJobDeferredSourceBusy(pool, jobId) {
  await markJobQueued(pool, jobId);
}

export function inferFailureTypeFromError(err) {
  if (err?.failureType) return err.failureType;
  if (err?.name === 'IntegrationJobAbortedError') return err.failureType || FAILURE_TYPES.ABORTED;
  const msg = String(err?.message || '').toLowerCase();
  if (msg.includes('parse') || msg.includes('csv') || msg.includes('json')) {
    return FAILURE_TYPES.PARSE_ERROR;
  }
  if (msg.includes('fetch') || msg.includes('network') || msg.includes('timeout') || msg.includes('econn')) {
    return FAILURE_TYPES.FETCH_ERROR;
  }
  return null;
}
