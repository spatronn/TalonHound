import { FAILURE_TYPES } from './integrationQueueConfig.js';

export function createWorkerIdentity() {
  const workerId = `${process.pid}-${Date.now().toString(36)}`;
  const hostname = process.env.HOSTNAME || process.env.COMPUTERNAME || 'unknown';
  return { workerId, hostname };
}

export async function markJobRunning(pool, {
  jobId,
  integrationKey,
  jobName,
  triggeredBy,
  workerId,
  workerHostname
}) {
  await pool.query(
    `INSERT INTO integration_queue_jobs (
       job_id, integration_key, job_name, status, triggered_by,
       queued_at, started_at, heartbeat_at, worker_id, worker_hostname,
       failure_type, error_message, updated_at
     )
     VALUES ($1, $2, $3, 'running', $4, NOW(), NOW(), NOW(), $5, $6, NULL, NULL, NOW())
     ON CONFLICT (job_id)
     DO UPDATE SET
       status = 'running',
       started_at = COALESCE(integration_queue_jobs.started_at, NOW()),
       heartbeat_at = NOW(),
       worker_id = EXCLUDED.worker_id,
       worker_hostname = EXCLUDED.worker_hostname,
       failure_type = NULL,
       error_message = NULL,
       finished_at = NULL,
       updated_at = NOW()`,
    [String(jobId), integrationKey, jobName, triggeredBy || 'scheduler', workerId, workerHostname]
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

export async function markJobSuccess(pool, jobId, metrics) {
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
         error_message = NULL,
         failure_type = NULL,
         updated_at = NOW()
     WHERE job_id = $1`,
    [
      String(jobId),
      Number(metrics.records_processed || 0),
      Number(metrics.records_inserted || 0),
      Number(metrics.records_updated || 0),
      Number(metrics.records_duplicate || 0),
      Number(metrics.records_skipped || 0),
      Number(metrics.records_suppressed || 0),
      Number(metrics.records_failed || 0)
    ]
  );
}

export async function markJobFailed(pool, jobId, message, failureType = null) {
  await pool.query(
    `UPDATE integration_queue_jobs
     SET status = 'failed',
         finished_at = NOW(),
         error_message = $2,
         failure_type = $3,
         updated_at = NOW()
     WHERE job_id = $1`,
    [String(jobId), String(message || 'unknown error').slice(0, 4000), failureType]
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
