import { FAILURE_MESSAGES, FAILURE_TYPES, QUEUE_HARDENING } from './integrationQueueConfig.js';

export function getJobLastSeenMs(job) {
  const raw = job?.heartbeat_at || job?.updated_at || job?.started_at;
  if (!raw) return null;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : null;
}

export function getJobStartedMs(job) {
  const raw = job?.started_at || job?.queued_at;
  if (!raw) return null;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : null;
}

export function classifyRunningJobForRecovery(job, nowMs = Date.now(), config = QUEUE_HARDENING) {
  if (String(job?.status || '').toLowerCase() !== 'running') return null;

  const startedMs = getJobStartedMs(job);
  const lastSeenMs = getJobLastSeenMs(job);
  const referenceMs = lastSeenMs ?? startedMs;
  if (referenceMs == null) return null;

  const runningAgeMs = startedMs != null ? nowMs - startedMs : nowMs - referenceMs;
  if (runningAgeMs > config.jobTimeoutMs) {
    return { failureType: FAILURE_TYPES.TIMEOUT, ageMs: runningAgeMs, message: FAILURE_MESSAGES.timeout };
  }

  const staleAgeMs = nowMs - referenceMs;
  if (staleAgeMs > config.staleAfterMs) {
    return { failureType: FAILURE_TYPES.STALE, ageMs: staleAgeMs, message: FAILURE_MESSAGES.stale };
  }

  return null;
}

export function isSourceActivelyRunning(rows, integrationKey, excludeJobId, nowMs = Date.now(), config = QUEUE_HARDENING) {
  const key = String(integrationKey || '').trim();
  const exclude = String(excludeJobId || '').trim();
  for (const row of rows || []) {
    if (String(row.integration_key || '').trim() !== key) continue;
    if (exclude && String(row.job_id || '').trim() === exclude) continue;
    if (String(row.status || '').toLowerCase() !== 'running') continue;
    if (!classifyRunningJobForRecovery(row, nowMs, config)) {
      return row;
    }
  }
  return null;
}

export async function findActiveRunningJobForSource(pool, integrationKey, excludeJobId = null) {
  const q = await pool.query(
    `SELECT job_id, integration_key, status, started_at, queued_at, heartbeat_at, updated_at, worker_id
     FROM integration_queue_jobs
     WHERE integration_key = $1
       AND status = 'running'
       AND ($2::text IS NULL OR job_id <> $2)
     ORDER BY COALESCE(started_at, queued_at) DESC`,
    [integrationKey, excludeJobId]
  );
  return isSourceActivelyRunning(q.rows, integrationKey, excludeJobId);
}

export async function markQueueJobFailed(pool, jobId, { message, failureType }) {
  await pool.query(
    `UPDATE integration_queue_jobs
     SET status = 'failed',
         finished_at = COALESCE(finished_at, NOW()),
         error_message = $2,
         failure_type = $3,
         updated_at = NOW()
     WHERE job_id = $1`,
    [String(jobId), String(message || 'unknown error').slice(0, 4000), failureType || null]
  );
}

export async function recoverStaleRunningJobs(pool, { logPrefix = '[integration-worker]' } = {}) {
  const runningQ = await pool.query(
    `SELECT job_id, integration_key, status, started_at, queued_at, heartbeat_at, updated_at, worker_id
     FROM integration_queue_jobs
     WHERE status = 'running'`
  );

  const nowMs = Date.now();
  let staleCount = 0;
  const recovered = [];

  for (const row of runningQ.rows) {
    const classification = classifyRunningJobForRecovery(row, nowMs);
    if (!classification) continue;

    await markQueueJobFailed(pool, row.job_id, {
      message: classification.message,
      failureType: classification.failureType
    });

    staleCount += 1;
    recovered.push({
      job_id: row.job_id,
      integration_key: row.integration_key,
      failure_type: classification.failureType,
      age_ms: classification.ageMs
    });

    console.log(
      `${logPrefix} Marked stale running job as failed job_id=${row.job_id} source=${row.integration_key} failure_type=${classification.failureType} age_ms=${classification.ageMs}`
    );
  }

  const fixedFinished = await pool.query(
    `UPDATE integration_queue_jobs
     SET status = CASE WHEN error_message IS NULL THEN 'success' ELSE 'failed' END,
         updated_at = NOW()
     WHERE status = 'running'
       AND finished_at IS NOT NULL
     RETURNING job_id`
  );

  const runsFixed = await pool.query(
    `UPDATE integration_runs
     SET status = 'failed',
         finished_at = COALESCE(finished_at, NOW()),
         error_message = COALESCE(error_message, $1)
     WHERE status = 'running'
       AND started_at < NOW() - ($2::text || ' milliseconds')::interval
     RETURNING id, job_type`,
    [FAILURE_MESSAGES.stale, String(QUEUE_HARDENING.staleAfterMs)]
  );

  if (runsFixed.rowCount > 0) {
    console.log(`${logPrefix} Reconciled stale integration_runs count=${runsFixed.rowCount}`);
  }

  return {
    staleCount,
    recovered,
    fixedFinishedCount: fixedFinished.rowCount || 0,
    fixedRunsCount: runsFixed.rowCount || 0
  };
}

export async function runQueueRecovery(pool, { logPrefix = '[integration-worker]' } = {}) {
  console.log(`${logPrefix} Queue recovery started`);
  const result = await recoverStaleRunningJobs(pool, { logPrefix });
  console.log(
    `${logPrefix} Queue recovery completed stale_count=${result.staleCount} fixed_finished=${result.fixedFinishedCount} fixed_runs=${result.fixedRunsCount}`
  );
  return result;
}

export function enrichIntegrationQueueJobRow(row, nowMs = Date.now()) {
  const state = String(row.state || row.status || '').toLowerCase();
  const startedRaw = row.started_at || (state === 'running' ? row.timestamp : null);
  const startedMs = startedRaw ? new Date(startedRaw).getTime() : null;
  const runningForMs = state === 'running' && startedMs ? Math.max(0, nowMs - startedMs) : null;
  const possiblyStuck = state === 'running' && classifyRunningJobForRecovery({
    status: 'running',
    started_at: row.started_at || row.timestamp,
    heartbeat_at: row.heartbeat_at,
    updated_at: row.updated_at,
    queued_at: row.queued_at || row.timestamp
  }, nowMs) != null;

  const failureType = row.failure_type || null;
  let failedReason = row.failed_reason || row.error_message || null;
  if (!failedReason && failureType) {
    if (failureType === FAILURE_TYPES.STALE) failedReason = FAILURE_MESSAGES.stale;
    else if (failureType === FAILURE_TYPES.TIMEOUT) failedReason = FAILURE_MESSAGES.timeout;
  }

  return {
    ...row,
    running_for_ms: runningForMs,
    possibly_stuck: possiblyStuck,
    failure_type: failureType,
    failed_reason: failedReason
  };
}
