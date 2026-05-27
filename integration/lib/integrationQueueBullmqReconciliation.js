import { FAILURE_MESSAGES, FAILURE_TYPES } from './integrationQueueConfig.js';
import {
  classifyRunningJobForRecovery,
  markQueueJobFailed
} from './integrationQueueRecovery.js';

export const BULLMQ_TERMINAL_STATES = new Set(['completed', 'failed']);

export function isDbTerminalStatus(status) {
  const s = String(status || '').toLowerCase();
  return s === 'failed' || s === 'success';
}

export function isBullmqReconcilableState(state) {
  const s = String(state || '').toLowerCase();
  return s === 'active' || s === 'stalled';
}

export async function loadDbJobsByIds(pool, jobIds) {
  const ids = [...new Set((jobIds || []).map((id) => String(id)).filter(Boolean))];
  if (!ids.length) return new Map();
  const q = await pool.query(
    `SELECT job_id, integration_key, job_name, status, started_at, heartbeat_at, worker_id, failure_type
     FROM integration_queue_jobs
     WHERE job_id = ANY($1::text[])`,
    [ids]
  );
  return new Map(q.rows.map((row) => [String(row.job_id), row]));
}

export async function getBullmqJobState(job) {
  try {
    return await job.getState();
  } catch {
    return 'unknown';
  }
}

/**
 * Idempotently close a BullMQ job that is blocking the queue.
 */
export async function moveBullJobToFailed(job, message, { dryRun = false } = {}) {
  if (!job?.id) return { ok: false, skipped: true, reason: 'no_job' };
  const jobId = String(job.id);
  if (dryRun) return { ok: true, dryRun: true, job_id: jobId };

  const state = await getBullmqJobState(job);
  if (BULLMQ_TERMINAL_STATES.has(state)) {
    return { ok: true, skipped: true, job_id: jobId, state };
  }
  if (!isBullmqReconcilableState(state) && state !== 'unknown') {
    return { ok: true, skipped: true, job_id: jobId, state, reason: 'not_reconcilable_state' };
  }

  try {
    await job.moveToFailed(new Error(message), '0', true);
    return { ok: true, job_id: jobId, state: await getBullmqJobState(job) };
  } catch (err) {
    const msg = String(err?.message || err);
    if (msg.includes('Missing lock') || msg.includes('not in the active state')) {
      try {
        await job.discard();
        return { ok: true, job_id: jobId, discarded: true };
      } catch (discardErr) {
        return { ok: false, job_id: jobId, error: discardErr?.message || String(discardErr) };
      }
    }
    return { ok: false, job_id: jobId, error: msg };
  }
}

async function reconcileOneBullJob({
  pool,
  bullJob,
  dbRow,
  dryRun,
  logPrefix,
  nowMs
}) {
  const jobId = String(bullJob.id);
  const bullState = await getBullmqJobState(bullJob);
  if (!isBullmqReconcilableState(bullState)) {
    return { kind: 'skipped', job_id: jobId, reason: `bullmq_state=${bullState}` };
  }

  const dbStatus = dbRow ? String(dbRow.status || '').toLowerCase() : null;

  if (dbRow && isDbTerminalStatus(dbStatus)) {
    const bullResult = await moveBullJobToFailed(bullJob, FAILURE_MESSAGES.reconciled, { dryRun });
    console.log(
      `${logPrefix} Reconciled stale active job job_id=${jobId} source=${dbRow.integration_key || '-'} db_status=${dbStatus} bullmq_state=${bullState}`
    );
    return {
      kind: 'reconciled_terminal_db',
      job_id: jobId,
      integration_key: dbRow.integration_key,
      db_status: dbStatus,
      bullmq_state: bullState,
      bull_result: bullResult
    };
  }

  if (dbRow && dbStatus === 'running') {
    const classification = classifyRunningJobForRecovery(dbRow, nowMs);
    if (classification) {
      if (!dryRun) {
        await markQueueJobFailed(pool, jobId, {
          message: classification.message,
          failureType: classification.failureType
        });
      }
      const bullResult = await moveBullJobToFailed(bullJob, classification.message, { dryRun });
      console.log(
        `${logPrefix} Reconciled stale running job job_id=${jobId} source=${dbRow.integration_key} failure_type=${classification.failureType} bullmq_state=${bullState}`
      );
      return {
        kind: 'reconciled_stale_running',
        job_id: jobId,
        integration_key: dbRow.integration_key,
        failure_type: classification.failureType,
        bullmq_state: bullState,
        bull_result: bullResult
      };
    }
    return { kind: 'skipped', job_id: jobId, reason: 'db_running_fresh' };
  }

  const bullResult = await moveBullJobToFailed(bullJob, FAILURE_MESSAGES.bullmq_orphan, { dryRun });
  if (!dryRun && dbRow && dbStatus === 'queued') {
    await markQueueJobFailed(pool, jobId, {
      message: FAILURE_MESSAGES.bullmq_orphan,
      failureType: FAILURE_TYPES.BULLMQ_ORPHAN
    });
  }
  console.log(
    `${logPrefix} Reconciled orphan BullMQ job job_id=${jobId} bullmq_state=${bullState} db_status=${dbStatus || 'missing'}`
  );
  return {
    kind: 'reconciled_orphan_bull',
    job_id: jobId,
    bullmq_state: bullState,
    db_status: dbStatus,
    bull_result: bullResult
  };
}

/**
 * Reconcile BullMQ active/stalled jobs with PostgreSQL integration_queue_jobs.
 */
export async function reconcileBullmqWithDb({
  pool,
  queue,
  dryRun = false,
  logPrefix = '[integration-worker]'
} = {}) {
  const nowMs = Date.now();
  const [bullCounts, activeJobs, stalledJobs] = await Promise.all([
    queue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed', 'paused'),
    queue.getJobs(['active'], 0, 500),
    queue.getJobs(['stalled'], 0, 500)
  ]);

  const bullById = new Map();
  for (const job of [...activeJobs, ...stalledJobs]) {
    bullById.set(String(job.id), job);
  }

  const dbMap = await loadDbJobsByIds(pool, [...bullById.keys()]);

  const staleActiveJobs = [];
  const staleStalledJobs = [];
  const actionsTaken = [];
  const skipped = [];

  for (const [jobId, bullJob] of bullById) {
    const bullState = await getBullmqJobState(bullJob);
    const entry = { job_id: jobId, bullmq_state: bullState, db: dbMap.get(jobId) || null };
    if (bullState === 'active') staleActiveJobs.push(entry);
    if (bullState === 'stalled') staleStalledJobs.push(entry);

    const result = await reconcileOneBullJob({
      pool,
      bullJob,
      dbRow: dbMap.get(jobId),
      dryRun,
      logPrefix,
      nowMs
    });
    if (result.kind === 'skipped') skipped.push(result);
    else actionsTaken.push(result);
  }

  return {
    bull_counts: bullCounts,
    stale_active_jobs: staleActiveJobs,
    stale_stalled_jobs: staleStalledJobs,
    actions_taken: actionsTaken,
    skipped,
    reconciled_count: actionsTaken.length
  };
}

/**
 * Release orphan DB "source locks" (running rows that are stale or not backed by BullMQ).
 */
export async function releaseOrphanDbSourceLocks({
  pool,
  queue,
  dryRun = false,
  logPrefix = '[integration-worker]'
} = {}) {
  const nowMs = Date.now();
  const [runningRes, activeJobs, waitingJobs, delayedJobs] = await Promise.all([
    pool.query(
      `SELECT job_id, integration_key, status, started_at, heartbeat_at, worker_id
       FROM integration_queue_jobs
       WHERE status = 'running'`
    ),
    queue.getJobs(['active'], 0, 500),
    queue.getJobs(['waiting'], 0, 500),
    queue.getJobs(['delayed'], 0, 500)
  ]);

  const liveBullIds = new Set([
    ...activeJobs.map((j) => String(j.id)),
    ...waitingJobs.map((j) => String(j.id)),
    ...delayedJobs.map((j) => String(j.id))
  ]);

  const orphanLocks = [];
  const actionsTaken = [];

  for (const row of runningRes.rows) {
    const jobId = String(row.job_id);
    const classification = classifyRunningJobForRecovery(row, nowMs);
    const notInBullmq = !liveBullIds.has(jobId);

    if (!classification && !notInBullmq) continue;

    orphanLocks.push({
      job_id: jobId,
      integration_key: row.integration_key,
      reason: classification ? classification.failureType : 'not_in_bullmq',
      worker_id: row.worker_id
    });

    const message = classification?.message
      || FAILURE_MESSAGES.reconciled;
    const failureType = classification?.failureType || FAILURE_TYPES.RECONCILED;

    if (!dryRun) {
      await markQueueJobFailed(pool, jobId, { message, failureType });
      const bullJob = await queue.getJob(jobId);
      if (bullJob) {
        await moveBullJobToFailed(bullJob, message, { dryRun: false });
      }
    }

    console.log(
      `${logPrefix} Released orphan source lock job_id=${jobId} source=${row.integration_key} reason=${failureType}`
    );
    actionsTaken.push({ job_id: jobId, integration_key: row.integration_key, failure_type: failureType });
  }

  return { orphan_locks: orphanLocks, released_count: actionsTaken.length, actions_taken: actionsTaken };
}

export async function failBullmqJobsForDbRecovered(pool, queue, recoveredRows, { dryRun = false, logPrefix } = {}) {
  const results = [];
  for (const row of recoveredRows || []) {
    const jobId = String(row.job_id);
    const bullJob = await queue.getJob(jobId);
    if (!bullJob) continue;
    const bullResult = await moveBullJobToFailed(
      bullJob,
      row.message || FAILURE_MESSAGES.stale,
      { dryRun }
    );
    if (!dryRun && bullResult.ok) {
      console.log(`${logPrefix} Closed BullMQ job after DB stale recovery job_id=${jobId}`);
    }
    results.push({ job_id: jobId, bull_result: bullResult });
  }
  return results;
}
