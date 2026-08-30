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

export function getQueueKeyPrefix(queue) {
  return queue.qualifiedName || `bull:${queue.name}`;
}

/** Job still listed in BullMQ active/stalled while DB says otherwise (or missing). */
export async function isBlockingBullmqEntry(dbRow, bullState, nowMs = Date.now(), { job = null, isGhost = false } = {}) {
  if (!isBullmqReconcilableState(bullState)) return false;
  if (!dbRow) {
    if (isGhost) return true;
    if (bullState === 'stalled') return true;
    if (job && typeof job.isActive === 'function') {
      try {
        if (await job.isActive()) return false;
      } catch {
        // fall through
      }
    }
    return true;
  }
  const dbStatus = String(dbRow.status || '').toLowerCase();
  if (isDbTerminalStatus(dbStatus)) return true;
  if (dbStatus === 'queued') return true;
  if (dbStatus === 'running' && classifyRunningJobForRecovery(dbRow, nowMs)) return true;
  return false;
}

export async function purgeJobFromBullmqLists(queue, jobId) {
  const client = await queue.client;
  const prefix = getQueueKeyPrefix(queue);
  const id = String(jobId);
  const removed = {
    active: await client.lrem(`${prefix}:active`, 0, id),
    stalled: await client.srem(`${prefix}:stalled`, id)
  };
  try {
    await client.del(`${prefix}:${id}:lock`);
  } catch {
    // ignore
  }
  return removed;
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
    const state = await getBullmqJobState(job);
    return { ok: true, job_id: jobId, state };
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

export async function moveBullJobToFailedAndPurge(job, message, { dryRun = false, queue = null } = {}) {
  const result = await moveBullJobToFailed(job, message, { dryRun });
  if (!dryRun && queue?.client && job?.id) {
    const purged = await purgeJobFromBullmqLists(queue, job.id);
    return { ...result, purged };
  }
  return result;
}

async function reconcileGhostBullJobId(queue, jobId, { dryRun, logPrefix } = {}) {
  if (!dryRun) {
    const purged = await purgeJobFromBullmqLists(queue, jobId);
    console.log(`${logPrefix} Purged ghost BullMQ list entry job_id=${jobId} purged=${JSON.stringify(purged)}`);
    return { ok: true, ghost: true, purged };
  }
  return { ok: true, dryRun: true, ghost: true };
}

async function reconcileOneBullJob({
  pool,
  queue,
  bullJob,
  dbRow,
  dryRun,
  logPrefix,
  nowMs,
  isGhost = false
}) {
  const jobId = String(bullJob.id);
  const bullState = isGhost ? 'active' : await getBullmqJobState(bullJob);

  if (isGhost) {
    const bullResult = await reconcileGhostBullJobId(queue, jobId, { dryRun, logPrefix });
    return {
      kind: 'reconciled_ghost_list',
      job_id: jobId,
      bullmq_state: bullState,
      db_status: dbRow ? String(dbRow.status || '').toLowerCase() : null,
      bull_result: bullResult
    };
  }

  if (!isBullmqReconcilableState(bullState)) {
    if (!dryRun) await purgeJobFromBullmqLists(queue, jobId);
    return { kind: 'skipped', job_id: jobId, reason: `bullmq_state=${bullState}` };
  }

  const dbStatus = dbRow ? String(dbRow.status || '').toLowerCase() : null;

  if (dbRow && isDbTerminalStatus(dbStatus)) {
    const bullResult = await moveBullJobToFailedAndPurge(bullJob, FAILURE_MESSAGES.reconciled, { dryRun, queue });
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
      const bullResult = await moveBullJobToFailedAndPurge(bullJob, classification.message, { dryRun, queue });
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

  if (!dbRow && !isGhost && typeof bullJob.isActive === 'function') {
    try {
      if (await bullJob.isActive()) {
        return { kind: 'skipped', job_id: jobId, reason: 'live_repeat_job' };
      }
    } catch {
      // continue with orphan reconcile
    }
  }

  const bullResult = await moveBullJobToFailedAndPurge(bullJob, FAILURE_MESSAGES.bullmq_orphan, { dryRun, queue });
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

export async function loadStalledBullJobs(queue, limit = 500) {
  const jobs = [];
  try {
    const client = await queue.client;
    const prefix = getQueueKeyPrefix(queue);
    const stalledIds = await client.smembers(`${prefix}:stalled`);
    for (const id of stalledIds.slice(0, limit)) {
      const job = await queue.getJob(id);
      if (job) jobs.push(job);
    }
  } catch (err) {
    console.warn(`[integration-queue] loadStalledBullJobs failed: ${err?.message || err}`);
  }
  return jobs;
}

/**
 * Count jobs BullMQ genuinely considers STALLED right now (for the health gauge).
 *
 * The raw `<prefix>:stalled` SET is NOT a set of confirmed-stalled jobs. BullMQ's
 * moveStalledJobsToWait check unconditionally re-adds EVERY active job to this set
 * on each stalled-check as a "potentially stalled" candidate and only verifies the
 * lock on the NEXT check (see moveStalledJobsToWait.lua: SADD active -> stalled,
 * then EXISTS <job>:lock == 0 => really stalled). So a healthy long-running job
 * always appears here between checks, and counting raw membership makes any job
 * that merely outlives one stalledInterval look stalled -> queue health Degraded.
 *
 * A candidate is only really stalled when its lock key is missing AND it is still
 * sitting in the active list — exactly BullMQ's own criterion. This filters to
 * those, so the gauge reflects real stalls, not liveness of long jobs.
 */
export async function loadTrulyStalledBullJobs(queue, limit = 500) {
  const jobs = [];
  try {
    const client = await queue.client;
    const prefix = getQueueKeyPrefix(queue);
    const stalledIds = await client.smembers(`${prefix}:stalled`);
    for (const id of stalledIds.slice(0, limit)) {
      // Lock still held => worker is alive and renewing => healthy active candidate.
      if ((await client.exists(`${prefix}:${id}:lock`)) === 1) continue;
      const job = await queue.getJob(id);
      if (!job) continue; // completed/removed between checks => not stalled
      // Only active-list jobs with a missing lock are genuinely stalled right now;
      // a completed/waiting job in the leftover candidate set is not.
      if ((await getBullmqJobState(job)) !== 'active') continue;
      jobs.push(job);
    }
  } catch (err) {
    console.warn(`[integration-queue] loadTrulyStalledBullJobs failed: ${err?.message || err}`);
  }
  return jobs;
}

export async function loadRedisListedBullJobIds(queue, limit = 500) {
  const client = await queue.client;
  const prefix = getQueueKeyPrefix(queue);
  const [activeIds, stalledIds] = await Promise.all([
    client.lrange(`${prefix}:active`, 0, limit - 1),
    client.smembers(`${prefix}:stalled`)
  ]);
  return [...new Set([...activeIds, ...stalledIds].map((id) => String(id)).filter(Boolean))].slice(0, limit);
}

/** Union of BullMQ API jobs and raw Redis active/stalled list entries. */
export async function loadAllReconcilableBullJobs(queue, limit = 500) {
  const [activeJobs, stalledJobs, listedIds] = await Promise.all([
    queue.getJobs(['active'], 0, limit),
    loadStalledBullJobs(queue, limit),
    loadRedisListedBullJobIds(queue, limit)
  ]);

  const byId = new Map();
  for (const job of [...activeJobs, ...stalledJobs]) {
    byId.set(String(job.id), { job, isGhost: false });
  }
  for (const id of listedIds) {
    if (!byId.has(id)) {
      const job = await queue.getJob(id);
      byId.set(id, { job: job || { id }, isGhost: !job });
    }
  }
  return [...byId.entries()].map(([id, meta]) => ({ id, ...meta }));
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
  const [bullCounts, reconcilableEntries, stalledJobs] = await Promise.all([
    queue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed', 'paused'),
    loadAllReconcilableBullJobs(queue, 500),
    loadStalledBullJobs(queue, 500)
  ]);

  let stalledListed = 0;
  try {
    const client = await queue.client;
    stalledListed = (await client.smembers(`${getQueueKeyPrefix(queue)}:stalled`)).length;
  } catch {
    stalledListed = stalledJobs.length;
  }

  const bullCountsFull = {
    ...bullCounts,
    stalled: stalledListed
  };

  const jobIds = reconcilableEntries.map((e) => e.id);
  const dbMap = await loadDbJobsByIds(pool, jobIds);

  const staleActiveJobs = [];
  const staleStalledJobs = [];
  const actionsTaken = [];
  const skipped = [];

  for (const { id: jobId, job: bullJob, isGhost } of reconcilableEntries) {
    const bullState = isGhost ? 'active' : await getBullmqJobState(bullJob);
    const dbRow = dbMap.get(jobId) || null;
    const entry = { job_id: jobId, bullmq_state: bullState, db: dbRow };

    if (await isBlockingBullmqEntry(dbRow, bullState, nowMs, { job: bullJob, isGhost })) {
      if (bullState === 'active' || isGhost) staleActiveJobs.push(entry);
      if (bullState === 'stalled') staleStalledJobs.push(entry);
    }

    const result = await reconcileOneBullJob({
      pool,
      queue,
      bullJob,
      dbRow,
      dryRun,
      logPrefix,
      nowMs,
      isGhost
    });
    if (result.kind === 'skipped') skipped.push(result);
    else actionsTaken.push(result);
  }

  if (!dryRun) {
    const remainingIds = await loadRedisListedBullJobIds(queue, 500);
    for (const jobId of remainingIds) {
      const dbRow = dbMap.get(jobId) || null;
      if (!(await isBlockingBullmqEntry(dbRow, 'active', nowMs, { isGhost: true }))) continue;
      const purged = await purgeJobFromBullmqLists(queue, jobId);
      console.log(`${logPrefix} Purged remaining list entry job_id=${jobId} purged=${JSON.stringify(purged)}`);
      actionsTaken.push({ kind: 'purged_list_entry', job_id: jobId, purged });
    }
  }

  return {
    bull_counts: bullCountsFull,
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
      `SELECT job_id, integration_key, job_name, status, started_at, heartbeat_at, worker_id
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
        await moveBullJobToFailedAndPurge(bullJob, message, { dryRun: false, queue });
      } else if (!dryRun) {
        await purgeJobFromBullmqLists(queue, jobId);
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
    const bullResult = await moveBullJobToFailedAndPurge(
      bullJob,
      row.message || FAILURE_MESSAGES.stale,
      { dryRun, queue }
    );
    if (!dryRun && bullResult.ok) {
      console.log(`${logPrefix} Closed BullMQ job after DB stale recovery job_id=${jobId}`);
    }
    results.push({ job_id: jobId, bull_result: bullResult });
  }
  return results;
}
