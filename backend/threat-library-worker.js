import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import IORedis from 'ioredis';
import { Queue, Worker } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { createServiceLogger } from './lib/appLogger.js';
import { getThreatLibraryQueueName, getThreatLibraryWorkerOptions } from './lib/threatLibrary/queueConfig.js';
import { runThreatLibraryJob } from './lib/threatLibrary/jobRunner.js';
import { parseJobMode, jobModeInvokesAi, isIocSourceJobMode, UnknownJobModeError } from './lib/threatLibrary/jobModes.js';
import { updateJob, getReportById, updateReportStatus } from './lib/threatLibrary/store.js';
import { createAuditLogService } from './lib/auditLogService.js';
import { auditAnalysisOutcome } from './lib/threatLibrary/audit.js';
import {
  dispatchQueuedThreatLibraryAnalyses,
  enqueueClaimedThreatLibraryJob,
  recoverInterruptedAnalysisJobs,
  resolveThreatLibraryWorkerConcurrency
} from './lib/threatLibrary/analysisConcurrency.js';
import { claimJobOwnership, startJobHeartbeat, requeueOwnedJob } from './lib/threatLibrary/jobOwnership.js';
import { createFencedDb } from './lib/threatLibrary/jobFence.js';
import { getInferenceScheduler } from './lib/threatLibrary/ai/inferenceScheduler.js';
import { probeQuarantinedCapacity } from './lib/threatLibrary/ai/capacityRecovery.js';
import { maybeScheduleAutoRetry } from './lib/threatLibrary/autoRetry.js';
import { buildRetryProgress } from './lib/threatLibrary/retryState.js';
import { AI_FAILURE_CODES, aiFailure } from './lib/threatLibrary/ai/timeouts.js';

const log = createServiceLogger('threat-library-worker');

// Refuse to run a stale worker image that still has the pre-streaming AI adapter.
// Compose used to build a separate image per service; building only `backend` left
// this worker on the old AbortController(timeout_ms) path.
const aiDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'lib', 'threatLibrary', 'ai');
for (const required of ['client.js', 'analyze.js', 'timeouts.js']) {
  if (!fs.existsSync(path.join(aiDir, required))) {
    log.error('stale threat-library-worker image', {
      missing: required,
      aiDir,
      hint: 'Rebuild/recreate using the shared talonhound-backend:local image'
    });
    process.exit(1);
  }
}

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const auditService = createAuditLogService(pool);
const redis = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
const queueName = getThreatLibraryQueueName();
const queue = new Queue(queueName, { connection: redis });
const concurrency = resolveThreatLibraryWorkerConcurrency();
const workerStartedAt = Date.now();
/** jobId → { controller, ownerToken } for jobs this process is running. */
const activeRuns = new Map();
/** BullMQ job id → owner token, so the `failed` handler writes only as that owner. */
const ownerByDelivery = new Map();
let shuttingDown = false;

async function dispatchQueuedAnalyses() {
  return dispatchQueuedThreatLibraryAnalyses(pool, {
    enqueue: (job) => enqueueClaimedThreatLibraryJob(queue, job)
  });
}

async function releaseSlotAndDispatch(reason, fields = {}) {
  log.info('report completed', { reason, ...fields });
  try {
    const result = await dispatchQueuedAnalyses();
    if (result.claimed.length) {
      log.info('next queued report claimed', {
        claimed: result.claimed.map((c) => ({ jobId: c.jobId, reportId: c.reportId })),
        occupied: result.occupied,
        limit: result.limit
      });
    }
  } catch (err) {
    log.warn('failed to dispatch queued analyses', { error: err?.message });
  }
}

const worker = new Worker(
  queueName,
  async (job) => {
    const reportId = Number(job.data?.reportId);
    const jobId = Number(job.data?.jobId);
    if (!reportId || !jobId) {
      throw new Error('Invalid threat library job payload');
    }
    // Explicit mode contract: an unknown mode never reaches a pipeline stage.
    let mode;
    try {
      mode = parseJobMode(job.data?.jobType || job.name);
    } catch (err) {
      if (!(err instanceof UnknownJobModeError)) throw err;
      log.warn('job rejected', { bullmqJobId: job.id, reportId, jobId, code: err.code });
      await updateJob(pool, jobId, { status: 'failed', stage: 'starting', error_message: err.code, bullmq_job_id: String(job.id) });
      // IOC-source jobs must never fail the parent report analysis.
      if (!isIocSourceJobMode(String(job.data?.jobType || job.name || ''))) {
        await updateReportStatus(pool, reportId, {
          analysis_status: 'failed',
          import_status: 'failed',
          failure_stage: 'starting',
          failure_code: err.code,
          failure_reason: err.message
        });
      }
      await releaseSlotAndDispatch('unknown_job_mode', { bullmqJobId: job.id, reportId, jobId });
      return { ok: false, code: err.code };
    }
    // One live owner per job: a duplicate delivery (stalled-lock re-delivery,
    // re-dispatch after recovery) yields to a live owner instead of running twice.
    const ownerToken = crypto.randomUUID();
    const claimed = await claimJobOwnership(pool, { jobId, ownerToken, bullmqJobId: String(job.id) });
    if (!claimed) {
      log.warn('duplicate delivery skipped; job owned by a live worker or already ended', { bullmqJobId: job.id, reportId, jobId, mode });
      return { ok: false, code: 'duplicate_delivery' };
    }
    log.info('job started', {
      bullmqJobId: job.id,
      reportId,
      jobId,
      mode,
      aiInvocationAllowed: jobModeInvokesAi(mode),
      resumeAnalysis: job.data?.resumeAnalysis === true,
      autoRetryAttempt: job.data?.jobPayload?.auto_retry?.attempt ?? null,
      aiClient: 'streaming-v4'
    });
    const controller = new AbortController();
    activeRuns.set(jobId, { controller, ownerToken });
    ownerByDelivery.set(String(job.id), ownerToken);
    let rethrowing = false;
    const heartbeat = startJobHeartbeat(pool, {
      jobId,
      ownerToken,
      onLost: () => controller.abort(aiFailure(AI_FAILURE_CODES.JOB_OWNERSHIP_LOST))
    });

    try {
      const result = await runThreatLibraryJob(pool, {
        reportId,
        jobId,
        sourceUrl: job.data?.sourceUrl,
        resumeAnalysis: job.data?.resumeAnalysis === true,
        jobType: mode,
        newAnalysisRun: job.data?.newAnalysisRun === true,
        restoreStatus: job.data?.restoreStatus,
        membershipPolicy: job.data?.membershipPolicy,
        jobPayload: job.data?.jobPayload,
        signal: controller.signal,
        // Every pipeline write is fenced on (jobId, ownerToken) in the same
        // transaction (jobFence.js): a run that lost the job commits nothing.
        fence: { jobId, ownerToken }
      });
      log.info('job finished', { bullmqJobId: job.id, reportId, mode, ok: result?.ok === true, code: result?.code });
      if (result?.interrupted) {
        if (result.code === AI_FAILURE_CODES.WORKER_SHUTDOWN) await requeueAfterShutdown(reportId, jobId, ownerToken);
        // Ownership lost: the new owner reports the outcome.
        return result;
      }
      if (!isIocSourceJobMode(mode)) {
        await auditAnalysisOutcome(pool, auditService, {
          reportId,
          jobId,
          ok: result?.ok === true,
          code: result?.code || null,
          summary: result?.summary || null
        });
        if (result && result.ok === false && !shuttingDown) {
          try {
            await maybeScheduleAutoRetry(pool, {
              reportId,
              jobId,
              jobType: mode,
              jobPayload: job.data?.jobPayload || null,
              result
            });
          } catch (err) {
            log.warn('automatic retry scheduling failed', { reportId, jobId, error: err?.message });
          }
        }
      }
      return result;
    } catch (err) {
      if (err?.code === AI_FAILURE_CODES.JOB_OWNERSHIP_LOST) {
        // A fenced write found the job owned by another worker: nothing was
        // committed; the new owner reports the outcome.
        log.warn('job ownership lost during the run; yielding', { bullmqJobId: job.id, reportId, jobId });
        return { ok: false, code: err.code, interrupted: true };
      }
      rethrowing = true; // the `failed` handler records it as this owner
      throw err;
    } finally {
      if (!rethrowing) ownerByDelivery.delete(String(job.id));
      heartbeat.stop();
      activeRuns.delete(jobId);
      await releaseSlotAndDispatch(mode, { bullmqJobId: job.id, reportId, jobId });
    }
  },
  {
    connection: redis,
    concurrency,
    ...getThreatLibraryWorkerOptions()
  }
);

worker.on('failed', async (job, err) => {
  log.warn('job failed', { bullmqJobId: job?.id, error: err?.message });
  const reportId = Number(job?.data?.reportId);
  const jobId = Number(job?.data?.jobId);
  if (reportId && jobId) {
    const ownerToken = ownerByDelivery.get(String(job?.id));
    ownerByDelivery.delete(String(job?.id));
    try {
      if (!ownerToken) {
        // Failed before this delivery owned the job (e.g. the claim itself
        // failed): it is not ours to mark; recovery re-queues a stale claim.
        throw Object.assign(new Error('delivery never owned the job'), { code: 'not_owner' });
      }
      // Fenced: never mark a job (or its report) that another worker now owns.
      const db = createFencedDb(pool, { jobId, ownerToken });
      const failedMode = String(job?.data?.jobType || job?.name || '');
      const report = await getReportById(pool, reportId);
      if (!isIocSourceJobMode(failedMode) && report && report.analysis_status === 'analyzing') {
        await updateReportStatus(db, reportId, {
          analysis_status: 'failed',
          import_status: 'failed',
          failure_stage: 'analyzing',
          failure_code: 'worker_failed',
          failure_reason: err?.message || 'Threat Library worker failed'
        });
      }
      await updateJob(db, jobId, {
        status: 'failed',
        stage: isIocSourceJobMode(failedMode) ? failedMode : 'analyzing',
        error_message: err?.message || 'worker failed'
      });
      if (!isIocSourceJobMode(failedMode)) {
        await auditAnalysisOutcome(pool, auditService, {
          reportId,
          jobId,
          ok: false,
          code: 'worker_failed',
          summary: null
        });
      }
    } catch (e) {
      if (e?.code === 'not_owner' || e?.code === AI_FAILURE_CODES.JOB_OWNERSHIP_LOST) {
        log.warn('worker failure not recorded: job is not owned by this delivery', { bullmqJobId: job?.id, jobId, code: e.code });
      } else {
        log.warn('failed to mark report after worker failure', { error: e?.message });
      }
    }
    await releaseSlotAndDispatch('worker_failed', { bullmqJobId: job?.id, reportId, jobId });
  }
});

/**
 * Graceful shutdown interrupted an AI run: hand the job back to the queue
 * (owner-guarded) so the next worker resumes from its checkpoints.
 */
async function requeueAfterShutdown(reportId, jobId, ownerToken) {
  try {
    const requeued = await requeueOwnedJob(pool, { jobId, ownerToken, reason: 'requeued after worker shutdown' });
    if (!requeued) return;
    const report = await getReportById(pool, reportId);
    await updateReportStatus(pool, reportId, {
      analysis_status: 'pending',
      import_status: 'processing',
      analysis_progress: {
        ...buildRetryProgress('pending', {
          candidate_extraction_version: report?.analysis_progress?.candidate_extraction_version || null
        }),
        extraction_diagnostics: report?.analysis_progress?.extraction_diagnostics || undefined,
        interrupted: { reason: 'worker_shutdown', at: new Date().toISOString() }
      }
    });
    log.info('analysis requeued after worker shutdown', { reportId, jobId });
  } catch (err) {
    log.warn('failed to requeue analysis after shutdown; crash recovery will pick it up', { reportId, jobId, error: err?.message });
  }
}

async function recoverThenDispatch() {
  try {
    const active = await queue.getJobs(['active']);
    for (const job of active) {
      if (job.processedOn && job.processedOn < workerStartedAt - 2000) {
        await job.moveToFailed(new Error('worker_restarted'), job.token, true).catch(() => {});
        log.info('stale analysis recovered', {
          bullmqJobId: job.id,
          reportId: job.data?.reportId || null,
          reason: 'worker_restarted'
        });
      }
    }
    const recovered = await recoverInterruptedAnalysisJobs(pool, {
      getJobState: async (id) => {
        const job = await queue.getJob(id);
        return job ? job.getState() : null;
      }
    });
    const dispatched = await dispatchQueuedAnalyses();
    log.info('scheduler recovered', {
      recovered: recovered.length,
      claimed: dispatched.claimed.length,
      occupied: dispatched.occupied,
      limit: dispatched.limit
    });
  } catch (err) {
    log.warn('failed to recover queued analyses', { error: err?.message });
  }
}

worker.on('ready', () => {
  log.info('worker ready', {
    queue: queueName,
    concurrency,
    aiClient: 'streaming-v3',
    version: process.env.TALONHOUND_VERSION || null
  });
  recoverThenDispatch().catch(() => {});
});

// Bounded safety net: import/complete/settings already dispatch directly.
// Also dispatches delayed automatic retries once due, and recovers jobs whose
// owner (this or another worker process) stopped heartbeating.
const DISPATCH_SAFETY_MS = 30_000;
const safetyTimer = setInterval(async () => {
  if (shuttingDown) return;
  try {
    const recovered = await recoverInterruptedAnalysisJobs(pool, {
      getJobState: async (id) => {
        const j = await queue.getJob(id);
        return j ? j.getState() : null;
      }
    });
    if (recovered.length) log.info('scheduler recovered', { recovered: recovered.length, source: 'safety_net' });
  } catch (err) {
    log.warn('failed to recover interrupted analyses', { error: err?.message, source: 'safety_net' });
  }
  // Quarantined AI capacity is probed even when no analysis is waiting, so a
  // provider that recovered frees its slot without manual action.
  try {
    const outcome = await probeQuarantinedCapacity(pool, getInferenceScheduler(pool));
    if (outcome === 'released') log.info('quarantined AI capacity released after idle probe', { source: 'safety_net' });
  } catch (err) {
    log.warn('quarantined AI capacity probe failed', { error: err?.message, source: 'safety_net' });
  }
  dispatchQueuedAnalyses().catch((err) => {
    log.warn('failed to dispatch queued analyses', { error: err?.message, source: 'safety_net' });
  });
}, DISPATCH_SAFETY_MS);
if (typeof safetyTimer.unref === 'function') safetyTimer.unref();

async function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  clearInterval(safetyTimer);
  // Stop in-flight AI work now (Compose gives ~10s before SIGKILL): each run
  // cancels its provider request, releases its inference slot and is requeued.
  for (const [jobId, run] of activeRuns) {
    log.info('interrupting analysis for shutdown', { jobId });
    run.controller.abort(aiFailure(AI_FAILURE_CODES.WORKER_SHUTDOWN));
  }
  await worker.close();
  await queue.close();
  await redis.quit();
  await pool.end();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
