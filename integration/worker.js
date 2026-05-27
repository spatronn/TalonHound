import { Worker, DelayedError } from 'bullmq';
import pg from 'pg';
import { config } from './config.js';
import { importQueue, redis } from './queue.js';
import { runHourlyImport, runUsomImport, runUrlhausImport, runThreatfoxImport, runMalwareBazaarImport, runPhishtankImport } from './importer.js';
import { sanitizeUrlhausErrorMessage } from './lib/urlhaus.js';
import { sanitizeMalwareBazaarErrorMessage } from './lib/malwarebazaar.js';
import { QUEUE_HARDENING, FAILURE_MESSAGES, FAILURE_TYPES } from './lib/integrationQueueConfig.js';
import { findActiveRunningJobForSource, recoverStaleRunningJobs, runQueueRecovery } from './lib/integrationQueueRecovery.js';
import {
  createWorkerIdentity,
  markJobRunning,
  startJobHeartbeat,
  markJobSuccess,
  markJobFailed,
  markJobDeferredSourceBusy,
  inferFailureTypeFromError
} from './lib/integrationQueueJobState.js';

const { Pool } = pg;
const pool = new Pool(config.db);

const LOG_PREFIX = '[integration-worker]';
const WORKER_CONCURRENCY = Math.max(Number(process.env.WORKER_CONCURRENCY || 1), 1);
const WORKER_LOCK_DURATION_MS = Math.max(Number(process.env.WORKER_LOCK_DURATION_MS || 300000), 60000);
const WORKER_STALLED_INTERVAL_MS = Math.max(Number(process.env.WORKER_STALLED_INTERVAL_MS || 60000), 10000);
const WORKER_MAX_STALLED_COUNT = Math.max(Number(process.env.WORKER_MAX_STALLED_COUNT || 5), 1);

const { workerId, hostname: workerHostname } = createWorkerIdentity();

let shuttingDown = false;
let activeJobId = null;
let cleanupTimer = null;

function resolveIntegrationKey(job) {
  if (job?.data?.integration_key) return job.data.integration_key;
  if (job?.name === 'hourly-import') return 'et-blockrules';
  if (job?.name === 'usom-import') return 'usom-trcert';
  if (job?.name === 'urlhaus-import') return 'urlhaus-abusech';
  if (job?.name === 'threatfox-import') return 'threatfox-abusech';
  if (job?.name === 'malwarebazaar-import') return 'malwarebazaar-abusech';
  if (job?.name === 'phishtank-import') return 'phishtank-opendnsrr';
  return 'unknown';
}

function safeJobErrorMessage(job, err) {
  const raw = String(err?.message || 'unknown error');
  const integrationKey = resolveIntegrationKey(job);
  if (integrationKey === 'urlhaus-abusech') {
    return sanitizeUrlhausErrorMessage(raw).slice(0, 4000);
  }
  if (integrationKey === 'malwarebazaar-abusech') {
    return sanitizeMalwareBazaarErrorMessage(raw).slice(0, 4000);
  }
  return raw.slice(0, 4000);
}

async function runImportForJob(job) {
  if (job.name === 'hourly-import') return runHourlyImport();
  if (job.name === 'usom-import') return runUsomImport();
  if (job.name === 'urlhaus-import') return runUrlhausImport();
  if (job.name === 'threatfox-import') return runThreatfoxImport();
  if (job.name === 'malwarebazaar-import') return runMalwareBazaarImport();
  if (job.name === 'phishtank-import') return runPhishtankImport();
  return { skipped: true, reason: 'unknown_job' };
}

async function executeJobWithTimeout(job, integrationKey) {
  const timeoutMs = QUEUE_HARDENING.jobTimeoutMs;
  let timer;
  try {
    return await Promise.race([
      runImportForJob(job),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(Object.assign(new Error(FAILURE_MESSAGES.timeout), { failureType: FAILURE_TYPES.TIMEOUT }));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

const worker = new Worker(
  config.queueName,
  async (job) => {
    if (shuttingDown) {
      throw Object.assign(new Error(FAILURE_MESSAGES.worker_shutdown), { failureType: FAILURE_TYPES.WORKER_SHUTDOWN });
    }

    const integrationKey = resolveIntegrationKey(job);
    const triggeredBy = job?.data?.triggeredBy || 'scheduler';
    activeJobId = String(job.id);

    const blocking = await findActiveRunningJobForSource(pool, integrationKey, String(job.id));
    if (blocking) {
      await markJobDeferredSourceBusy(pool, String(job.id));
      await job.moveToDelayed(Date.now() + QUEUE_HARDENING.sourceBusyDeferMs, job.token);
      console.log(
        `${LOG_PREFIX} Same source already running; deferred job_id=${job.id} source=${integrationKey} blocking_job_id=${blocking.job_id}`
      );
      throw new DelayedError();
    }

    await markJobRunning(pool, {
      jobId: String(job.id),
      integrationKey,
      jobName: job.name,
      triggeredBy,
      workerId,
      workerHostname
    });

    console.log(
      `${LOG_PREFIX} Job started job_id=${job.id} source=${integrationKey} name=${job.name} triggered_by=${triggeredBy} worker_id=${workerId}`
    );

    const stopHeartbeat = startJobHeartbeat(pool, String(job.id), QUEUE_HARDENING.heartbeatIntervalMs);

    try {
      const result = await executeJobWithTimeout(job, integrationKey);

      const metrics = result?.metrics || {
        records_processed: Number(result?.records_processed || result?.recordsProcessed || 0),
        records_inserted: Number(result?.records_inserted ?? result?.recordsProcessed ?? 0),
        records_updated: Number(result?.records_updated || 0),
        records_duplicate: Number(result?.records_duplicate || 0),
        records_skipped: Number(result?.records_skipped || 0),
        records_suppressed: Number(result?.records_suppressed || result?.suppressed_count || 0),
        records_failed: Number(result?.records_failed || 0)
      };

      await markJobSuccess(pool, String(job.id), metrics);

      const skipNote = result?.skipped ? ` skipped=${result.reason || 'true'}` : '';
      console.log(
        `${LOG_PREFIX} Job completed job_id=${job.id} source=${integrationKey}${skipNote} records_processed=${metrics.records_processed || 0}`
      );
      return result;
    } finally {
      stopHeartbeat();
      activeJobId = null;
    }
  },
  {
    connection: redis,
    concurrency: WORKER_CONCURRENCY,
    lockDuration: WORKER_LOCK_DURATION_MS,
    stalledInterval: WORKER_STALLED_INTERVAL_MS,
    maxStalledCount: WORKER_MAX_STALLED_COUNT
  }
);

worker.on('failed', async (job, err) => {
  if (err?.name === 'DelayedError') return;
  const safeMsg = safeJobErrorMessage(job, err);
  const failureType = err?.failureType || inferFailureTypeFromError(err);
  console.error(
    `${LOG_PREFIX} Job failed job_id=${job?.id} source=${job ? resolveIntegrationKey(job) : 'unknown'} attemptsMade=${job?.attemptsMade} failure_type=${failureType || '-'} message=${safeMsg}`
  );
  try {
    if (job?.id) {
      await markJobFailed(pool, String(job.id), safeMsg, failureType);
    }
  } catch (e) {
    console.error(`${LOG_PREFIX} failed to persist failed state`, e?.message || e);
  }
});

worker.on('error', (err) => {
  console.error(`${LOG_PREFIX} worker error`, err?.message || err);
});

function startPeriodicCleanup() {
  cleanupTimer = setInterval(async () => {
    try {
      const result = await recoverStaleRunningJobs(pool, { logPrefix: LOG_PREFIX, queue: importQueue });
      if (result.staleCount > 0) {
        console.log(`${LOG_PREFIX} Periodic cleanup stale_count=${result.staleCount}`);
      }
    } catch (err) {
      console.error(`${LOG_PREFIX} periodic cleanup failed`, err?.message || err);
    }
  }, QUEUE_HARDENING.cleanupIntervalMs);
  cleanupTimer.unref?.();
}

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${LOG_PREFIX} Graceful shutdown started signal=${signal} grace_ms=${QUEUE_HARDENING.shutdownGraceMs}`);

  if (cleanupTimer) clearInterval(cleanupTimer);

  const closePromise = worker.close();
  let closedInTime = false;
  await Promise.race([
    closePromise.then(() => { closedInTime = true; }),
    new Promise((resolve) => setTimeout(resolve, QUEUE_HARDENING.shutdownGraceMs))
  ]);

  if (!closedInTime && activeJobId) {
    console.log(
      `${LOG_PREFIX} Shutdown grace expired with active job job_id=${activeJobId}; stale recovery will reconcile on next startup`
    );
  } else {
    console.log(`${LOG_PREFIX} Worker stopped accepting jobs`);
  }

  try {
    await redis.quit();
  } catch {
    // ignore
  }
  try {
    await pool.end();
  } catch {
    // ignore
  }

  console.log(`${LOG_PREFIX} Graceful shutdown completed`);
  process.exit(0);
}

await runQueueRecovery(pool, {
  logPrefix: LOG_PREFIX,
  queue: importQueue,
  workerConcurrency: WORKER_CONCURRENCY
});
startPeriodicCleanup();

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { shutdown(sig).catch((err) => {
    console.error(`${LOG_PREFIX} shutdown error`, err?.message || err);
    process.exit(1);
  }); });
}
