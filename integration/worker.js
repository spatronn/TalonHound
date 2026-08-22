import { Worker } from 'bullmq';
import { config } from './config.js';
import { createIntegrationPool } from './lib/pg-pool.js';
import { importQueue, redis } from './queue.js';
import { runHourlyImport, runUsomImport, runUrlhausImport, runThreatfoxImport, runMalwareBazaarImport, runPhishtankImport, runAlienvaultOtxImport } from './importer.js';
import { sanitizeUrlhausErrorMessage } from './lib/urlhaus.js';
import { sanitizeMalwareBazaarErrorMessage } from './lib/malwarebazaar.js';
import { sanitizeThreatFoxErrorMessage } from './lib/threatfox.js';
import { sanitizeOtxErrorMessage } from './lib/alienvaultOtx.js';
import { sanitizeUsomLogValue } from './lib/usomNormalizer.js';
import {
  QUEUE_HARDENING,
  FAILURE_MESSAGES,
  FAILURE_TYPES,
  resolveIntegrationJobTimeoutMs
} from './lib/integrationQueueConfig.js';
import { recoverStaleRunningJobs, runQueueRecovery } from './lib/integrationQueueRecovery.js';
import {
  createWorkerIdentity,
  markJobRunning,
  startJobHeartbeat,
  markJobSuccess,
  markJobSkipped,
  markJobFailed
} from './lib/integrationQueueJobState.js';
import { resolveFeedSyncConcurrency, feedSyncLockIdentity } from './lib/feedSyncConcurrency.js';
import { acquireFeedSyncLock } from './lib/feedSyncLock.js';
import { runFeedDataPurgeJob } from './lib/feedLifecycle.js';
import { withImportOptimizationContext } from './lib/iocExpiration.js';
import { runCustomThreatFeedImport } from './lib/customThreatFeedImport.js';
import { runSpamhausDropSync } from './lib/spamhausDropSync.js';
import { runFileArtifactReconciliation } from './runFileArtifactReconciliation.js';
import { resolveWorkerJobFailureType } from './lib/job-cancellation.js';
import {
  enqueueMalwareBazaarHistoricalRecovery,
  runMalwareBazaarHistoricalRecovery
} from './lib/malwarebazaarHistoricalRecovery.js';

const pool = createIntegrationPool();

const LOG_PREFIX = '[integration-worker]';
// Global cap on simultaneous feed syncs across the whole deployment. Enforced in
// Redis via BullMQ global concurrency (setGlobalConcurrency below), so it holds
// across every trigger and every worker process — not just within this Node
// process. The per-worker `concurrency` is set to the same value so a single
// worker container can actually fill all global slots; adding more worker
// replicas cannot exceed the global ceiling.
const FEED_SYNC_CONCURRENCY = resolveFeedSyncConcurrency(process.env.FEED_SYNC_CONCURRENCY, {
  logger: (msg) => console.warn(`${LOG_PREFIX} ${msg}`)
});
const WORKER_LOCK_DURATION_MS = Math.max(Number(process.env.WORKER_LOCK_DURATION_MS || 300000), 60000);
const WORKER_STALLED_INTERVAL_MS = Math.max(Number(process.env.WORKER_STALLED_INTERVAL_MS || 60000), 10000);
const WORKER_MAX_STALLED_COUNT = Math.max(Number(process.env.WORKER_MAX_STALLED_COUNT || 5), 1);

const { workerId, hostname: workerHostname } = createWorkerIdentity();

let shuttingDown = false;
let activeJobId = null;
let activeJobAbortController = null;
let cleanupTimer = null;

function resolveIntegrationKey(job) {
  if (job?.data?.integration_key) return job.data.integration_key;
  if (job?.name === 'feed_data_purge') return job.data.integration_key || job.data.feed_key || 'unknown';
  if (job?.name === 'custom-threat-feed-sync') return job.data.integration_key || 'unknown';
  if (job?.name === 'spamhaus-drop-sync') return 'spamhaus-drop';
  if (job?.name === 'file-artifact-reconciliation') return 'file-artifact';
  if (job?.name === 'hourly-import') return 'et-blockrules';
  if (job?.name === 'usom-import') return 'usom-trcert';
  if (job?.name === 'urlhaus-import') return 'urlhaus-abusech';
  if (job?.name === 'threatfox-import') return 'threatfox-abusech';
  if (job?.name === 'malwarebazaar-import') return 'malwarebazaar-abusech';
  if (job?.name === 'malwarebazaar-historical-recovery') return 'malwarebazaar-abusech';
  if (job?.name === 'phishtank-import') return 'phishtank-opendnsrr';
  if (job?.name === 'alienvault-otx-import') return 'alienvault-otx';
  return 'unknown';
}

const JOB_TYPE_BY_NAME = Object.freeze({
  'hourly-import': 'hourly_import',
  'usom-import': 'usom_import',
  'urlhaus-import': 'urlhaus_import',
  'threatfox-import': 'threatfox_import',
  'malwarebazaar-import': 'malwarebazaar_import',
  'malwarebazaar-historical-recovery': 'malwarebazaar_historical_recovery',
  'phishtank-import': 'phishtank_import',
  'alienvault-otx-import': 'alienvault_otx_import',
  'custom-threat-feed-sync': 'custom_threat_feed_sync',
  'feed_data_purge': 'feed_data_purge',
  'spamhaus-drop-sync': 'spamhaus_drop_sync',
  'file-artifact-reconciliation': 'file_artifact_reconciliation'
});

function resolveJobType(job, result) {
  return result?.jobType
    || result?.job_type
    || JOB_TYPE_BY_NAME[job?.name]
    || null;
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
  if (integrationKey === 'threatfox-abusech') {
    return sanitizeThreatFoxErrorMessage(raw).slice(0, 4000);
  }
  if (integrationKey === 'alienvault-otx') {
    return sanitizeOtxErrorMessage(raw).slice(0, 4000);
  }
  if (integrationKey === 'usom-trcert') {
    return sanitizeUsomLogValue(raw, 4000);
  }
  return raw.slice(0, 4000);
}

async function runImportForJob(job, { signal, triggeredBy } = {}) {
  const opts = { signal, triggeredBy: triggeredBy || job?.data?.triggeredBy || 'scheduler', job };
  if (job.name === 'feed_data_purge') return runFeedDataPurgeJob(pool, job, opts);
  if (job.name === 'custom-threat-feed-sync') {
    return runCustomThreatFeedImport(pool, {
      ...opts,
      integrationKey: job?.data?.integration_key,
      jobId: String(job.id)
    });
  }
  if (job.name === 'spamhaus-drop-sync') {
    return runSpamhausDropSync(pool, opts);
  }
  if (job.name === 'file-artifact-reconciliation') {
    return runFileArtifactReconciliation(pool, opts);
  }
  if (job.name === 'hourly-import') return runHourlyImport(opts);
  if (job.name === 'usom-import') return runUsomImport(opts);
  if (job.name === 'urlhaus-import') return runUrlhausImport(opts);
  if (job.name === 'threatfox-import') return runThreatfoxImport(opts);
  if (job.name === 'malwarebazaar-import') return runMalwareBazaarImport(opts);
  if (job.name === 'malwarebazaar-historical-recovery') {
    const client = await pool.connect();
    try {
      return await withImportOptimizationContext(client, () => runMalwareBazaarHistoricalRecovery({
        ...opts,
        client,
        sourceName: config.malwareBazaarSourceName,
        from: job?.data?.from || null,
        to: job?.data?.to || null,
        dryRun: false
      }));
    } finally {
      client.release();
    }
  }
  if (job.name === 'phishtank-import') return runPhishtankImport(opts);
  if (job.name === 'alienvault-otx-import') return runAlienvaultOtxImport(opts);
  return { skipped: true, reason: 'unknown_job' };
}

async function executeJobWithTimeout(job, integrationKey) {
  const timeoutInfo = resolveIntegrationJobTimeoutMs(
    integrationKey,
    job?.name,
    QUEUE_HARDENING.jobTimeoutMs
  );
  const timeoutMs = timeoutInfo.timeoutMs;
  const controller = new AbortController();
  activeJobAbortController = controller;
  const { signal } = controller;
  let timer;
  let timedOut = false;

  const importPromise = runImportForJob(job, {
    signal,
    triggeredBy: job?.data?.triggeredBy || 'scheduler'
  });

  try {
    return await Promise.race([
      importPromise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          console.log(`${LOG_PREFIX} Job cooperative cancel reason=timeout job_id=${job.id} timeout_ms=${timeoutMs}`);
          controller.abort(FAILURE_TYPES.TIMEOUT);
          reject(Object.assign(new Error(FAILURE_MESSAGES.timeout), {
            failureType: FAILURE_TYPES.TIMEOUT,
            timeoutMs
          }));
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    activeJobAbortController = null;
    if (timedOut) {
      try {
        await importPromise;
        console.warn(
          `${LOG_PREFIX} Import completed after timeout job_id=${job.id}; integration_runs may disagree with queue status`
        );
      } catch {
        // expected when abort propagates
      }
    }
  }
}

const { waitUntilSetupComplete } = await import('./lib/systemTime.js');
const { setSystemScheduleTimezoneOverride } = await import('./lib/integrationSchedule.js');
const systemTz = await waitUntilSetupComplete(pool, { logPrefix: LOG_PREFIX });
process.env.TZ = systemTz;
process.env.SYSTEM_TIMEZONE = systemTz;
setSystemScheduleTimezoneOverride(systemTz);

// Enforce the global feed-sync concurrency ceiling in Redis. This is authoritative
// across every worker process/container consuming this queue: BullMQ will keep
// excess jobs in `waiting` and only move up to FEED_SYNC_CONCURRENCY into `active`
// at once, automatically handing a freed slot to the next waiting job (FIFO/priority).
try {
  await importQueue.setGlobalConcurrency(FEED_SYNC_CONCURRENCY);
  console.log(`${LOG_PREFIX} Global feed sync concurrency set concurrency_limit=${FEED_SYNC_CONCURRENCY} queue=${config.queueName}`);
} catch (err) {
  console.error(`${LOG_PREFIX} Failed to set global concurrency`, err?.message || err);
  throw err;
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

    // Atomic, cross-process per-feed exclusion. A busy feed's duplicate trigger is
    // skipped (not deferred-then-rerun) so it never causes a redundant overlapping
    // sync or duplicate ingestion. The global concurrency ceiling is enforced
    // upstream in Redis, so reaching here already means a global slot was free.
    const lockIdentity = feedSyncLockIdentity(integrationKey, job.name);
    const feedLock = await acquireFeedSyncLock(pool, lockIdentity);
    if (!feedLock.acquired) {
      await markJobSkipped(pool, String(job.id), {}, FAILURE_TYPES.SOURCE_BUSY, {
        triggeredBy,
        jobName: job.name,
        jobType: JOB_TYPE_BY_NAME[job.name] || null
      });
      console.log(
        `${LOG_PREFIX} Feed sync skipped reason=already_running job_id=${job.id} source=${integrationKey} name=${job.name} triggered_by=${triggeredBy} concurrency_limit=${FEED_SYNC_CONCURRENCY}`
      );
      activeJobId = null;
      return { skipped: true, reason: 'source_busy' };
    }

    const timeoutInfo = resolveIntegrationJobTimeoutMs(
      integrationKey,
      job.name,
      QUEUE_HARDENING.jobTimeoutMs
    );

    await markJobRunning(pool, {
      jobId: String(job.id),
      integrationKey,
      jobName: job.name,
      triggeredBy,
      workerId,
      workerHostname
    });

    const jobStartedAtMs = Date.now();
    console.log(
      `${LOG_PREFIX} Feed sync started job_id=${job.id} source=${integrationKey} name=${job.name} triggered_by=${triggeredBy} worker_id=${workerId} concurrency_limit=${FEED_SYNC_CONCURRENCY} timeout_ms=${timeoutInfo.timeoutMs} timeout_source=${timeoutInfo.source}`
    );

    const stopHeartbeat = startJobHeartbeat(pool, String(job.id), QUEUE_HARDENING.heartbeatIntervalMs);

    try {
      const result = await executeJobWithTimeout(job, integrationKey);

      const metrics = result?.metrics || {
        records_processed: Number(result?.metrics?.records_processed ?? result?.records_processed ?? 0),
        records_inserted: Number(result?.metrics?.records_inserted ?? result?.records_inserted ?? 0),
        records_updated: Number(result?.metrics?.records_updated ?? result?.records_updated ?? 0),
        records_duplicate: Number(result?.metrics?.records_duplicate ?? result?.records_duplicate ?? 0),
        records_unchanged: Number(result?.metrics?.records_unchanged ?? result?.records_unchanged ?? 0),
        records_reactivated: Number(result?.metrics?.records_reactivated ?? result?.records_reactivated ?? 0),
        records_removed: Number(result?.metrics?.records_removed ?? result?.records_removed ?? 0),
        records_skipped: Number(result?.metrics?.records_skipped ?? result?.records_skipped ?? 0),
        records_suppressed: Number(result?.metrics?.records_suppressed ?? result?.records_suppressed ?? result?.suppressed_count ?? 0),
        records_failed: Number(result?.metrics?.records_failed ?? result?.records_failed ?? 0)
      };

      const jobMeta = {
        triggeredBy,
        runMode: result?.mode || result?.run_mode || job?.data?.run_mode || null,
        jobType: resolveJobType(job, result),
        jobName: job.name,
        runDetails: result?.runDetails || result?.run_details || null,
        fetched: result?.fetched ?? result?.metrics?.fetched ?? null,
        parsed: result?.parsed ?? result?.metrics?.parsed ?? null
      };

      if (result?.skipped) {
        await markJobSkipped(pool, String(job.id), metrics, result.reason, jobMeta);
      } else {
        await markJobSuccess(pool, String(job.id), metrics, jobMeta);
      }

      if (job.name === 'malwarebazaar-import' && result?.shouldEnqueueRecovery) {
        try {
          await enqueueMalwareBazaarHistoricalRecovery(importQueue, { triggeredBy: 'gap-detection' });
        } catch (err) {
          console.warn(
            `${LOG_PREFIX} MalwareBazaar recovery enqueue failed job_id=${job.id} message=${sanitizeMalwareBazaarErrorMessage(err?.message || err)}`
          );
        }
      }
      if (job.name === 'malwarebazaar-historical-recovery' && result?.shouldRequeue) {
        try {
          await enqueueMalwareBazaarHistoricalRecovery(importQueue, {
            triggeredBy: 'recovery-resume',
            from: job?.data?.from || null,
            to: job?.data?.to || null
          });
        } catch (err) {
          console.warn(
            `${LOG_PREFIX} MalwareBazaar recovery requeue failed job_id=${job.id} message=${sanitizeMalwareBazaarErrorMessage(err?.message || err)}`
          );
        }
      }

      const skipNote = result?.skipped ? ` skipped=${result.reason || 'true'}` : '';
      console.log(
        `${LOG_PREFIX} Feed sync ${result?.skipped ? 'skipped' : 'completed'} job_id=${job.id} source=${integrationKey}${skipNote} records_processed=${metrics.records_processed || 0} duration_ms=${Date.now() - jobStartedAtMs}`
      );
      return result;
    } finally {
      stopHeartbeat();
      // Always release the per-feed exclusion lock: success, skip, parser/HTTP
      // error, timeout, DB error, or unexpected throw all pass through here, so a
      // failed feed can never permanently hold a slot from 2 down to 1.
      await feedLock.release();
      activeJobId = null;
    }
  },
  {
    connection: redis,
    concurrency: FEED_SYNC_CONCURRENCY,
    lockDuration: WORKER_LOCK_DURATION_MS,
    stalledInterval: WORKER_STALLED_INTERVAL_MS,
    maxStalledCount: WORKER_MAX_STALLED_COUNT
  }
);

worker.on('failed', async (job, err) => {
  if (err?.name === 'DelayedError') return;
  const safeMsg = safeJobErrorMessage(job, err);
  const failureType = resolveWorkerJobFailureType(err);
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
  if (activeJobAbortController) {
    console.log(`${LOG_PREFIX} Job cooperative cancel reason=worker_shutdown job_id=${activeJobId || '-'}`);
    activeJobAbortController.abort(FAILURE_TYPES.WORKER_SHUTDOWN);
  }
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
  workerConcurrency: FEED_SYNC_CONCURRENCY
});
startPeriodicCleanup();

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { shutdown(sig).catch((err) => {
    console.error(`${LOG_PREFIX} shutdown error`, err?.message || err);
    process.exit(1);
  }); });
}
