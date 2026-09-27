import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import IORedis from 'ioredis';
import { Queue, Worker } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { createServiceLogger } from './lib/appLogger.js';
import { getThreatLibraryQueueName, getThreatLibraryWorkerOptions } from './lib/threatLibrary/queueConfig.js';
import { runAnalysisPipeline } from './lib/threatLibrary/pipeline.js';
import { updateJob, getReportById, updateReportStatus } from './lib/threatLibrary/store.js';
import { createAuditLogService } from './lib/auditLogService.js';
import { auditAnalysisOutcome } from './lib/threatLibrary/audit.js';
import {
  dispatchQueuedThreatLibraryAnalyses,
  enqueueClaimedThreatLibraryJob,
  recoverInterruptedAnalysisJobs,
  resolveThreatLibraryWorkerConcurrency
} from './lib/threatLibrary/analysisConcurrency.js';

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
    log.info('job started', {
      bullmqJobId: job.id,
      reportId,
      jobId,
      resumeAnalysis: job.data?.resumeAnalysis === true,
      aiClient: 'streaming-v3'
    });
    await updateJob(pool, jobId, { status: 'running', stage: 'starting', bullmq_job_id: String(job.id) });
    try {
      const result = await runAnalysisPipeline(pool, {
        reportId,
        jobId,
        sourceUrl: job.data?.sourceUrl,
        resumeAnalysis: job.data?.resumeAnalysis === true,
        jobType: job.data?.jobType || job.name,
        newAnalysisRun: job.data?.newAnalysisRun === true
      });
      log.info('job finished', { bullmqJobId: job.id, reportId, ok: result?.ok === true, code: result?.code });
      await auditAnalysisOutcome(pool, auditService, {
        reportId,
        jobId,
        ok: result?.ok === true,
        code: result?.code || null,
        summary: result?.summary || null
      });
      return result;
    } finally {
      await releaseSlotAndDispatch(job.data?.jobType || job.name, { bullmqJobId: job.id, reportId, jobId });
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
    try {
      const report = await getReportById(pool, reportId);
      if (report && report.analysis_status === 'analyzing') {
        await updateReportStatus(pool, reportId, {
          analysis_status: 'failed',
          import_status: 'failed',
          failure_stage: 'analyzing',
          failure_code: 'worker_failed',
          failure_reason: err?.message || 'Threat Library worker failed'
        });
        await updateJob(pool, jobId, {
          status: 'failed',
          stage: 'analyzing',
          error_message: err?.message || 'worker failed'
        });
      }
      await auditAnalysisOutcome(pool, auditService, {
        reportId,
        jobId,
        ok: false,
        code: 'worker_failed',
        summary: null
      });
    } catch (e) {
      log.warn('failed to mark report after worker failure', { error: e?.message });
    }
    await releaseSlotAndDispatch('worker_failed', { bullmqJobId: job?.id, reportId, jobId });
  }
});

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

// Bounded safety net only: import/complete/settings already dispatch directly.
const DISPATCH_SAFETY_MS = 30_000;
const safetyTimer = setInterval(() => {
  dispatchQueuedAnalyses().catch((err) => {
    log.warn('failed to dispatch queued analyses', { error: err?.message, source: 'safety_net' });
  });
}, DISPATCH_SAFETY_MS);
if (typeof safetyTimer.unref === 'function') safetyTimer.unref();

async function shutdown() {
  clearInterval(safetyTimer);
  await worker.close();
  await queue.close();
  await redis.quit();
  await pool.end();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
