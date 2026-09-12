import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { createServiceLogger } from './lib/appLogger.js';
import { getThreatLibraryQueueName, getThreatLibraryWorkerOptions } from './lib/threatLibrary/queueConfig.js';
import { runAnalysisPipeline } from './lib/threatLibrary/pipeline.js';
import { updateJob, getReportById, updateReportStatus } from './lib/threatLibrary/store.js';

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

const redis = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
const concurrency = Math.min(Math.max(Number(process.env.THREAT_LIBRARY_WORKER_CONCURRENCY || 2), 1), 4);

const worker = new Worker(
  getThreatLibraryQueueName(),
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
      aiClient: 'streaming-v2'
    });
    await updateJob(pool, jobId, { status: 'running', stage: 'starting', bullmq_job_id: String(job.id) });
    const result = await runAnalysisPipeline(pool, {
      reportId,
      jobId,
      sourceUrl: job.data?.sourceUrl,
      resumeAnalysis: job.data?.resumeAnalysis === true,
      jobType: job.data?.jobType || job.name,
      newAnalysisRun: job.data?.newAnalysisRun === true
    });
    log.info('job finished', { bullmqJobId: job.id, reportId, ok: result?.ok === true, code: result?.code });
    return result;
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
    } catch (e) {
      log.warn('failed to mark report after worker failure', { error: e?.message });
    }
  }
});

worker.on('ready', () => {
  log.info('worker ready', {
    queue: getThreatLibraryQueueName(),
    concurrency,
    aiClient: 'streaming-v2',
    version: process.env.TALONHOUND_VERSION || null
  });
});

async function shutdown() {
  await worker.close();
  await redis.quit();
  await pool.end();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
