import { Worker } from 'bullmq';
import pg from 'pg';
import { config } from './config.js';
import { redis } from './queue.js';
import { runHourlyImport, runUsomImport, runUrlhausImport, runThreatfoxImport, runMalwareBazaarImport, runPhishtankImport } from './importer.js';

const { Pool } = pg;
const pool = new Pool(config.db);

const STALE_RUNNING_MINUTES = Math.max(Number(process.env.INTEGRATION_STALE_RUNNING_MINUTES || 180), 60);
const WORKER_CONCURRENCY = Math.max(Number(process.env.WORKER_CONCURRENCY || 1), 1);
const WORKER_LOCK_DURATION_MS = Math.max(Number(process.env.WORKER_LOCK_DURATION_MS || 300000), 60000);
const WORKER_STALLED_INTERVAL_MS = Math.max(Number(process.env.WORKER_STALLED_INTERVAL_MS || 60000), 10000);
const WORKER_MAX_STALLED_COUNT = Math.max(Number(process.env.WORKER_MAX_STALLED_COUNT || 5), 1);

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

const worker = new Worker(
  config.queueName,
  async (job) => {
    const integrationKey = resolveIntegrationKey(job);

    await pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, started_at, updated_at)
       VALUES ($1, $2, $3, 'running', $4, NOW(), NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='running', started_at=NOW(), updated_at=NOW()`,
      [String(job.id), integrationKey, job.name, job?.data?.triggeredBy || 'scheduler']
    );

    let result;
    if (job.name === 'hourly-import') {
      result = await runHourlyImport();
    } else if (job.name === 'usom-import') {
      result = await runUsomImport();
    } else if (job.name === 'urlhaus-import') {
      result = await runUrlhausImport();
    } else if (job.name === 'threatfox-import') {
      result = await runThreatfoxImport();
    } else if (job.name === 'malwarebazaar-import') {
      result = await runMalwareBazaarImport();
    } else if (job.name === 'phishtank-import') {
      result = await runPhishtankImport();
    } else {
      result = { skipped: true, reason: 'unknown_job' };
    }

    await pool.query(
      `UPDATE integration_queue_jobs
       SET status='success', finished_at=NOW(), records_processed=$2, error_message=NULL, updated_at=NOW()
       WHERE job_id=$1`,
      [String(job.id), Number(result?.recordsProcessed || 0)]
    );

    console.log(`[worker] completed job id=${job.id} result=${JSON.stringify(result)} suppressed_count=${Number(result?.suppressed_count || 0)}`);
    return result;
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
  console.error(`[worker] failed job id=${job?.id} attemptsMade=${job?.attemptsMade}`, err);
  try {
    if (job?.id) {
      await pool.query(
        `UPDATE integration_queue_jobs
         SET status='failed', finished_at=NOW(), error_message=$2, updated_at=NOW()
         WHERE job_id=$1`,
        [String(job.id), String(err?.message || 'unknown error').slice(0, 4000)]
      );
    }
  } catch (e) {
    console.error('[worker] failed to persist failed state', e);
  }
});

worker.on('error', (err) => {
  console.error('[worker] error', err);
});

async function reconcileStaleQueueRows() {
  try {
    const fixedFinished = await pool.query(
      `UPDATE integration_queue_jobs
       SET status = CASE WHEN error_message IS NULL THEN 'success' ELSE 'failed' END,
           updated_at = NOW()
       WHERE status = 'running'
         AND finished_at IS NOT NULL`
    );

    const fixedStale = await pool.query(
      `UPDATE integration_queue_jobs
       SET status = 'failed',
           finished_at = COALESCE(finished_at, NOW()),
           error_message = COALESCE(error_message, 'reconciled: stale running row after worker restart/timeout'),
           updated_at = NOW()
       WHERE status = 'running'
         AND started_at < NOW() - (($1 || ' minutes')::interval)`,
      [String(STALE_RUNNING_MINUTES)]
    );

    if ((fixedFinished.rowCount || 0) > 0 || (fixedStale.rowCount || 0) > 0) {
      console.log(`[worker] reconciled queue rows fixed_finished=${fixedFinished.rowCount || 0} fixed_stale=${fixedStale.rowCount || 0}`);
    }
  } catch (err) {
    console.error('[worker] reconcile failed', err?.message || err);
  }
}

async function shutdown(signal) {
  console.log(`[worker] shutting down: ${signal}`);
  await worker.close();
  await redis.quit();
  await pool.end();
  process.exit(0);
}

await reconcileStaleQueueRows();

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => shutdown(sig));
}
