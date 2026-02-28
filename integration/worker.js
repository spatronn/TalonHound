import { Worker } from 'bullmq';
import pg from 'pg';
import { config } from './config.js';
import { redis } from './queue.js';
import { runHourlyImport, runUsomImport } from './importer.js';

const { Pool } = pg;
const pool = new Pool(config.db);

function resolveIntegrationKey(job) {
  if (job?.data?.integration_key) return job.data.integration_key;
  if (job?.name === 'hourly-import') return 'et-blockrules';
  if (job?.name === 'usom-import') return 'usom-trcert';
  return 'unknown';
}

const worker = new Worker(
  config.queueName,
  async (job) => {
    const integrationKey = resolveIntegrationKey(job);

    await pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, started_at, updated_at)
       VALUES ($1, $2, $3, 'running', $4, TO_TIMESTAMP($5 / 1000.0), NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='running', started_at=NOW(), updated_at=NOW()`,
      [String(job.id), integrationKey, job.name, job?.data?.triggeredBy || 'scheduler', Number(job.timestamp || Date.now())]
    );

    let result;
    if (job.name === 'hourly-import') {
      result = await runHourlyImport();
    } else if (job.name === 'usom-import') {
      result = await runUsomImport();
    } else {
      result = { skipped: true, reason: 'unknown_job' };
    }

    await pool.query(
      `UPDATE integration_queue_jobs
       SET status='success', finished_at=NOW(), records_processed=$2, updated_at=NOW()
       WHERE job_id=$1`,
      [String(job.id), Number(result?.recordsProcessed || 0)]
    );

    console.log(`[worker] completed job id=${job.id} result=${JSON.stringify(result)}`);
    return result;
  },
  {
    connection: redis,
    concurrency: Number(process.env.WORKER_CONCURRENCY || 1)
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

async function shutdown(signal) {
  console.log(`[worker] shutting down: ${signal}`);
  await worker.close();
  await redis.quit();
  await pool.end();
  process.exit(0);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => shutdown(sig));
}
