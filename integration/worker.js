import { Worker } from 'bullmq';
import pg from 'pg';
import { config } from './config.js';
import { redis } from './queue.js';
import { runHourlyImport, runUsomImport, runUrlhausImport, runThreatfoxImport, runMalwareBazaarImport, runPhishtankImport } from './importer.js';

const { Pool } = pg;
const pool = new Pool(config.db);

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
