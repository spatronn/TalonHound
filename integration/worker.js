import { Worker } from 'bullmq';
import { config } from './config.js';
import { redis } from './queue.js';
import { runHourlyImport, runUsomImport } from './importer.js';

const worker = new Worker(
  config.queueName,
  async (job) => {
    if (job.name === 'hourly-import') {
      const result = await runHourlyImport();
      console.log(`[worker] completed job id=${job.id} result=${JSON.stringify(result)}`);
      return result;
    }

    if (job.name === 'usom-import') {
      const result = await runUsomImport();
      console.log(`[worker] completed job id=${job.id} result=${JSON.stringify(result)}`);
      return result;
    }

    return { skipped: true, reason: 'unknown_job' };
  },
  {
    connection: redis,
    concurrency: Number(process.env.WORKER_CONCURRENCY || 1)
  }
);

worker.on('failed', (job, err) => {
  console.error(`[worker] failed job id=${job?.id} attemptsMade=${job?.attemptsMade}`, err);
});

worker.on('error', (err) => {
  console.error('[worker] error', err);
});

async function shutdown(signal) {
  console.log(`[worker] shutting down: ${signal}`);
  await worker.close();
  await redis.quit();
  process.exit(0);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => shutdown(sig));
}
