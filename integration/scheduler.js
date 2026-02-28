import { config } from './config.js';
import { importQueue, redis } from './queue.js';

async function main() {
  await importQueue.add(
    'hourly-import',
    { triggeredBy: 'scheduler' },
    {
      jobId: 'hourly-import',
      repeat: { pattern: config.schedulerCron }
    }
  );

  console.log(`[scheduler] repeat job set with cron=${config.schedulerCron}`);

  setInterval(async () => {
    await importQueue.add(
      'hourly-import',
      { triggeredBy: 'scheduler' },
      {
        jobId: 'hourly-import',
        repeat: { pattern: config.schedulerCron }
      }
    );
  }, 10 * 60 * 1000);
}

main().catch((err) => {
  console.error('[scheduler] fatal', err);
  process.exit(1);
});

async function shutdown(signal) {
  console.log(`[scheduler] shutting down: ${signal}`);
  await importQueue.close();
  await redis.quit();
  process.exit(0);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => shutdown(sig));
}
