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

  await importQueue.add(
    'usom-import',
    { triggeredBy: 'scheduler' },
    {
      jobId: 'usom-import',
      repeat: { pattern: config.schedulerCron }
    }
  );


  await importQueue.add(
    'urlhaus-import',
    { triggeredBy: 'scheduler' },
    {
      jobId: 'urlhaus-import',
      repeat: { pattern: config.schedulerCron }
    }
  );

  await importQueue.add(
    'threatfox-import',
    { triggeredBy: 'scheduler' },
    {
      jobId: 'threatfox-import',
      repeat: { pattern: config.schedulerCron }
    }
  );

  await importQueue.add(
    'malwarebazaar-import',
    { triggeredBy: 'scheduler' },
    {
      jobId: 'malwarebazaar-import',
      repeat: { pattern: config.schedulerCron }
    }
  );

  await importQueue.add(
    'phishtank-import',
    { triggeredBy: 'scheduler' },
    {
      jobId: 'phishtank-import',
      repeat: { pattern: config.schedulerCron }
    }
  );

  console.log(`[scheduler] repeat jobs set with cron=${config.schedulerCron}`);

  setInterval(async () => {
    await importQueue.add(
      'hourly-import',
      { triggeredBy: 'scheduler' },
      {
        jobId: 'hourly-import',
        repeat: { pattern: config.schedulerCron }
      }
    );

    await importQueue.add(
      'usom-import',
      { triggeredBy: 'scheduler' },
      {
        jobId: 'usom-import',
        repeat: { pattern: config.schedulerCron }
      }
    );

    await importQueue.add(
      'urlhaus-import',
      { triggeredBy: 'scheduler' },
      {
        jobId: 'urlhaus-import',
        repeat: { pattern: config.schedulerCron }
      }
    );

    await importQueue.add(
      'threatfox-import',
      { triggeredBy: 'scheduler' },
      {
        jobId: 'threatfox-import',
        repeat: { pattern: config.schedulerCron }
      }
    );

    await importQueue.add(
      'malwarebazaar-import',
      { triggeredBy: 'scheduler' },
      {
        jobId: 'malwarebazaar-import',
        repeat: { pattern: config.schedulerCron }
      }
    );

    await importQueue.add(
      'phishtank-import',
      { triggeredBy: 'scheduler' },
      {
        jobId: 'phishtank-import',
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
