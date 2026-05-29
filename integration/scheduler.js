import { createIntegrationPool } from './lib/pg-pool.js';
import { importQueue, redis } from './queue.js';
import { syncIntegrationFeedSchedules } from './lib/integrationFeedScheduleSync.js';

const pool = createIntegrationPool();

async function syncSchedules() {
  await syncIntegrationFeedSchedules(pool, importQueue, { logPrefix: '[scheduler]' });
}

async function main() {
  await syncSchedules();

  setInterval(async () => {
    try {
      await syncSchedules();
    } catch (err) {
      console.error('[scheduler] sync failed', err);
    }
  }, 60 * 1000);
}

main().catch((err) => {
  console.error('[scheduler] fatal', err);
  process.exit(1);
});

async function shutdown(signal) {
  console.log(`[scheduler] shutting down: ${signal}`);
  await importQueue.close();
  await redis.quit();
  await pool.end();
  process.exit(0);
}

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => shutdown(sig));
}
