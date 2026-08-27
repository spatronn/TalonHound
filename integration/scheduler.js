import { createIntegrationPool } from './lib/pg-pool.js';
import { importQueue, redis } from './queue.js';
import { syncIntegrationFeedSchedules } from './lib/integrationFeedScheduleSync.js';
import { syncSpamhausDropSchedule } from './lib/spamhausDropScheduleSync.js';
import { syncFileArtifactReconciliationSchedule } from './lib/fileArtifactReconciliationScheduleSync.js';
import { HEARTBEAT_KEYS, touchWorkerHeartbeat } from './lib/workerHeartbeat.js';

const pool = createIntegrationPool();

async function syncSchedules() {
  await syncIntegrationFeedSchedules(pool, importQueue, { logPrefix: '[scheduler]' });
  await syncSpamhausDropSchedule(pool, importQueue, { logPrefix: '[scheduler]' });
  await syncFileArtifactReconciliationSchedule(pool, importQueue, { logPrefix: '[scheduler]' });
}

async function touchSchedulerHeartbeat() {
  try {
    await touchWorkerHeartbeat(redis, HEARTBEAT_KEYS.integration_scheduler);
  } catch (err) {
    console.error('[scheduler] heartbeat failed', err?.message || err);
  }
}

async function main() {
  const { waitUntilSetupComplete } = await import('./lib/systemTime.js');
  const { setSystemScheduleTimezoneOverride } = await import('./lib/integrationSchedule.js');
  const tz = await waitUntilSetupComplete(pool, { logPrefix: '[scheduler]' });
  process.env.TZ = tz;
  process.env.SYSTEM_TIMEZONE = tz;
  setSystemScheduleTimezoneOverride(tz);

  await syncSchedules();
  await touchSchedulerHeartbeat();

  let syncInProgress = false;
  setInterval(async () => {
    if (syncInProgress) {
      console.warn('[scheduler] previous sync still running; skipping overlapping tick');
      return;
    }
    syncInProgress = true;
    try {
      await syncSchedules();
      await touchSchedulerHeartbeat();
    } catch (err) {
      console.error('[scheduler] sync failed', err);
    } finally {
      syncInProgress = false;
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
