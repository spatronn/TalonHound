import pg from 'pg';
import { config } from './config.js';
import { importQueue, redis } from './queue.js';

const { Pool } = pg;
const pool = new Pool(config.db);

const INTEGRATION_JOBS = {
  'et-blockrules': 'hourly-import',
  'usom-trcert': 'usom-import',
  'urlhaus-abusech': 'urlhaus-import',
  'threatfox-abusech': 'threatfox-import',
  'malwarebazaar-abusech': 'malwarebazaar-import',
  'phishtank-opendnsrr': 'phishtank-import'
};

const ALLOWED_CRONS = new Set(['*/5 * * * *', '*/15 * * * *', '*/30 * * * *', '0 * * * *']);

function sanitizeCron(value) {
  const v = String(value || '').trim();
  return ALLOWED_CRONS.has(v) ? v : '0 * * * *';
}

async function loadActiveFeedSchedules() {
  const q = await pool.query(
    `SELECT key, schedule_cron
     FROM integration_feeds
     WHERE active = TRUE`
  );

  return (q.rows || [])
    .map((r) => ({
      key: String(r.key || '').trim(),
      cron: sanitizeCron(r.schedule_cron)
    }))
    .filter((r) => r.key && INTEGRATION_JOBS[r.key]);
}

async function ensureSchedule(feed) {
  const jobName = INTEGRATION_JOBS[feed.key];
  const jobId = `${feed.key}-scheduled`;

  await importQueue.add(
    jobName,
    { triggeredBy: 'scheduler', integration_key: feed.key },
    {
      jobId,
      repeat: { pattern: feed.cron }
    }
  );
}

async function syncSchedules() {
  const desired = await loadActiveFeedSchedules();
  const desiredKeys = new Set(desired.map((d) => d.key));

  const repeatables = await importQueue.getRepeatableJobs();

  for (const r of repeatables) {
    const key = String(r.id || '').replace(/-scheduled$/, '');
    if (!key || !INTEGRATION_JOBS[key]) continue;

    const desiredFeed = desired.find((d) => d.key === key);
    const repeatCron = String(r.pattern || '').trim();

    if (!desiredFeed || desiredFeed.cron !== repeatCron) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`[scheduler] removed repeat job key=${key} pattern=${repeatCron || '-'} reason=${!desiredFeed ? 'inactive_or_missing' : 'schedule_changed'}`);
    }
  }

  for (const feed of desired) {
    await ensureSchedule(feed);
  }

  console.log(`[scheduler] schedule sync complete, active=${desiredKeys.size}`);
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
