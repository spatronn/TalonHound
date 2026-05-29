import { config } from './config.js';
import { createIntegrationPool } from './lib/pg-pool.js';
import { importQueue, redis } from './queue.js';

const pool = createIntegrationPool();

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

function deriveFeedKeyFromRepeatable(repeatable, desiredByKey, desiredKeysByJobName) {
  const idRaw = String(repeatable.id || '').trim();
  const idKey = idRaw.replace(/-scheduled$/, '');
  if (idKey && desiredByKey.has(idKey)) return idKey;

  const jobName = String(repeatable.name || '').trim();
  const keysForName = desiredKeysByJobName.get(jobName) || [];
  if (keysForName.length === 1) return keysForName[0];

  return null;
}

async function syncSchedules() {
  const desired = await loadActiveFeedSchedules();
  const desiredByKey = new Map(desired.map((d) => [d.key, d]));
  const desiredKeysByJobName = new Map();

  for (const d of desired) {
    const jobName = INTEGRATION_JOBS[d.key];
    if (!desiredKeysByJobName.has(jobName)) desiredKeysByJobName.set(jobName, []);
    desiredKeysByJobName.get(jobName).push(d.key);
  }

  const repeatables = await importQueue.getRepeatableJobs();
  const seenPerFeedAndCron = new Set();

  const knownJobNames = new Set(Object.values(INTEGRATION_JOBS));

  for (const r of repeatables) {
    const jobName = String(r.name || '').trim();

    // Ignore unrelated repeatable jobs on this queue.
    if (!knownJobNames.has(jobName)) continue;

    const mappedKey = deriveFeedKeyFromRepeatable(r, desiredByKey, desiredKeysByJobName);
    const repeatCron = sanitizeCron(String(r.pattern || '').trim());

    if (!mappedKey) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`[scheduler] removed repeat job name=${jobName} key=unknown pattern=${repeatCron || '-'} reason=legacy_or_unmapped`);
      continue;
    }

    const desiredFeed = desiredByKey.get(mappedKey);
    if (!desiredFeed) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`[scheduler] removed repeat job key=${mappedKey} pattern=${repeatCron || '-'} reason=inactive_or_missing`);
      continue;
    }

    if (desiredFeed.cron !== repeatCron) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`[scheduler] removed repeat job key=${mappedKey} pattern=${repeatCron || '-'} reason=schedule_changed`);
      continue;
    }

    const dedupKey = `${mappedKey}::${repeatCron}`;
    if (seenPerFeedAndCron.has(dedupKey)) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`[scheduler] removed repeat job key=${mappedKey} pattern=${repeatCron || '-'} reason=duplicate`);
      continue;
    }

    seenPerFeedAndCron.add(dedupKey);
  }

  for (const feed of desired) {
    const dedupKey = `${feed.key}::${feed.cron}`;
    if (seenPerFeedAndCron.has(dedupKey)) continue;
    await ensureSchedule(feed);
    seenPerFeedAndCron.add(dedupKey);
  }

  console.log(`[scheduler] schedule sync complete, active=${desired.length}`);
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
