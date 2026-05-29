import {
  buildHourlySlotMap,
  effectiveCronForFeed,
  sanitizeScheduleCron,
  isDailyScheduleCron,
  buildRepeatJobConfig
} from './integrationSchedule.js';

/** BullMQ job names keyed by integration_feeds.key */
export const INTEGRATION_FEED_JOBS = Object.freeze({
  'et-blockrules': 'hourly-import',
  'usom-trcert': 'usom-import',
  'urlhaus-abusech': 'urlhaus-import',
  'threatfox-abusech': 'threatfox-import',
  'malwarebazaar-abusech': 'malwarebazaar-import',
  'phishtank-opendnsrr': 'phishtank-import'
});

function deriveFeedKeyFromRepeatable(repeatable, desiredByKey, desiredKeysByJobName) {
  const idRaw = String(repeatable.id || '').trim();
  const idKey = idRaw.replace(/-scheduled$/, '');
  if (idKey && desiredByKey.has(idKey)) return idKey;

  const jobName = String(repeatable.name || '').trim();
  const keysForName = desiredKeysByJobName.get(jobName) || [];
  if (keysForName.length === 1) return keysForName[0];

  return null;
}

function repeatConfigKey(repeat) {
  if (!repeat || typeof repeat !== 'object') return '';
  const pattern = String(repeat.pattern || '').trim();
  const tz = String(repeat.tz || '').trim();
  return `${pattern}::${tz}`;
}

function desiredRepeatConfig(feedKey, scheduleCron, slotMap) {
  return buildRepeatJobConfig(feedKey, scheduleCron, slotMap);
}

function repeatableMatchesDesired(repeatable, desiredRepeat) {
  const repeatCron = sanitizeScheduleCron(String(repeatable.pattern || '').trim());
  const desiredPattern = String(desiredRepeat.pattern || '').trim();
  if (repeatCron !== desiredPattern) return false;

  const actualTz = String(repeatable.tz || '').trim();
  const desiredTz = String(desiredRepeat.tz || '').trim();
  return actualTz === desiredTz;
}

export async function loadActiveFeedSchedules(pool) {
  const q = await pool.query(
    `SELECT key, schedule_cron
     FROM integration_feeds
     WHERE active = TRUE`
  );

  return (q.rows || [])
    .map((r) => ({
      key: String(r.key || '').trim(),
      cron: sanitizeScheduleCron(r.schedule_cron)
    }))
    .filter((r) => r.key && INTEGRATION_FEED_JOBS[r.key]);
}

async function ensureFeedSchedule(importQueue, feed, slotMap) {
  const jobName = INTEGRATION_FEED_JOBS[feed.key];
  const jobId = `${feed.key}-scheduled`;
  const repeat = desiredRepeatConfig(feed.key, feed.cron, slotMap);

  await importQueue.add(
    jobName,
    { triggeredBy: 'scheduler', integration_key: feed.key },
    { jobId, repeat }
  );
}

/**
 * Reconcile BullMQ repeatables with DB schedules.
 * Removes stale hourly repeatables when a feed is switched to daily (and vice versa).
 */
export async function syncIntegrationFeedSchedules(pool, importQueue, { logPrefix = '[scheduler]' } = {}) {
  const desired = await loadActiveFeedSchedules(pool);
  const slotMap = buildHourlySlotMap(desired.map((d) => ({ key: d.key, schedule: d.cron })));
  const desiredByKey = new Map(desired.map((d) => [d.key, d]));
  const desiredKeysByJobName = new Map();

  for (const d of desired) {
    const jobName = INTEGRATION_FEED_JOBS[d.key];
    if (!desiredKeysByJobName.has(jobName)) desiredKeysByJobName.set(jobName, []);
    desiredKeysByJobName.get(jobName).push(d.key);
  }

  const repeatables = await importQueue.getRepeatableJobs();
  const seenPerFeed = new Set();
  const knownJobNames = new Set(Object.values(INTEGRATION_FEED_JOBS));

  for (const r of repeatables) {
    const jobName = String(r.name || '').trim();
    if (!knownJobNames.has(jobName)) continue;

    const mappedKey = deriveFeedKeyFromRepeatable(r, desiredByKey, desiredKeysByJobName);
    const repeatCron = sanitizeScheduleCron(String(r.pattern || '').trim());

    if (!mappedKey) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job name=${jobName} key=unknown pattern=${repeatCron || '-'} reason=legacy_or_unmapped`);
      continue;
    }

    const desiredFeed = desiredByKey.get(mappedKey);
    if (!desiredFeed) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job key=${mappedKey} pattern=${repeatCron || '-'} reason=inactive_or_missing`);
      continue;
    }

    const desiredRepeat = desiredRepeatConfig(mappedKey, desiredFeed.cron, slotMap);
    if (!repeatableMatchesDesired(r, desiredRepeat)) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(
        `${logPrefix} removed repeat job key=${mappedKey} pattern=${repeatCron || '-'} tz=${r.tz || '-'} reason=schedule_changed wanted=${repeatConfigKey(desiredRepeat)}`
      );
      continue;
    }

    const dedupKey = `${mappedKey}::${repeatConfigKey(desiredRepeat)}`;
    if (seenPerFeed.has(dedupKey)) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job key=${mappedKey} pattern=${repeatCron || '-'} reason=duplicate`);
      continue;
    }

    seenPerFeed.add(dedupKey);
  }

  for (const feed of desired) {
    const repeat = desiredRepeatConfig(feed.key, feed.cron, slotMap);
    const dedupKey = `${feed.key}::${repeatConfigKey(repeat)}`;
    if (seenPerFeed.has(dedupKey)) continue;
    await ensureFeedSchedule(importQueue, feed, slotMap);
    seenPerFeed.add(dedupKey);
    console.log(
      `${logPrefix} ensured repeat job key=${feed.key} pattern=${repeat.pattern}${repeat.tz ? ` tz=${repeat.tz}` : ''}`
    );
  }

  console.log(`${logPrefix} schedule sync complete, active=${desired.length}`);
  return { active: desired.length };
}

export async function syncSingleFeedSchedule(pool, importQueue, feedKey, { logPrefix = '[integrations]' } = {}) {
  const key = String(feedKey || '').trim();
  if (!INTEGRATION_FEED_JOBS[key]) {
    return { ok: false, reason: 'unknown_feed' };
  }

  await syncIntegrationFeedSchedules(pool, importQueue, { logPrefix });
  return { ok: true };
}
