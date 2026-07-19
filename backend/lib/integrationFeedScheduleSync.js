import {
  buildHourlySlotMap,
  effectiveCronForFeed,
  sanitizeScheduleCron,
  isDailyScheduleCron,
  buildRepeatJobConfig,
  isRunOnceSchedule
} from './integrationSchedule.js';

/** BullMQ job names keyed by integration_feeds.key */
export const INTEGRATION_FEED_JOBS = Object.freeze({
  'et-blockrules': 'hourly-import',
  'usom-trcert': 'usom-import',
  'urlhaus-abusech': 'urlhaus-import',
  'threatfox-abusech': 'threatfox-import',
  'malwarebazaar-abusech': 'malwarebazaar-import',
  'phishtank-opendnsrr': 'phishtank-import',
  'alienvault-otx': 'alienvault-otx-import'
});

export const CUSTOM_THREAT_FEED_JOB = 'custom-threat-feed-sync';
export const USOM_FEED_KEY = 'usom-trcert';
export const USOM_RUN_MODES = Object.freeze({
  INCREMENTAL: 'incremental',
  FULL_RECONCILIATION: 'full_reconciliation'
});

function envEnabled(value, fallback = true) {
  if (value == null || String(value).trim() === '') return fallback;
  return !['0', 'false', 'no', 'off'].includes(String(value).trim().toLowerCase());
}

export function getUsomFullReconciliationScheduleConfig(env = process.env) {
  return {
    incrementalEnabled: envEnabled(env.USOM_INCREMENTAL_ENABLED, true),
    enabled: envEnabled(env.USOM_FULL_RECONCILIATION_ENABLED, true),
    cron: sanitizeScheduleCron(env.USOM_FULL_RECONCILIATION_CRON || '0 3 * * 0'),
    timezone: String(env.USOM_FULL_RECONCILIATION_TIMEZONE || 'Europe/Istanbul').trim() || 'Europe/Istanbul'
  };
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

function repeatConfigKey(repeat) {
  if (!repeat || typeof repeat !== 'object') return '';
  const pattern = String(repeat.pattern || '').trim();
  const tz = String(repeat.tz || '').trim();
  return `${pattern}::${tz}`;
}

function desiredRepeatConfig(feedKey, scheduleCron, slotMap, timezone = null) {
  return buildRepeatJobConfig(feedKey, scheduleCron, slotMap, timezone);
}

function repeatableMatchesDesired(repeatable, desiredRepeat) {
  const repeatCron = sanitizeScheduleCron(String(repeatable.pattern || '').trim());
  const desiredPattern = String(desiredRepeat.pattern || '').trim();
  if (repeatCron !== desiredPattern) return false;

  const actualTz = String(repeatable.tz || '').trim();
  const desiredTz = String(desiredRepeat.tz || '').trim();
  return actualTz === desiredTz;
}

export async function loadCustomThreatFeedSchedules(pool) {
  const q = await pool.query(
    `SELECT f.key, f.schedule_cron
     FROM custom_threat_feeds c
     JOIN integration_feeds f ON f.integration_id = c.feed_id
     WHERE c.deactivated_at IS NULL
       AND f.active = TRUE
       AND f.archived_at IS NULL
       AND f.schedule_cron <> 'run_once'`
  );
  return (q.rows || [])
    .map((r) => ({
      key: String(r.key || '').trim(),
      cron: sanitizeScheduleCron(r.schedule_cron)
    }))
    .filter((r) => r.key && r.key.startsWith('ctf-') && !isRunOnceSchedule(r.cron));
}

async function ensureCustomFeedSchedule(importQueue, feed, slotMap) {
  const jobId = `${feed.key}-scheduled`;
  const repeat = desiredRepeatConfig(feed.key, feed.cron, slotMap);
  await importQueue.add(
    CUSTOM_THREAT_FEED_JOB,
    { triggeredBy: 'scheduler', integration_key: feed.key },
    { jobId, repeat }
  );
}

export async function syncCustomThreatFeedSchedules(pool, importQueue, { logPrefix = '[scheduler]' } = {}) {
  const desired = await loadCustomThreatFeedSchedules(pool);
  const slotMap = buildHourlySlotMap(desired.map((d) => ({ key: d.key, schedule: d.cron })));
  const desiredByKey = new Map(desired.map((d) => [d.key, d]));
  const desiredKeysByJobName = new Map([[CUSTOM_THREAT_FEED_JOB, desired.map((d) => d.key)]]);

  const repeatables = await importQueue.getRepeatableJobs();
  const seenPerFeed = new Set();

  for (const r of repeatables) {
    const jobName = String(r.name || '').trim();
    if (jobName !== CUSTOM_THREAT_FEED_JOB) continue;

    const mappedKey = deriveFeedKeyFromRepeatable(r, desiredByKey, desiredKeysByJobName);
    const repeatCron = sanitizeScheduleCron(String(r.pattern || '').trim());

    if (!mappedKey) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed custom repeat job key=unknown pattern=${repeatCron || '-'} reason=legacy_or_unmapped`);
      continue;
    }

    const desiredFeed = desiredByKey.get(mappedKey);
    if (!desiredFeed) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed custom repeat job key=${mappedKey} pattern=${repeatCron || '-'} reason=inactive_or_missing`);
      continue;
    }

    const desiredRepeat = desiredRepeatConfig(mappedKey, desiredFeed.cron, slotMap);
    if (!repeatableMatchesDesired(r, desiredRepeat)) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed custom repeat job key=${mappedKey} reason=schedule_changed`);
      continue;
    }

    const dedupKey = `${mappedKey}::${repeatConfigKey(desiredRepeat)}`;
    if (seenPerFeed.has(dedupKey)) {
      await importQueue.removeRepeatableByKey(r.key);
      continue;
    }
    seenPerFeed.add(dedupKey);
  }

  for (const feed of desired) {
    const repeat = desiredRepeatConfig(feed.key, feed.cron, slotMap);
    const dedupKey = `${feed.key}::${repeatConfigKey(repeat)}`;
    if (seenPerFeed.has(dedupKey)) continue;
    await ensureCustomFeedSchedule(importQueue, feed, slotMap);
    seenPerFeed.add(dedupKey);
    console.log(`${logPrefix} ensured custom repeat job key=${feed.key} pattern=${repeat.pattern}`);
  }

  return { active: desired.length };
}

export async function loadActiveFeedSchedules(pool) {
  const q = await pool.query(
    `SELECT key, schedule_cron
     FROM integration_feeds
     WHERE active = TRUE
       AND archived_at IS NULL
       AND schedule_cron <> 'run_once'`
  );

  return (q.rows || [])
    .map((r) => ({
      key: String(r.key || '').trim(),
      cron: sanitizeScheduleCron(r.schedule_cron)
    }))
    .filter((r) => r.key && INTEGRATION_FEED_JOBS[r.key] && !isRunOnceSchedule(r.cron));
}

async function ensureFeedSchedule(importQueue, feed, slotMap) {
  const jobName = INTEGRATION_FEED_JOBS[feed.key];
  const mode = feed.mode || USOM_RUN_MODES.INCREMENTAL;
  const identity = scheduleIdentity(feed.key, mode);
  const jobId = mode === USOM_RUN_MODES.FULL_RECONCILIATION
    ? `${feed.key}-full-reconciliation-scheduled`
    : `${feed.key}-scheduled`;
  const repeat = {
    ...desiredRepeatConfig(feed.key, feed.cron, slotMap, feed.timezone),
    key: `integration-schedule:${identity}`
  };

  await importQueue.add(
    jobName,
    {
      triggeredBy: `scheduler:${mode}`,
      integration_key: feed.key,
      run_mode: mode
    },
    { jobId, repeat }
  );
}

function scheduleIdentity(feedKey, mode = USOM_RUN_MODES.INCREMENTAL) {
  return `${feedKey}::${mode}`;
}

function deriveFeedScheduleIdentity(repeatable, desiredByIdentity, desiredKeysByJobName) {
  const repeatKey = String(repeatable?.key || '').trim();
  if (repeatKey.startsWith('integration-schedule:')) {
    return repeatKey.slice('integration-schedule:'.length);
  }
  const id = String(repeatable?.id || '').trim();
  if (id.endsWith('-full-reconciliation-scheduled')) {
    return scheduleIdentity(id.slice(0, -'-full-reconciliation-scheduled'.length), USOM_RUN_MODES.FULL_RECONCILIATION);
  }
  if (id.endsWith('-scheduled')) {
    return scheduleIdentity(id.slice(0, -'-scheduled'.length), USOM_RUN_MODES.INCREMENTAL);
  }
  const key = deriveFeedKeyFromRepeatable(repeatable, new Map(
    [...desiredByIdentity.values()].map((feed) => [feed.key, feed])
  ), desiredKeysByJobName);
  return key ? scheduleIdentity(key, USOM_RUN_MODES.INCREMENTAL) : null;
}

/**
 * Reconcile BullMQ repeatables with DB schedules.
 * Removes stale hourly repeatables when a feed is switched to daily (and vice versa).
 */
export async function syncIntegrationFeedSchedules(pool, importQueue, { logPrefix = '[scheduler]' } = {}) {
  const activeFeeds = await loadActiveFeedSchedules(pool);
  const fullConfig = getUsomFullReconciliationScheduleConfig();
  const desired = activeFeeds
    .filter((feed) => feed.key !== USOM_FEED_KEY || fullConfig.incrementalEnabled)
    .map((feed) => ({ ...feed, mode: USOM_RUN_MODES.INCREMENTAL }));
  if (fullConfig.enabled && activeFeeds.some((feed) => feed.key === USOM_FEED_KEY)) {
    desired.push({
      key: USOM_FEED_KEY,
      cron: fullConfig.cron,
      timezone: fullConfig.timezone,
      mode: USOM_RUN_MODES.FULL_RECONCILIATION
    });
  }
  const slotMap = buildHourlySlotMap(activeFeeds.map((d) => ({ key: d.key, schedule: d.cron })));
  const desiredByIdentity = new Map(desired.map((d) => [scheduleIdentity(d.key, d.mode), d]));
  const desiredKeysByJobName = new Map();

  for (const d of activeFeeds) {
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

    const identity = deriveFeedScheduleIdentity(r, desiredByIdentity, desiredKeysByJobName);
    const repeatCron = sanitizeScheduleCron(String(r.pattern || '').trim());

    if (!identity) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job name=${jobName} key=unknown pattern=${repeatCron || '-'} reason=legacy_or_unmapped`);
      continue;
    }

    const desiredFeed = desiredByIdentity.get(identity);
    if (!desiredFeed) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job identity=${identity} pattern=${repeatCron || '-'} reason=inactive_or_missing`);
      continue;
    }
    if (
      desiredFeed.key === USOM_FEED_KEY
      && !String(r.key || '').startsWith('integration-schedule:')
    ) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job identity=${identity} pattern=${repeatCron || '-'} reason=legacy_mode_key`);
      continue;
    }
    if (
      desiredFeed.key === USOM_FEED_KEY
      && Number.isFinite(Number(r.next))
      && Number(r.next) < Date.now() - 60_000
    ) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job identity=${identity} pattern=${repeatCron || '-'} reason=overdue_iteration`);
      continue;
    }

    const desiredRepeat = desiredRepeatConfig(desiredFeed.key, desiredFeed.cron, slotMap, desiredFeed.timezone);
    if (!repeatableMatchesDesired(r, desiredRepeat)) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(
        `${logPrefix} removed repeat job identity=${identity} pattern=${repeatCron || '-'} tz=${r.tz || '-'} reason=schedule_changed wanted=${repeatConfigKey(desiredRepeat)}`
      );
      continue;
    }

    const dedupKey = `${identity}::${repeatConfigKey(desiredRepeat)}`;
    if (seenPerFeed.has(dedupKey)) {
      await importQueue.removeRepeatableByKey(r.key);
      console.log(`${logPrefix} removed repeat job identity=${identity} pattern=${repeatCron || '-'} reason=duplicate`);
      continue;
    }

    seenPerFeed.add(dedupKey);
  }

  for (const feed of desired) {
    const repeat = desiredRepeatConfig(feed.key, feed.cron, slotMap, feed.timezone);
    const identity = scheduleIdentity(feed.key, feed.mode);
    const dedupKey = `${identity}::${repeatConfigKey(repeat)}`;
    if (seenPerFeed.has(dedupKey)) continue;
    await ensureFeedSchedule(importQueue, feed, slotMap);
    seenPerFeed.add(dedupKey);
    console.log(
      `${logPrefix} ensured repeat job identity=${identity} pattern=${repeat.pattern}${repeat.tz ? ` tz=${repeat.tz}` : ''}`
    );
  }

  console.log(`${logPrefix} schedule sync complete, active=${activeFeeds.length} schedules=${desired.length}`);
  await syncCustomThreatFeedSchedules(pool, importQueue, { logPrefix });
  return { active: activeFeeds.length, schedules: desired.length };
}

export async function syncSingleFeedSchedule(pool, importQueue, feedKey, { logPrefix = '[integrations]' } = {}) {
  const key = String(feedKey || '').trim();
  if (key.startsWith('ctf-')) {
    await syncCustomThreatFeedSchedules(pool, importQueue, { logPrefix });
    return { ok: true };
  }
  if (!INTEGRATION_FEED_JOBS[key]) {
    return { ok: false, reason: 'unknown_feed' };
  }

  await syncIntegrationFeedSchedules(pool, importQueue, { logPrefix });
  return { ok: true };
}
