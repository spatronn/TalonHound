import { getSpamhausDropConfig, ALLOWED_SYNC_INTERVALS } from './spamhausDropSync.js';

export const SPAMHAUS_DROP_JOB_NAME = 'spamhaus-drop-sync';
export const SPAMHAUS_DROP_JOB_ID = 'spamhaus-drop-scheduled';

function intervalHoursToCron(hours) {
  const h = ALLOWED_SYNC_INTERVALS.includes(Number(hours)) ? Number(hours) : 24;
  if (h === 6) return '0 */6 * * *';
  if (h === 12) return '0 */12 * * *';
  return '0 0 * * *'; // 24h
}

export async function syncSpamhausDropSchedule(pool, importQueue, { logPrefix = '[scheduler]' } = {}) {
  const config = await getSpamhausDropConfig(pool);

  const repeatables = await importQueue.getRepeatableJobs();
  const existing = repeatables.find(
    (r) => r.name === SPAMHAUS_DROP_JOB_NAME || (r.id && String(r.id) === SPAMHAUS_DROP_JOB_ID)
  );

  if (!config.enabled) {
    if (existing) {
      await importQueue.removeRepeatableByKey(existing.key);
      console.log(`${logPrefix} removed spamhaus-drop-sync repeatable (provider disabled)`);
    }
    return { active: false };
  }

  const wantedPattern = intervalHoursToCron(config.sync_interval_hours);

  if (existing) {
    const currentPattern = String(existing.pattern || '').trim();
    if (currentPattern === wantedPattern) {
      return { active: true, pattern: wantedPattern };
    }
    await importQueue.removeRepeatableByKey(existing.key);
    console.log(
      `${logPrefix} removed spamhaus-drop-sync repeatable (schedule changed from=${currentPattern} to=${wantedPattern})`
    );
  }

  await importQueue.add(
    SPAMHAUS_DROP_JOB_NAME,
    { triggeredBy: 'scheduler', integration_key: 'spamhaus-drop' },
    {
      jobId: SPAMHAUS_DROP_JOB_ID,
      repeat: { pattern: wantedPattern }
    }
  );
  console.log(`${logPrefix} ensured spamhaus-drop-sync repeatable pattern=${wantedPattern}`);
  return { active: true, pattern: wantedPattern };
}
