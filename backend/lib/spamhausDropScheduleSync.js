import { getSpamhausDropConfig, ALLOWED_SYNC_INTERVALS } from './spamhausDropSync.js';
import {
  collectLiveScheduleIdentities,
  evaluateRepeatableStall,
  USOM_RUN_MODES
} from './integrationFeedScheduleSync.js';

export const SPAMHAUS_DROP_JOB_NAME = 'spamhaus-drop-sync';
export const SPAMHAUS_DROP_JOB_ID = 'spamhaus-drop-scheduled';
export const SPAMHAUS_DROP_INTEGRATION_KEY = 'spamhaus-drop';

function intervalHoursToCron(hours) {
  const h = ALLOWED_SYNC_INTERVALS.includes(Number(hours)) ? Number(hours) : 24;
  if (h === 6) return '0 */6 * * *';
  if (h === 12) return '0 */12 * * *';
  return '0 0 * * *'; // 24h
}

export function spamhausDropScheduleIdentity() {
  return `${SPAMHAUS_DROP_INTEGRATION_KEY}::${USOM_RUN_MODES.INCREMENTAL}`;
}

export async function syncSpamhausDropSchedule(pool, importQueue, {
  logPrefix = '[scheduler]',
  liveScheduleIdentities = null
} = {}) {
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
  const identity = spamhausDropScheduleIdentity();

  if (existing) {
    const currentPattern = String(existing.pattern || '').trim();
    if (currentPattern === wantedPattern) {
      const live = liveScheduleIdentities || await collectLiveScheduleIdentities(importQueue);
      const stall = evaluateRepeatableStall(existing, identity, live);
      if (stall.stalled) {
        await importQueue.removeRepeatableByKey(existing.key);
        console.warn(
          `${logPrefix} repeat recovery reason=overdue_iteration identity=${identity} `
          + `pattern=${wantedPattern} `
          + `old_next=${new Date(stall.oldNextMs).toISOString()} now=${new Date().toISOString()} `
          + `overdue_s=${Math.round(stall.overdueMs / 1000)} live_iteration=false action=removed_for_rearm`
        );
        // Fall through to re-add below.
      } else {
        return { active: true, pattern: wantedPattern };
      }
    } else {
      await importQueue.removeRepeatableByKey(existing.key);
      console.log(
        `${logPrefix} removed spamhaus-drop-sync repeatable (schedule changed from=${currentPattern} to=${wantedPattern})`
      );
    }
  }

  await importQueue.add(
    SPAMHAUS_DROP_JOB_NAME,
    {
      triggeredBy: 'scheduler',
      integration_key: SPAMHAUS_DROP_INTEGRATION_KEY,
      run_mode: USOM_RUN_MODES.INCREMENTAL
    },
    {
      jobId: SPAMHAUS_DROP_JOB_ID,
      repeat: { pattern: wantedPattern }
    }
  );
  console.log(`${logPrefix} ensured spamhaus-drop-sync repeatable pattern=${wantedPattern}`);
  return { active: true, pattern: wantedPattern };
}
