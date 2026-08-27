import { buildRepeatJobConfig } from './integrationSchedule.js';
import {
  collectLiveScheduleIdentities,
  evaluateRepeatableStall,
  USOM_RUN_MODES
} from './integrationFeedScheduleSync.js';

export const FILE_ARTIFACT_RECON_JOB_NAME = 'file-artifact-reconciliation';
export const FILE_ARTIFACT_RECON_JOB_ID = 'file-artifact-reconciliation-scheduled';
export const FILE_ARTIFACT_RECON_CRON = '0 0 * * *';
export const FILE_ARTIFACT_INTEGRATION_KEY = 'file-artifact';

function isFileArtifactsDualWriteEnabled() {
  const v = String(process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

export function fileArtifactScheduleIdentity() {
  return `${FILE_ARTIFACT_INTEGRATION_KEY}::${USOM_RUN_MODES.INCREMENTAL}`;
}

/**
 * Ensure daily File Artifact reconciliation repeatable when dual-write is enabled.
 */
export async function syncFileArtifactReconciliationSchedule(pool, importQueue, {
  logPrefix = '[scheduler]',
  liveScheduleIdentities = null
} = {}) {
  const enabled = isFileArtifactsDualWriteEnabled();
  const repeatables = await importQueue.getRepeatableJobs();
  const existing = repeatables.find(
    (r) => r.name === FILE_ARTIFACT_RECON_JOB_NAME
      || (r.id && String(r.id) === FILE_ARTIFACT_RECON_JOB_ID)
  );

  if (!enabled) {
    if (existing) {
      await importQueue.removeRepeatableByKey(existing.key);
      console.log(`${logPrefix} removed file-artifact-reconciliation repeatable (dual-write disabled)`);
    }
    return { active: false };
  }

  const repeat = buildRepeatJobConfig(FILE_ARTIFACT_INTEGRATION_KEY, FILE_ARTIFACT_RECON_CRON);
  const wantedPattern = String(repeat?.pattern || FILE_ARTIFACT_RECON_CRON).trim();
  const identity = fileArtifactScheduleIdentity();

  if (existing) {
    const currentPattern = String(existing.pattern || '').trim();
    if (currentPattern === wantedPattern) {
      const live = liveScheduleIdentities || await collectLiveScheduleIdentities(importQueue);
      const stall = evaluateRepeatableStall(existing, identity, live);
      if (stall.stalled) {
        await importQueue.removeRepeatableByKey(existing.key);
        console.warn(
          `${logPrefix} repeat recovery reason=overdue_iteration identity=${identity} `
          + `pattern=${wantedPattern}${existing.tz ? ` tz=${existing.tz}` : ''} `
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
        `${logPrefix} removed file-artifact-reconciliation repeatable (schedule changed from=${currentPattern} to=${wantedPattern})`
      );
    }
  }

  await importQueue.add(
    FILE_ARTIFACT_RECON_JOB_NAME,
    {
      triggeredBy: 'scheduler',
      integration_key: FILE_ARTIFACT_INTEGRATION_KEY,
      run_mode: USOM_RUN_MODES.INCREMENTAL
    },
    {
      jobId: FILE_ARTIFACT_RECON_JOB_ID,
      repeat: repeat?.tz ? { pattern: wantedPattern, tz: repeat.tz } : { pattern: wantedPattern }
    }
  );
  console.log(`${logPrefix} ensured file-artifact-reconciliation repeatable pattern=${wantedPattern}`);
  return { active: true, pattern: wantedPattern };
}
