import { buildRepeatJobConfig } from './integrationSchedule.js';

export const FILE_ARTIFACT_RECON_JOB_NAME = 'file-artifact-reconciliation';
export const FILE_ARTIFACT_RECON_JOB_ID = 'file-artifact-reconciliation-scheduled';
export const FILE_ARTIFACT_RECON_CRON = '0 0 * * *';

function isFileArtifactsDualWriteEnabled() {
  const v = String(process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * Ensure daily File Artifact reconciliation repeatable when dual-write is enabled.
 */
export async function syncFileArtifactReconciliationSchedule(pool, importQueue, { logPrefix = '[scheduler]' } = {}) {
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

  const repeat = buildRepeatJobConfig('file-artifact', FILE_ARTIFACT_RECON_CRON);
  const wantedPattern = String(repeat?.pattern || FILE_ARTIFACT_RECON_CRON).trim();

  if (existing) {
    const currentPattern = String(existing.pattern || '').trim();
    if (currentPattern === wantedPattern) {
      return { active: true, pattern: wantedPattern };
    }
    await importQueue.removeRepeatableByKey(existing.key);
    console.log(
      `${logPrefix} removed file-artifact-reconciliation repeatable (schedule changed from=${currentPattern} to=${wantedPattern})`
    );
  }

  await importQueue.add(
    FILE_ARTIFACT_RECON_JOB_NAME,
    { triggeredBy: 'scheduler', integration_key: 'file-artifact' },
    {
      jobId: FILE_ARTIFACT_RECON_JOB_ID,
      repeat: repeat?.tz ? { pattern: wantedPattern, tz: repeat.tz } : { pattern: wantedPattern }
    }
  );
  console.log(`${logPrefix} ensured file-artifact-reconciliation repeatable pattern=${wantedPattern}`);
  return { active: true, pattern: wantedPattern };
}
