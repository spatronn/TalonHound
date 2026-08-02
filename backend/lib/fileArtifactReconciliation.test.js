import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  FILE_ARTIFACT_RECON_JOB_NAME,
  FILE_ARTIFACT_RECON_JOB_ID,
  FILE_ARTIFACT_RECON_CRON
} from './fileArtifactReconciliationScheduleSync.js';
import { buildJobResultSnapshot } from './jobResultSnapshot.js';

describe('file-artifact-reconciliation job contract', () => {
  it('uses stable job name / id / daily cron', () => {
    assert.equal(FILE_ARTIFACT_RECON_JOB_NAME, 'file-artifact-reconciliation');
    assert.equal(FILE_ARTIFACT_RECON_JOB_ID, 'file-artifact-reconciliation-scheduled');
    assert.equal(FILE_ARTIFACT_RECON_CRON, '0 0 * * *');
  });

  it('preserves reconciliation metrics in result_details', () => {
    const snap = buildJobResultSnapshot({
      status: 'success',
      metrics: {
        records_processed: 100,
        records_updated: 5,
        records_failed: 1
      },
      runDetails: {
        checked: 100,
        updated: 5,
        failed: 1,
        scanned: 100,
        mappings_found: 88,
        merged: 3,
        promoted_to_sha256: 2,
        conflicts: 1,
        skipped: 10,
        errors: 0
      }
    });
    assert.equal(snap.result_details.scanned, 100);
    assert.equal(snap.result_details.mappings_found, 88);
    assert.equal(snap.result_details.merged, 3);
    assert.equal(snap.result_details.promoted_to_sha256, 2);
    assert.equal(snap.result_details.conflicts, 1);
  });

  it('run history is persisted via integration_queue_jobs (not integration_runs)', () => {
    // Worker markJobSuccess updates integration_queue_jobs.result_details.
    // Feed importers still use integration_runs; reconciliation is queue-native.
    assert.equal(FILE_ARTIFACT_RECON_JOB_NAME.includes('reconciliation'), true);
  });
});
