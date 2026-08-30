/**
 * Queued File Artifact reconciliation: provider exact-hash mapping + SHA256 primary promote.
 * Idempotent; does not delete IOC rows.
 */

import { runFileArtifactBackfill } from './backfill-file-artifacts.js';
import { isFileArtifactsDualWriteEnabled } from './lib/fileArtifacts.js';

export async function runFileArtifactReconciliation(pool, {
  signal = null,
  triggeredBy = 'scheduler',
  dryRun = false
} = {}) {
  if (signal?.aborted) {
    return { skipped: true, reason: 'aborted' };
  }

  if (!isFileArtifactsDualWriteEnabled()) {
    return {
      skipped: true,
      reason: 'file_artifacts_dual_write_disabled',
      metrics: {
        records_processed: 0,
        records_inserted: 0,
        records_updated: 0,
        records_failed: 0
      },
      runDetails: {
        checked: 0,
        updated: 0,
        failed: 0,
        scanned: 0,
        mappings_found: 0,
        merged: 0,
        promoted_to_sha256: 0,
        skipped: 1,
        conflicts: 0,
        errors: 0
      }
    };
  }

  const summary = await runFileArtifactBackfill({
    pool,
    endPool: false,
    dryRun,
    phase: 'provider',
    promotePrimaries: true,
    providerFilter: 'all'
  });

  if (signal?.aborted) {
    return { skipped: true, reason: 'aborted', summary };
  }

  const scanned = Number(summary.provider_mapped || 0) + Number(summary.batch_count || 0);
  const mappingsFound = Number(summary.provider_mapped || 0);
  const merged = Number(summary.merged_artifacts || 0);
  const promoted = Number(summary.promoted_to_sha256 || 0);
  const conflicts = Number(summary.conflicts || 0);
  const errors = Number(summary.errors || 0);
  const skipped = Number(summary.skipped_existing || 0) + Number(summary.unmatched_provider_records || 0);

  return {
    jobType: 'file_artifact_reconciliation',
    metrics: {
      records_processed: scanned,
      records_inserted: Number(summary.created_hashes || 0),
      records_updated: merged + promoted,
      records_failed: errors + conflicts,
      records_unchanged: skipped
    },
    runDetails: {
      mode: 'file_artifact_reconciliation',
      trigger: triggeredBy,
      checked: scanned,
      updated: merged + promoted,
      rejected: conflicts,
      failed: errors,
      unchanged: skipped,
      scanned,
      mappings_found: mappingsFound,
      merged,
      promoted_to_sha256: promoted,
      skipped,
      conflicts,
      errors,
      created_hashes: Number(summary.created_hashes || 0),
      created_source_observations: Number(summary.created_source_observations || 0),
      duration_ms: Number(summary.duration_ms || 0)
    },
    summary
  };
}
