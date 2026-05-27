/**
 * Import run metrics for integration_runs / integration_queue_jobs.
 * records_updated stays 0 until feed reconciliation updates existing rows (not in Sprint 1).
 */

export function createImportMetrics() {
  return {
    records_inserted: 0,
    records_updated: 0,
    records_duplicate: 0,
    records_skipped: 0,
    records_suppressed: 0,
    records_failed: 0,
    noteInsert() {
      this.records_inserted += 1;
    },
    noteUpdated() {
      this.records_updated += 1;
    },
    noteDuplicate() {
      this.records_duplicate += 1;
    },
    noteSkipped(n = 1) {
      this.records_skipped += Math.max(0, Number(n) || 0);
    },
    noteFailed(n = 1) {
      this.records_failed += Math.max(0, Number(n) || 0);
    },
    noteSuppressed(n = 1) {
      this.records_suppressed += Math.max(0, Number(n) || 0);
    },
    merge(other) {
      if (!other) return;
      this.records_inserted += Number(other.records_inserted || 0);
      this.records_updated += Number(other.records_updated || 0);
      this.records_duplicate += Number(other.records_duplicate || 0);
      this.records_skipped += Number(other.records_skipped || 0);
      this.records_suppressed += Number(other.records_suppressed || 0);
      this.records_failed += Number(other.records_failed || 0);
    },
    recordsProcessed() {
      return (
        this.records_inserted
        + this.records_updated
        + this.records_duplicate
        + this.records_skipped
        + this.records_suppressed
        + this.records_failed
      );
    },
    toJSON() {
      const processed = this.recordsProcessed();
      return {
        records_processed: processed,
        records_inserted: this.records_inserted,
        records_updated: this.records_updated,
        records_duplicate: this.records_duplicate,
        records_skipped: this.records_skipped,
        records_suppressed: this.records_suppressed,
        records_failed: this.records_failed
      };
    }
  };
}

export async function finalizeIntegrationRun(client, runId, metrics, status = 'success') {
  if (!runId || !client) return;
  const m = metrics?.toJSON?.() || metrics || {};
  await client.query(
    `UPDATE integration_runs
     SET status = $2,
         finished_at = clock_timestamp(),
         records_processed = $3,
         records_inserted = $4,
         records_updated = $5,
         records_duplicate = $6,
         records_skipped = $7,
         records_suppressed = $8,
         records_failed = $9,
         error_message = NULL
     WHERE id = $1`,
    [
      runId,
      status,
      Number(m.records_processed || 0),
      Number(m.records_inserted || 0),
      Number(m.records_updated || 0),
      Number(m.records_duplicate || 0),
      Number(m.records_skipped || 0),
      Number(m.records_suppressed || 0),
      Number(m.records_failed || 0)
    ]
  );
}

export async function failIntegrationRun(client, runId, errorMessage, metrics = null) {
  if (!runId || !client) return;
  const m = metrics?.toJSON?.() || metrics || {};
  await client.query(
    `UPDATE integration_runs
     SET status = 'failed',
         finished_at = clock_timestamp(),
         error_message = $2,
         records_processed = $3,
         records_inserted = $4,
         records_updated = $5,
         records_duplicate = $6,
         records_skipped = $7,
         records_suppressed = $8,
         records_failed = $9
     WHERE id = $1`,
    [
      runId,
      String(errorMessage || 'unknown error').slice(0, 4000),
      Number(m.records_processed || 0),
      Number(m.records_inserted || 0),
      Number(m.records_updated || 0),
      Number(m.records_duplicate || 0),
      Number(m.records_skipped || 0),
      Number(m.records_suppressed || 0),
      Number(m.records_failed || 0)
    ]
  );
}

export function metricsFromImportResult(result, suppressionStats) {
  const metrics = createImportMetrics();
  if (result?.metrics) {
    metrics.merge(result.metrics);
    return metrics;
  }
  const inserted = Number(result?.recordsProcessed || result?.records_inserted || 0);
  metrics.records_inserted = inserted;
  const sup = suppressionStats?.toJSON?.() || {};
  metrics.records_suppressed = Number(sup.suppressed_count || sup.skipped_suppressed_iocs || 0);
  return metrics;
}
