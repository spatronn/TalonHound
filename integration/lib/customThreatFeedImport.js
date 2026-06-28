import { runCustomThreatFeedSync, loadCustomFeedByIntegrationKey } from './customThreatFeedSync.js';
import { isRunOnceSchedule } from './integrationSchedule.js';
import { insertCustomFeedSyncAudit } from './customThreatFeedWorkerAudit.js';
import { createImportMetrics } from './import-metrics.js';

function isAutomaticCustomFeedTrigger(triggeredBy) {
  const source = String(triggeredBy || 'scheduler').trim().toLowerCase();
  return source === '' || source === 'scheduler' || source === 'scheduled' || source === 'repeatable';
}

function buildSkippedMetrics(reason) {
  const metrics = createImportMetrics();
  metrics.noteSkipped(1);
  return {
    skipped: true,
    reason,
    metrics: metrics.toJSON()
  };
}

export async function runCustomThreatFeedImport(pool, options = {}) {
  const integrationKey = options.integrationKey
    || options.integration_key
    || options.job?.data?.integration_key;
  const triggeredBy = options.triggeredBy || options.job?.data?.triggeredBy || 'scheduler';
  const queueJobId = options.jobId || (options.job?.id ? String(options.job.id) : null);
  const { signal } = options;

  const feed = await loadCustomFeedByIntegrationKey(pool, integrationKey);
  if (!feed) {
    return buildSkippedMetrics('feed_not_found');
  }
  if (feed.deactivated_at || feed.integration_active === false) {
    return buildSkippedMetrics('feed_disabled');
  }
  if (
    isAutomaticCustomFeedTrigger(triggeredBy)
    && isRunOnceSchedule(feed.schedule)
    && feed.last_success_at
  ) {
    return buildSkippedMetrics('run_once_already_completed');
  }

  const client = await pool.connect();
  try {
    const result = await runCustomThreatFeedSync(client, feed, {
      signal,
      triggeredBy,
      queueJobId
    });

    await insertCustomFeedSyncAudit(pool, { ...result, url_host: feed.url_host }, triggeredBy);

    const metrics = createImportMetrics();
    metrics.records_inserted = result.inserted || 0;
    metrics.records_updated = (result.updated || 0) + (result.refreshed || 0);
    metrics.records_duplicate = result.duplicate_rows || 0;
    metrics.records_failed = result.status === 'failed' ? 1 : 0;
    metrics.noteSkipped(result.invalid_rows || 0);

    if (result.status === 'failed') {
      const err = new Error(result.error_message || 'Custom Threat Feed sync failed');
      err.failureType = 'import_error';
      throw err;
    }

    return {
      metrics: metrics.toJSON(),
      ...result
    };
  } finally {
    client.release();
  }
}
