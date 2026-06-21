import { AUDIT_ACTION, AUDIT_ENTITY } from './auditConstants.js';
import { extractUrlHost } from './customThreatFeedUtils.js';

export async function insertCustomFeedSyncAudit(pool, result, triggeredBy = 'scheduler') {
  if (!pool || !result) return;
  const action = result.status === 'failed'
    ? AUDIT_ACTION.CUSTOM_FEED_SYNC_FAILED
    : AUDIT_ACTION.CUSTOM_FEED_SYNC_COMPLETED;

  const metadata = {
    feed_id: result.feed_id,
    feed_name: result.feed_name,
    url_host: result.url_host || extractUrlHost(result.url || ''),
    actor: triggeredBy,
    run_id: result.run_id,
    inserted: result.inserted,
    updated: result.updated,
    refreshed: result.refreshed,
    expired_missing: result.expired_missing,
    invalid_rows: result.invalid_rows,
    status: result.status,
    error: result.error_message ? String(result.error_message).slice(0, 500) : null
  };

  await pool.query(
    `INSERT INTO audit_logs (
       action, entity_type, entity_id, entity_display, severity, status, source, metadata
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
    [
      action,
      AUDIT_ENTITY.CUSTOM_THREAT_FEED,
      String(result.feed_id || ''),
      result.feed_name || 'Custom Threat Feed',
      result.status === 'failed' ? 'warning' : 'info',
      result.status === 'failed' ? 'failed' : 'success',
      'integration-worker',
      JSON.stringify(metadata)
    ]
  );
}
