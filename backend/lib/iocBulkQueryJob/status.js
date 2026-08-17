export const BULK_QUERY_TASK_TYPE = 'ioc_bulk_query';
export const BULK_QUERY_TASK_TYPE_LABEL = 'IOC Bulk Action';

export const TERMINAL_BULK_QUERY_STATUSES = Object.freeze([
  'completed', 'failed', 'cancelled', 'expired'
]);
export const ACTIVE_BULK_QUERY_STATUSES = Object.freeze(['queued', 'processing']);

export const LIST_STATUS_FILTERS = Object.freeze({
  all: null,
  processing: ['queued', 'processing'],
  ready: ['completed'],
  failed: ['failed'],
  expired: ['expired']
});

export function effectiveBulkQueryStatus(row, now = new Date()) {
  if (!row) return null;
  const status = String(row.status || '');
  if (status === 'completed' && row.expires_at) {
    const expires = new Date(row.expires_at);
    if (Number.isFinite(expires.getTime()) && expires.getTime() <= now.getTime()) {
      return 'expired';
    }
  }
  return status;
}

export function parseListStatusFilter(raw) {
  if (raw == null || raw === '' || raw === 'all') return null;
  const key = String(raw).trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(LIST_STATUS_FILTERS, key)) {
    return LIST_STATUS_FILTERS[key];
  }
  const allowed = new Set(['queued', 'processing', 'completed', 'failed', 'expired', 'cancelled']);
  if (allowed.has(key)) return [key];
  return undefined;
}

export function publicFailureReason(reason) {
  if (reason == null || reason === '') return null;
  let text = String(reason).replace(/\s+/g, ' ').trim();
  if (text.length > 280) text = `${text.slice(0, 277)}...`;
  return text || null;
}

export function serializeBulkQueryJob(row, now = new Date()) {
  const status = effectiveBulkQueryStatus(row, now);
  const matchCount = row.match_count == null ? null : Number(row.match_count);
  const succeeded = Number(row.succeeded || 0);
  const skipped = Number(row.skipped || 0);
  const failed = Number(row.failed || 0);
  return {
    id: row.id,
    task_type: BULK_QUERY_TASK_TYPE,
    task_type_label: BULK_QUERY_TASK_TYPE_LABEL,
    action: row.action,
    original_query: row.original_query,
    normalized_query: row.normalized_query,
    status,
    requested_by_email: row.requested_by_email,
    requested_at: row.requested_at,
    started_at: row.started_at,
    completed_at: row.completed_at,
    ready_at: row.completed_at,
    match_count: matchCount,
    record_count: matchCount,
    succeeded,
    skipped,
    failed,
    progress: row.progress,
    expires_at: row.expires_at,
    failure_reason: publicFailureReason(row.failure_reason),
    error_sample: Array.isArray(row.error_sample) ? row.error_sample : null,
    cancelled_at: row.cancelled_at,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}
