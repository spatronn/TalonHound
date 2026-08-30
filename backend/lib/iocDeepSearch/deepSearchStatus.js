// Shared status helpers + client serialization for IOC Deep Search / Action Center.
// Effective status can differ from the stored row when a completed result set has passed
// expires_at but the periodic cleanup job has not yet flipped the row to 'expired'.

import crypto from 'node:crypto';

export const DEEP_SEARCH_TASK_TYPE = 'ioc_deep_search';
export const DEEP_SEARCH_TASK_TYPE_LABEL = 'IOC Deep Search';

export const TERMINAL_DEEP_SEARCH_STATUSES = Object.freeze(['completed', 'failed', 'expired', 'cancelled']);
export const ACTIVE_DEEP_SEARCH_STATUSES = Object.freeze(['queued', 'running']);

/** Stable fingerprint of a normalized query, for de-dup and safe (non-leaking) logging. */
export function queryFingerprint(normalizedQuery) {
  return crypto.createHash('sha256').update(String(normalizedQuery || ''), 'utf8').digest('hex');
}

/**
 * Resolve the client-facing status for a row. A completed result set past expires_at is
 * presented as expired even before DB cleanup flips it.
 */
export function effectiveDeepSearchStatus(row, now = new Date()) {
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

/** True when a completed result set is still browsable (not past its retention window). */
export function isBrowsable(row, now = new Date()) {
  return effectiveDeepSearchStatus(row, now) === 'completed';
}

/**
 * Sanitize worker/API failure text before returning it to clients: strip absolute paths and
 * truncate. (Deep Search has no on-disk artifact, but worker errors may still carry paths.)
 */
export function publicFailureReason(reason) {
  if (reason == null || reason === '') return null;
  let text = String(reason);
  text = text.replace(/[A-Za-z]:\\[^\s]+/g, '[path]');
  text = text.replace(/\/(?:data|var|tmp|home|usr|opt|app)\/[^\s]+/g, '[path]');
  text = text.replace(/\s+/g, ' ').trim();
  if (text.length > 280) text = `${text.slice(0, 277)}...`;
  return text || null;
}

/** Filter buckets exposed by Action Center. Deep Search shares the export bucket names. */
export const LIST_STATUS_FILTERS = Object.freeze({
  all: null,
  processing: ['queued', 'running'],
  ready: ['completed'],
  failed: ['failed'],
  expired: ['expired']
});

export function parseListStatusFilter(raw) {
  if (raw == null || raw === '' || raw === 'all') return null;
  const key = String(raw).trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(LIST_STATUS_FILTERS, key)) {
    return LIST_STATUS_FILTERS[key];
  }
  const allowed = new Set(['queued', 'running', 'completed', 'failed', 'expired', 'cancelled']);
  if (allowed.has(key)) return [key];
  return undefined; // invalid
}

/**
 * Present a deep-search row to the client without leaking SQL/AST internals. Shape is kept
 * close to the export serializer so Action Center can render both task types uniformly.
 */
export function serializeDeepSearch(row, now = new Date()) {
  const status = effectiveDeepSearchStatus(row, now);
  return {
    id: row.id,
    task_type: DEEP_SEARCH_TASK_TYPE,
    task_type_label: DEEP_SEARCH_TASK_TYPE_LABEL,
    original_query: row.original_query,
    normalized_query: row.normalized_query,
    classification_reason: row.classification_reason || null,
    origin: row.origin,
    status,
    requested_by_email: row.requested_by_email,
    requested_at: row.requested_at,
    started_at: row.started_at,
    completed_at: row.completed_at,
    ready_at: row.completed_at,
    match_count: row.match_count == null ? null : Number(row.match_count),
    duration_ms: row.duration_ms == null ? null : Number(row.duration_ms),
    progress: row.progress,
    expires_at: row.expires_at,
    failure_reason: publicFailureReason(row.failure_reason),
    cancelled_at: row.cancelled_at,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}
