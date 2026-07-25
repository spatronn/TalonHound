// Shared status helpers for IOC search exports / Action Center.
// Effective status can differ from the stored row when a ready artifact has
// passed expires_at but the periodic cleanup job has not yet flipped the row.

export const EXPORT_TASK_TYPE = 'ioc_search_export';
export const EXPORT_TASK_TYPE_LABEL = 'IOC Search Export';

export const TERMINAL_EXPORT_STATUSES = Object.freeze(['ready', 'failed', 'expired', 'cancelled']);
export const ACTIVE_EXPORT_STATUSES = Object.freeze(['queued', 'processing']);

/** Filter buckets exposed by Action Center UI / list API. */
export const LIST_STATUS_FILTERS = Object.freeze({
  all: null,
  processing: ['queued', 'processing'],
  ready: ['ready'],
  failed: ['failed'],
  expired: ['expired']
});

/**
 * Resolve the client-facing status for a row.
 * Ready rows past expires_at are presented as expired even before DB cleanup.
 */
export function effectiveExportStatus(row, now = new Date()) {
  if (!row) return null;
  const status = String(row.status || '');
  if (status === 'ready' && row.expires_at) {
    const expires = new Date(row.expires_at);
    if (Number.isFinite(expires.getTime()) && expires.getTime() <= now.getTime()) {
      return 'expired';
    }
  }
  return status;
}

/**
 * Sanitize worker/API failure text before returning it to clients.
 * Strips absolute paths and truncates aggressively.
 */
export function publicFailureReason(reason) {
  if (reason == null || reason === '') return null;
  let text = String(reason);
  // Drop Windows and POSIX absolute path segments that may appear in worker errors.
  text = text.replace(/[A-Za-z]:\\[^\s]+/g, '[path]');
  text = text.replace(/\/(?:data|var|tmp|home|usr|opt|app)\/[^\s]+/g, '[path]');
  text = text.replace(/\s+/g, ' ').trim();
  if (text.length > 280) text = `${text.slice(0, 277)}...`;
  return text || null;
}

/**
 * Parse list filter query into a validated status array (or null = all).
 * Accepts UI buckets (processing/ready/failed/expired) or a single concrete status.
 */
export function parseListStatusFilter(raw) {
  if (raw == null || raw === '' || raw === 'all') return null;
  const key = String(raw).trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(LIST_STATUS_FILTERS, key)) {
    return LIST_STATUS_FILTERS[key];
  }
  const allowed = new Set(['queued', 'processing', 'ready', 'failed', 'expired', 'cancelled']);
  if (allowed.has(key)) return [key];
  return undefined; // invalid
}

export function parseListPagination({ page, pageSize, limit, offset } = {}) {
  // Prefer page/page_size (Action Center); fall back to limit/offset for older callers.
  const sizeRaw = pageSize != null ? Number(pageSize) : (limit != null ? Number(limit) : 25);
  const pageSizeSafe = Math.min(Math.max(Number.isFinite(sizeRaw) ? Math.trunc(sizeRaw) : 25, 1), 100);
  if (page != null || (limit == null && offset == null)) {
    const pageRaw = Number(page);
    const pageSafe = Math.max(Number.isFinite(pageRaw) ? Math.trunc(pageRaw) : 1, 1);
    return { limit: pageSizeSafe, offset: (pageSafe - 1) * pageSizeSafe, page: pageSafe, pageSize: pageSizeSafe };
  }
  const limitSafe = Math.min(Math.max(Number.isFinite(Number(limit)) ? Math.trunc(Number(limit)) : 50, 1), 200);
  const offsetSafe = Math.max(Number.isFinite(Number(offset)) ? Math.trunc(Number(offset)) : 0, 0);
  return {
    limit: limitSafe,
    offset: offsetSafe,
    page: Math.floor(offsetSafe / limitSafe) + 1,
    pageSize: limitSafe
  };
}
