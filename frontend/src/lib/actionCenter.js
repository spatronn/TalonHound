// Action Center presentation helpers (IOC Search Export tasks first).

export const ACTION_CENTER_PAGE_SIZE = 25;

export const ACTION_CENTER_FILTERS = Object.freeze([
  { key: 'all', label: 'All' },
  { key: 'processing', label: 'Processing' },
  { key: 'ready', label: 'Ready' },
  { key: 'failed', label: 'Failed' },
  { key: 'expired', label: 'Expired' }
]);

export const TASK_TYPE_LABELS = Object.freeze({
  ioc_search_export: 'IOC Search Export',
  ioc_deep_search: 'IOC Deep Search'
});

export function taskTypeLabel(taskType) {
  return TASK_TYPE_LABELS[taskType] || 'Task';
}

export function actionCenterStatusBadgeStyle(status) {
  const s = String(status || '').toLowerCase();
  // 'completed' (Deep Search) and 'ready' (Export) are both terminal-success; 'running'
  // (Deep Search) mirrors 'processing' (Export).
  if (s === 'ready' || s === 'completed') return { background: '#166534', color: '#86efac', border: '1px solid #15803d' };
  if (s === 'queued' || s === 'processing' || s === 'running') return { background: '#1d4ed8', color: '#93c5fd', border: '1px solid #2563eb' };
  if (s === 'failed') return { background: '#991b1b', color: '#fca5a5', border: '1px solid #b91c1c' };
  if (s === 'expired' || s === 'cancelled') return { background: '#334155', color: '#cbd5e1', border: '1px solid #475569' };
  return { background: '#1e293b', color: '#94a3b8', border: '1px solid #334155' };
}

export function formatActionCenterStatus(row) {
  const status = String(row?.status || '');
  if (status === 'processing' || status === 'running') {
    const p = Number(row?.progress);
    const label = status === 'running' ? 'Running' : 'Processing';
    return Number.isFinite(p) && p > 0 ? `${label} ${p}%` : label;
  }
  if (!status) return '—';
  return status.charAt(0).toUpperCase() + status.slice(1);
}

export function formatFileSize(bytes) {
  if (bytes == null || !Number.isFinite(Number(bytes))) return '—';
  const n = Number(bytes);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatExpiresIn(expiresAt, now = Date.now()) {
  if (!expiresAt) return '—';
  const ms = new Date(expiresAt).getTime() - now;
  if (!Number.isFinite(ms)) return '—';
  if (ms <= 0) return 'Expired';
  const totalSec = Math.floor(ms / 1000);
  const hours = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  if (hours >= 24) {
    const days = Math.floor(hours / 24);
    const remH = hours % 24;
    return remH > 0 ? `Expires in ${days}d ${remH}h` : `Expires in ${days}d`;
  }
  if (hours > 0) return mins > 0 ? `Expires in ${hours}h ${mins}m` : `Expires in ${hours}h`;
  if (mins > 0) return `Expires in ${mins}m`;
  return 'Expires in <1m';
}

export function truncateQuery(text, max = 72) {
  const s = String(text || '');
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

/** Polling interval: active jobs every 3s; otherwise refresh every 15s while on the page. */
export function actionCenterPollIntervalMs(items) {
  const hasActive = Array.isArray(items)
    && items.some((e) => e.status === 'queued' || e.status === 'processing' || e.status === 'running');
  return hasActive ? 3000 : 15000;
}

export function buildActionCenterListParams({ page = 1, pageSize = ACTION_CENTER_PAGE_SIZE, status = 'all' } = {}) {
  const params = {
    page: Math.max(1, Number(page) || 1),
    page_size: Math.min(100, Math.max(1, Number(pageSize) || ACTION_CENTER_PAGE_SIZE))
  };
  if (status && status !== 'all') params.status = status;
  return params;
}

/** Read `?task=<id>` from Action Center search params (highlight / scroll target). */
export function actionCenterTaskIdFromSearch(searchParams) {
  if (!searchParams) return '';
  const raw = typeof searchParams.get === 'function'
    ? searchParams.get('task')
    : searchParams.task;
  return String(raw || '').trim();
}

/** Subtle row highlight when Action Center was opened for a specific task. */
export function actionCenterTaskRowStyle(rowId, highlightedTaskId, baseStyle = {}) {
  if (!highlightedTaskId || String(rowId) !== String(highlightedTaskId)) return baseStyle;
  return {
    ...baseStyle,
    outline: '2px solid #2563eb',
    outlineOffset: -2,
    background: 'rgba(37,99,235,0.12)'
  };
}

/** True when the Search Exports modal string must not appear in the IOC list UI. */
export function hasLegacySearchExportsModal(sourceText) {
  return /Search Exports/.test(String(sourceText || ''));
}
