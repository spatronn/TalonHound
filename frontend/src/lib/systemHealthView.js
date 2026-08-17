export const HEALTH_LABELS = Object.freeze({
  healthy: 'Healthy',
  degraded: 'Degraded',
  unhealthy: 'Unhealthy',
  unknown: 'Unknown'
});

export function normalizeHealthStatus(value) {
  const status = String(value || '').toLowerCase();
  return Object.hasOwn(HEALTH_LABELS, status) ? status : 'unknown';
}

export function healthLabel(value) {
  return HEALTH_LABELS[normalizeHealthStatus(value)];
}

export function summaryLabel(summary = {}) {
  const total = Number(summary.total || 0);
  if (!total) return 'No evidence';
  const problems = Number(summary.unhealthy || 0) + Number(summary.degraded || 0);
  if (problems) return `${problems} need attention`;
  if (Number(summary.unknown || 0)) return `${summary.unknown} unknown`;
  return `${summary.healthy || 0} healthy`;
}

export function reasonLabel(reason) {
  const labels = {
    recent_success: 'Recent successful interaction',
    recent_failure: 'Recent failure',
    stale_success: 'Last success is outside the freshness window',
    stale_failure: 'Last failure is outside the freshness window',
    no_recent_evidence: 'No recent health evidence',
    not_configured: 'Required configuration is missing',
    partial_failure: 'Recent success and failure evidence',
    rate_limited: 'Provider recently rate limited',
    never_run: 'No completed run',
    disabled: 'Disabled',
    worker_registered: 'Worker registered with BullMQ',
    no_registered_worker: 'No registered worker evidence',
    worker_lookup_failed: 'Worker evidence unavailable',
    heartbeat_unavailable: 'No heartbeat is implemented',
    snapshot_unavailable: 'Queue evidence unavailable',
    evidence_unavailable: 'Evidence unavailable'
  };
  return labels[String(reason || '')] || String(reason || '').replaceAll('_', ' ') || '—';
}
