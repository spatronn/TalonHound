export const SYSTEM_HEALTH_STATUSES = Object.freeze([
  'healthy',
  'degraded',
  'unhealthy',
  'unknown'
]);

export function normalizeComponentStatus(value) {
  const status = String(value || '').toLowerCase();
  if (['healthy', 'ok', 'success', 'ready', 'running'].includes(status)) return 'healthy';
  if (['degraded', 'warning', 'warn', 'rate_limited'].includes(status)) return 'degraded';
  if (['unhealthy', 'error', 'failed', 'blocked', 'down', 'unavailable'].includes(status)) return 'unhealthy';
  return 'unknown';
}

/**
 * Unknown is not a failure. A known optional problem degrades the system; only
 * hard failures in required core services make the overall state unhealthy.
 */
export function resolveOverallSystemHealth({
  core = [],
  workers = [],
  feeds = [],
  providers = [],
  queues = []
} = {}) {
  const requiredCore = core.filter((item) => item.required !== false);
  if (requiredCore.some((item) => normalizeComponentStatus(item.status) === 'unhealthy')) {
    return { status: 'unhealthy', reason: 'required_core_failure' };
  }

  const relevant = [...core, ...workers, ...feeds, ...providers, ...queues]
    .filter((item) => item.enabled !== false && item.include_in_overall !== false);
  if (relevant.some((item) => ['unhealthy', 'degraded'].includes(normalizeComponentStatus(item.status)))) {
    return { status: 'degraded', reason: 'component_problem' };
  }
  if (relevant.some((item) => normalizeComponentStatus(item.status) === 'unknown')) {
    return { status: 'unknown', reason: 'insufficient_evidence' };
  }
  return { status: 'healthy', reason: 'all_observed_components_healthy' };
}

export function summarizeHealth(items = []) {
  return items.reduce((summary, item) => {
    const status = normalizeComponentStatus(item.status);
    summary.total += 1;
    summary[status] += 1;
    return summary;
  }, { total: 0, healthy: 0, degraded: 0, unhealthy: 0, unknown: 0 });
}
