function toNum(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function safeDateMs(value) {
  const ms = new Date(value || 0).getTime();
  return Number.isFinite(ms) ? ms : NaN;
}

export function normalizeIocType(raw) {
  const t = String(raw || '').trim().toLowerCase();
  if (t === 'ip' || t === 'ipv4') return 'ip';
  if (t === 'domain') return 'domain';
  if (t === 'url') return 'url';
  if (['md5', 'sha1', 'sha256', 'hash', 'file_hash'].includes(t)) return 'hash';
  return 'unknown';
}

export function mapIocTypeToActivityType(iocType) {
  const t = normalizeIocType(iocType);
  if (t === 'domain') return 'dns';
  if (t === 'ip') return 'network';
  if (t === 'url') return 'http';
  if (t === 'hash') return 'file';
  return 'network';
}

export function buildActivityModel(input = {}) {
  const iocType = normalizeIocType(input?.ioc_type || input?.observable_type);
  const activityType = mapIocTypeToActivityType(iocType);

  const totalHits = Math.max(toNum(input?.hits ?? input?.total_hits, toNum(input?.event_count, 0)), 0);
  const eventCount = Math.max(toNum(input?.event_count, totalHits), 0);
  const uniqueHosts = Math.max(toNum(input?.observed_hosts ?? input?.asset_count ?? input?.unique_hosts, 0), 0);
  const acceptedConnections = Math.max(toNum(input?.accepted_connections ?? input?.execution_evidence, 0), 0);
  const blockedConnections = Math.max(toNum(input?.blocked_connections, 0), 0);

  const firstSeenMs = safeDateMs(input?.first_seen);
  const lastSeenMs = safeDateMs(input?.last_seen);
  const durationMinutes = Number.isFinite(firstSeenMs) && Number.isFinite(lastSeenMs) && lastSeenMs >= firstSeenMs
    ? Math.round((lastSeenMs - firstSeenMs) / 60000)
    : 0;
  const persistence = Math.max(durationMinutes, Math.max(toNum(input?.previous_incident_count, 0), 0));

  const hasExecution = acceptedConnections > 0;
  const isBlocked = blockedConnections > 0 && acceptedConnections <= 0;

  const signals = {};
  if (activityType === 'dns') {
    signals.dns_queries = totalHits;
    signals.connections = acceptedConnections + blockedConnections;
  }
  if (activityType === 'network') signals.connections = Math.max(eventCount, acceptedConnections + blockedConnections);
  if (activityType === 'http') signals.http_requests = totalHits;
  if (activityType === 'file') signals.file_hits = totalHits;

  return {
    type: activityType,
    volume: Math.max(totalHits, eventCount),
    unique_hosts: uniqueHosts,
    persistence,
    has_execution: hasExecution,
    is_blocked: isBlocked,
    signals
  };
}
