import crypto from 'crypto';

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export function buildIncidentStatsSnapshot(input = {}) {
  return {
    incident_id: String(input?.id || input?.incident_id || ''),
    total_events: Math.max(safeNumber(input?.event_count ?? input?.total_events, 0), 0),
    unique_hosts: Math.max(safeNumber(input?.asset_count ?? input?.unique_hosts, 0), 0),
    accepted_connections: Math.max(safeNumber(input?.accepted_connections ?? input?.accepted_count, 0), 0),
    blocked_connections: Math.max(safeNumber(input?.blocked_connections ?? input?.blocked_count, 0), 0),
    blacklist_hits: Math.max(safeNumber(input?.blacklist_hits, 0), 0),
    total_hits: Math.max(safeNumber(input?.total_hits, 0), 0),
    verdict: String(input?.verdict || '')
  };
}

export function buildIncidentVersion(snapshot = {}) {
  const s = buildIncidentStatsSnapshot(snapshot);
  const raw = [
    s.incident_id,
    s.total_events,
    s.accepted_connections,
    s.blocked_connections,
    s.unique_hosts,
    s.blacklist_hits
  ].join('|');

  return crypto.createHash('sha1').update(raw).digest('hex').slice(0, 16);
}

export function shouldTriggerLlm(prevRaw, currentRaw) {
  const prev = prevRaw ? buildIncidentStatsSnapshot(prevRaw) : null;
  const current = buildIncidentStatsSnapshot(currentRaw);

  // Global thresholds: skip low-signal incidents.
  if (current.total_events < 50) return { trigger: false, reason: 'below_total_events_threshold' };
  if (current.unique_hosts < 2) return { trigger: false, reason: 'below_unique_hosts_threshold' };

  if (!prev || !prev.incident_id) {
    return { trigger: true, reason: 'new_incident' };
  }

  if (current.total_events >= Math.ceil(prev.total_events * 1.5)) {
    return { trigger: true, reason: 'total_events_50pct_increase' };
  }

  if (current.unique_hosts > prev.unique_hosts) {
    return { trigger: true, reason: 'unique_hosts_increase' };
  }

  if (prev.accepted_connections <= 0 && current.accepted_connections > 0) {
    return { trigger: true, reason: 'accepted_0_to_positive' };
  }

  if (current.blacklist_hits > prev.blacklist_hits) {
    return { trigger: true, reason: 'blacklist_hits_increase' };
  }

  return { trigger: false, reason: 'no_significant_change' };
}
