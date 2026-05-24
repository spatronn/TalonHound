import { IOC_MATCH_EVENT_STATS_SELECT } from './incidentEventAggSql.js';
import { calculateIncidentRisk } from './riskEngine.js';

function normSourceType(row = {}) {
  const st = String(row?.source_type || '').toLowerCase();
  if (st) return st;
  const p = String(row?.parser_source || '').toLowerCase();
  if (/(proxy|url|http|webproxy|swg|squid)/.test(p)) return 'proxy';
  if (/(^|\s)dns(\s|$)|resolver|query|bind_dns/.test(p)) return 'dns';
  if (/(firewall|traffic|forti|palo|pan-os|checkpoint|netflow)/.test(p)) return 'firewall';
  return 'generic';
}

export function emptyIocEnvironmentImpact() {
  return {
    incident_count: 0,
    detection_event_count: 0,
    observed_host_count: 0,
    evidence_log_count: 0,
    first_seen_in_env: null,
    last_seen_in_env: null,
    allowed_count: 0,
    blocked_count: 0,
    unknown_action_count: 0,
    source_breakdown: [],
    max_incident_risk_score: null,
    avg_incident_risk_score: null,
    related_open_incidents: 0,
    related_closed_incidents: 0,
    observed_in_environment: false
  };
}

function emptyImpact() {
  return emptyIocEnvironmentImpact();
}

/**
 * Aggregate environment impact for an IOC across all related incidents/activity.
 */
export async function buildIocEnvironmentImpact(pool, observable, observableType) {
  if (!pool || !observable) return emptyImpact();

  const aggQ = `
    WITH activities AS (
      SELECT a.id, a.incident_id, a.first_seen, a.last_seen, a.verdict, a.status
      FROM ioc_activity a
      WHERE lower(a.ioc_value) = lower($1)
        AND lower(COALESCE(a.ioc_type, '')) = lower(COALESCE($2, ''))
        AND EXISTS (SELECT 1 FROM ioc_match_events m WHERE m.activity_id = a.id)
    ),
    ev AS (
      SELECT m.*
      FROM ioc_match_events m
      INNER JOIN activities a ON a.id = m.activity_id
    )
    SELECT
      (SELECT COUNT(*)::int FROM activities) AS incident_count,
      (SELECT COUNT(*)::int FROM ev) AS detection_event_count,
      (SELECT COUNT(DISTINCT NULLIF(
        COALESCE(
          NULLIF(m.match_context->>'observed_host', ''),
          NULLIF(m.host_name, ''),
          NULLIF(m.match_context->>'client_ip', ''),
          NULLIF(m.match_context->>'srcip', '')
        ),
        ''
      ))::int FROM ev m) AS observed_host_count,
      (SELECT MIN(a.first_seen) FROM activities a) AS first_seen_in_env,
      (SELECT MAX(a.last_seen) FROM activities a) AS last_seen_in_env,
      (SELECT COALESCE(SUM(
        CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('accept','accepted','allow','allowed','permit') THEN 1 ELSE 0 END
      ), 0)::int FROM ev m) AS allowed_count,
      (SELECT COALESCE(SUM(
        CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('deny','denied','drop','blocked','block') THEN 1 ELSE 0 END
      ), 0)::int FROM ev m) AS blocked_count,
      (SELECT COUNT(DISTINCT CASE
        WHEN lower(COALESCE(a.status, '')) IN ('closed', 'resolved') THEN NULL
        ELSE a.id
      END)::int FROM activities a) AS related_open_incidents,
      (SELECT COUNT(DISTINCT CASE
        WHEN lower(COALESCE(a.status, '')) IN ('closed', 'resolved') THEN a.id
        ELSE NULL
      END)::int FROM activities a) AS related_closed_incidents
  `;

  const evidenceQ = `
    SELECT COUNT(*)::bigint AS c
    FROM ioc_match_event_related_logs rl
    INNER JOIN ioc_activity a ON a.id = rl.activity_id
    WHERE lower(a.ioc_value) = lower($1)
      AND lower(COALESCE(a.ioc_type, '')) = lower(COALESCE($2, ''))
  `;

  const sourceQ = `
    SELECT m.source_type, m.parser_source, COUNT(*)::int AS c
    FROM ioc_match_events m
    INNER JOIN ioc_activity a ON a.id = m.activity_id
    WHERE lower(a.ioc_value) = lower($1)
      AND lower(COALESCE(a.ioc_type, '')) = lower(COALESCE($2, ''))
    GROUP BY m.source_type, m.parser_source
    ORDER BY c DESC
    LIMIT 20
  `;

  const riskRowsQ = `
    SELECT
      a.*,
      COALESCE(ev.asset_count, 0) AS asset_count,
      COALESCE(ev.event_count, 0) AS event_count,
      COALESCE(ev.accepted_connections, 0) AS accepted_connections,
      COALESCE(ev.blocked_connections, 0) AS blocked_connections,
      COALESCE(ev.inbound_events, 0) AS inbound_events,
      COALESCE(ev.outbound_events, 0) AS outbound_events,
      COALESCE(ev.blacklist_hits, 0) AS blacklist_hits,
      ev.dominant_source_type,
      ev.dominant_parser_source,
      ev.detection_type,
      ev.has_endpoint_evidence,
      ev.has_proxy_evidence,
      ev.has_dns_evidence,
      ev.has_firewall_evidence,
      ev.confidence
    FROM ioc_activity a
    INNER JOIN LATERAL (
      SELECT ${IOC_MATCH_EVENT_STATS_SELECT}
      FROM ioc_match_events m
      WHERE m.activity_id = a.id
    ) ev ON TRUE
    WHERE lower(a.ioc_value) = lower($1)
      AND lower(COALESCE(a.ioc_type, '')) = lower(COALESCE($2, ''))
      AND COALESCE(ev.event_count, 0) > 0
  `;

  const [aggRes, evidenceRes, sourceRes, riskRes] = await Promise.all([
    pool.query(aggQ, [observable, observableType]),
    pool.query(evidenceQ, [observable, observableType]),
    pool.query(sourceQ, [observable, observableType]),
    pool.query(riskRowsQ, [observable, observableType])
  ]);

  const agg = aggRes.rows[0] || {};
  const incidentCount = Number(agg.incident_count || 0);
  if (incidentCount <= 0) return emptyImpact();

  const detectionEvents = Number(agg.detection_event_count || 0);
  const allowed = Number(agg.allowed_count || 0);
  const blocked = Number(agg.blocked_count || 0);
  const unknown = Math.max(detectionEvents - allowed - blocked, 0);

  const sourceMap = new Map();
  for (const row of sourceRes.rows || []) {
    const key = normSourceType(row);
    sourceMap.set(key, (sourceMap.get(key) || 0) + Number(row.c || 0));
  }
  const source_breakdown = [...sourceMap.entries()]
    .map(([source_type, count]) => ({ source_type, count }))
    .sort((a, b) => b.count - a.count);

  const riskScores = (riskRes.rows || []).map((row) => {
    const withHits = { ...row, total_hits: Math.max(Number(row.total_hits || 0), Number(row.event_count || 0)) };
    return Number(calculateIncidentRisk(withHits).risk_score || 0);
  }).filter((n) => Number.isFinite(n));

  const maxRisk = riskScores.length ? Math.max(...riskScores) : null;
  const avgRisk = riskScores.length
    ? Number((riskScores.reduce((a, b) => a + b, 0) / riskScores.length).toFixed(2))
    : null;

  const evidenceCount = Number(evidenceRes.rows?.[0]?.c);
  const evidence_log_count = Number.isFinite(evidenceCount) ? evidenceCount : 0;

  return {
    incident_count: incidentCount,
    detection_event_count: detectionEvents,
    observed_host_count: Number(agg.observed_host_count || 0),
    evidence_log_count,
    first_seen_in_env: agg.first_seen_in_env || null,
    last_seen_in_env: agg.last_seen_in_env || null,
    allowed_count: allowed,
    blocked_count: blocked,
    unknown_action_count: unknown,
    source_breakdown,
    max_incident_risk_score: maxRisk,
    avg_incident_risk_score: avgRisk,
    related_open_incidents: Number(agg.related_open_incidents || 0),
    related_closed_incidents: Number(agg.related_closed_incidents || 0),
    observed_in_environment: true
  };
}
