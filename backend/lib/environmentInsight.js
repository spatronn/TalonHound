export function parseEnvironmentInsightRange(value) {
  const raw = String(value || '30d').trim().toLowerCase();
  const days = raw.endsWith('d') ? Number(raw.slice(0, -1)) : Number(raw);
  return [7, 30, 90].includes(days) ? days : 30;
}

export function frequencyFromArray(values, limit = 10) {
  const counts = new Map();
  for (const value of values || []) {
    const key = String(value || '').trim() || 'unknown';
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export function topCountsFromRows(rows, keyField = 'key', countField = 'count', limit = 10) {
  return (rows || [])
    .map((row) => ({
      key: String(row?.[keyField] || 'unknown'),
      count: Number(row?.[countField] || 0)
    }))
    .filter((row) => row.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export function safeJson(value) {
  if (value == null) return null;
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return null; }
}

export async function buildEnvironmentInsightSummary({
  pool,
  rangeDays,
  calculateIncidentRisk,
  computeInstitutionRiskOverview,
  incidentStatsSelect
}) {
  const periodQ = await pool.query(
    `SELECT NOW() - ($1::text || ' days')::interval AS period_start, NOW() AS period_end`,
    [rangeDays]
  );
  const period = periodQ.rows[0] || {};

  const incidentQ = await pool.query(
    `SELECT
       COUNT(*)::int AS total_incidents,
       COUNT(*) FILTER (WHERE lower(COALESCE(status, '')) IN ('open', 'in progress', 'new'))::int AS open_incidents,
       COUNT(*) FILTER (WHERE lower(COALESCE(status, '')) IN ('closed', 'resolved'))::int AS closed_incidents
     FROM ioc_activity
     WHERE COALESCE(last_seen, first_seen, created_at) >= $1::timestamptz`,
    [period.period_start]
  );

  const eventQ = await pool.query(
    `SELECT
       COUNT(*)::int AS detection_events,
       COUNT(DISTINCT COALESCE(NULLIF(host_name, ''), NULLIF(destination_ip, '')))::int AS observed_hosts,
       SUM(CASE WHEN LOWER(COALESCE(match_context->>'action', normalized_event_json->>'action', '')) IN ('accept','accepted','allow','allowed','permit','pass') THEN 1 ELSE 0 END)::int AS allowed_count,
       SUM(CASE WHEN LOWER(COALESCE(match_context->>'action', normalized_event_json->>'action', '')) IN ('deny','denied','drop','blocked','block','reject') THEN 1 ELSE 0 END)::int AS blocked_count
     FROM ioc_match_events
     WHERE COALESCE(last_seen_at, event_time, created_at) >= $1::timestamptz`,
    [period.period_start]
  );

  const topIocTypesQ = await pool.query(
    `SELECT lower(ioc_type) AS key, COUNT(*)::int AS count
     FROM ioc_activity
     WHERE COALESCE(last_seen, first_seen, created_at) >= $1::timestamptz
     GROUP BY lower(ioc_type)
     ORDER BY count DESC
     LIMIT 10`,
    [period.period_start]
  );

  const topSourcesQ = await pool.query(
    `SELECT COALESCE(NULLIF(i.source_name, ''), 'unknown') AS key, COUNT(*)::int AS count
     FROM ioc_items i
     WHERE i.created_at >= $1::timestamptz
     GROUP BY COALESCE(NULLIF(i.source_name, ''), 'unknown')
     ORDER BY count DESC
     LIMIT 10`,
    [period.period_start]
  ).catch(() => ({ rows: [] }));

  const topTagsQ = await pool.query(
    `SELECT t.name AS key, COUNT(*)::int AS count
     FROM ioc_items i
     JOIN ioc_tags it ON it.ioc_id = i.id
     JOIN tags t ON t.id = it.tag_id
     WHERE i.created_at >= $1::timestamptz
     GROUP BY t.name
     ORDER BY count DESC
     LIMIT 10`,
    [period.period_start]
  ).catch(() => ({ rows: [] }));

  const aiQ = await pool.query(
    `SELECT structured_output_json
     FROM incident_ai_insights
     WHERE llm_last_updated_at >= $1::timestamptz
       AND structured_output_json IS NOT NULL`,
    [period.period_start]
  ).catch(() => ({ rows: [] }));

  const riskQ = await pool.query(
    `SELECT a.id, a.incident_id, a.ioc_value, a.ioc_type, a.status, a.verdict,
            a.first_seen, a.last_seen,
            COALESCE(ev.event_count, 0) AS event_count,
            COALESCE(ev.asset_count, 0) AS asset_count,
            COALESCE(ev.accepted_connections, 0) AS accepted_connections,
            COALESCE(ev.blocked_connections, 0) AS blocked_connections,
            COALESCE(ev.inbound_events, 0) AS inbound_events,
            COALESCE(ev.outbound_events, 0) AS outbound_events,
            COALESCE(ev.blacklist_hits, 0) AS blacklist_hits,
            ev.confidence
     FROM ioc_activity a
     LEFT JOIN LATERAL (
       SELECT ${incidentStatsSelect}
       FROM ioc_match_events m
       WHERE m.activity_id = a.id
     ) ev ON TRUE
     WHERE COALESCE(a.last_seen, a.first_seen, a.created_at) >= $1::timestamptz
     ORDER BY COALESCE(a.last_seen, a.first_seen, a.created_at) DESC
     LIMIT 300`,
    [period.period_start]
  );

  const scored = (riskQ.rows || []).map((row) => ({ ...row, ...calculateIncidentRisk(row) }));
  const topRisk = scored
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
    .slice(0, 5)
    .map((row) => ({
      id: row.id,
      incident_id: row.incident_id,
      ioc_value: row.ioc_value,
      ioc_type: row.ioc_type,
      risk_score: Number(row.risk_score || 0),
      reason: row.reason || null
    }));

  const aiRows = (aiQ.rows || []).map((row) => safeJson(row.structured_output_json) || {}).filter((row) => Object.keys(row).length);
  const controls = aiRows.flatMap((row) => Array.isArray(row.recommended_controls) ? row.recommended_controls : []);
  const missing = aiRows.flatMap((row) => Array.isArray(row.missing_context) ? row.missing_context : []);
  const drivers = aiRows.flatMap((row) => Array.isArray(row.risk_drivers) ? row.risk_drivers : []);
  const reducers = aiRows.flatMap((row) => Array.isArray(row.risk_reducers) ? row.risk_reducers : []);
  const threatClasses = aiRows.map((row) => row.threat_class || 'unknown');
  const eventStats = eventQ.rows[0] || {};
  const allowed = Number(eventStats.allowed_count || 0);
  const blocked = Number(eventStats.blocked_count || 0);
  const detectionEvents = Number(eventStats.detection_events || 0);
  const unknown = Math.max(detectionEvents - allowed - blocked, 0);
  let riskOverview = null;
  try { riskOverview = await computeInstitutionRiskOverview(); } catch {}

  return {
    range_days: rangeDays,
    period_start: period.period_start,
    period_end: period.period_end,
    aggregate_package_version: 'environment_insight_v1',
    totals: {
      ...(incidentQ.rows[0] || { total_incidents: 0, open_incidents: 0, closed_incidents: 0 }),
      detection_events: detectionEvents,
      observed_hosts: Number(eventStats.observed_hosts || 0)
    },
    top_ioc_types: topCountsFromRows(topIocTypesQ.rows),
    top_ioc_sources: topCountsFromRows(topSourcesQ.rows),
    top_tags: topCountsFromRows(topTagsQ.rows),
    threat_class_distribution: frequencyFromArray(threatClasses),
    recommended_controls_frequency: frequencyFromArray(controls),
    missing_context_frequency: frequencyFromArray(missing),
    allowed_blocked_unknown_ratio: { allowed, blocked, unknown },
    top_risk_drivers: frequencyFromArray(drivers),
    top_risk_reducers: frequencyFromArray(reducers),
    highest_risk_incidents: topRisk,
    repeated_ioc_patterns: [],
    institution_risk: riskOverview ? {
      score: riskOverview.institution_risk_score,
      level: riskOverview.risk_level,
      top_contributors: (riskOverview.top_contributing_incidents || []).slice(0, 5)
    } : null,
    safety_constraints: {
      no_automatic_remediation: true,
      allowed_actions_are_navigation_or_refresh_only: true
    }
  };
}
