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

function cleanText(value, max = 180) {
  if (value == null || typeof value === 'object' || typeof value === 'function') return '';
  return String(value).replace(/\s+/g, ' ').trim().slice(0, max);
}

function asTextArray(value, maxItems = 6) {
  return (Array.isArray(value) ? value : [])
    .map((x) => cleanText(x, 80))
    .filter(Boolean)
    .slice(0, maxItems);
}

export function compactEnvironmentInsightSummary(input = {}, opts = {}) {
  const topSampleLimit = Math.max(Number(opts.topSampleLimit ?? 5), 0);
  const listLimit = Math.max(Number(opts.listLimit ?? 10), 1);
  const samples = Array.isArray(input.highest_risk_incidents) ? input.highest_risk_incidents : [];
  const compactSamples = samples.slice(0, topSampleLimit).map((row) => ({
    id: row.id || null,
    incident_id: row.incident_id || null,
    public_id: row.public_id || row.ioc_public_id || null,
    ioc_type: row.ioc_type || null,
    risk_score: Number(row.risk_score || 0),
    threat_class: row.threat_class || 'unknown',
    tags: asTextArray(row.tags, 6),
    source: cleanText(row.source, 80) || null,
    observed_hosts_count: Number(row.observed_hosts_count || row.asset_count || 0),
    event_count: Number(row.event_count || 0),
    reason_summary: cleanText(row.reason_summary || row.reason, 180) || null
  }));

  return {
    range_days: input.range_days,
    period_start: input.period_start,
    period_end: input.period_end,
    aggregate_package_version: input.aggregate_package_version || 'environment_insight_v1',
    totals: input.totals || {},
    top_ioc_types: (input.top_ioc_types || []).slice(0, listLimit),
    top_ioc_sources: (input.top_ioc_sources || []).slice(0, listLimit),
    top_tags: (input.top_tags || []).slice(0, listLimit),
    threat_class_distribution: (input.threat_class_distribution || []).slice(0, listLimit),
    recommended_controls_frequency: (input.recommended_controls_frequency || []).slice(0, listLimit),
    missing_context_frequency: (input.missing_context_frequency || []).slice(0, listLimit),
    allowed_blocked_unknown_ratio: input.allowed_blocked_unknown_ratio || { allowed: 0, blocked: 0, unknown: 0 },
    top_risk_drivers: (input.top_risk_drivers || []).slice(0, listLimit),
    top_risk_reducers: (input.top_risk_reducers || []).slice(0, listLimit),
    highest_risk_incidents: compactSamples,
    institution_risk: input.institution_risk ? {
      score: input.institution_risk.score,
      level: input.institution_risk.level
    } : null,
    safety_constraints: {
      no_automatic_remediation: true,
      allowed_actions_are_navigation_or_refresh_only: true
    }
  };
}

export function environmentInsightPayloadMetrics(summary = {}, prompt = '') {
  const inputJson = JSON.stringify(summary || {});
  return {
    input_summary_bytes: Buffer.byteLength(inputJson),
    input_summary_chars: inputJson.length,
    final_prompt_chars: String(prompt || '').length,
    incidents_aggregated: Number(summary?.totals?.total_incidents || 0),
    top_samples: Array.isArray(summary?.highest_risk_incidents) ? summary.highest_risk_incidents.length : 0,
    threat_class_buckets: Array.isArray(summary?.threat_class_distribution) ? summary.threat_class_distribution.length : 0,
    top_tags: Array.isArray(summary?.top_tags) ? summary.top_tags.length : 0,
    top_sources: Array.isArray(summary?.top_ioc_sources) ? summary.top_ioc_sources.length : 0,
    controls_buckets: Array.isArray(summary?.recommended_controls_frequency) ? summary.recommended_controls_frequency.length : 0,
    missing_buckets: Array.isArray(summary?.missing_context_frequency) ? summary.missing_context_frequency.length : 0,
    top_driver_buckets: Array.isArray(summary?.top_risk_drivers) ? summary.top_risk_drivers.length : 0,
    top_reducer_buckets: Array.isArray(summary?.top_risk_reducers) ? summary.top_risk_reducers.length : 0
  };
}

export async function buildEnvironmentInsightSummary({
  pool,
  rangeDays,
  calculateIncidentRisk,
  computeInstitutionRiskOverview,
  incidentStatsSelect,
  topSampleLimit = 5
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
            ev.confidence,
            i.public_id AS ioc_public_id,
            COALESCE(NULLIF(i.source_name, ''), 'unknown') AS ioc_source_name,
            COALESCE(NULLIF(i.primary_threat_classification, ''), 'unknown') AS primary_threat_classification,
            COALESCE(tag_agg.tags, ARRAY[]::text[]) AS tags
     FROM ioc_activity a
     LEFT JOIN LATERAL (
       SELECT ${incidentStatsSelect}
       FROM ioc_match_events m
       WHERE m.activity_id = a.id
     ) ev ON TRUE
     LEFT JOIN LATERAL (
       SELECT i2.id, i2.public_id, i2.source_name, i2.primary_threat_classification
       FROM ioc_items i2
       WHERE lower(i2.observable) = lower(a.ioc_value)
         AND lower(i2.observable_type) = lower(a.ioc_type)
       ORDER BY i2.created_at DESC
       LIMIT 1
     ) i ON TRUE
     LEFT JOIN LATERAL (
       SELECT ARRAY_AGG(DISTINCT t.name ORDER BY t.name) AS tags
       FROM ioc_tags it
       JOIN tags t ON t.id = it.tag_id
       WHERE it.ioc_id = i.id
     ) tag_agg ON TRUE
     WHERE COALESCE(a.last_seen, a.first_seen, a.created_at) >= $1::timestamptz
     ORDER BY COALESCE(a.last_seen, a.first_seen, a.created_at) DESC
     LIMIT 300`,
    [period.period_start]
  );

  const scored = (riskQ.rows || []).map((row) => ({ ...row, ...calculateIncidentRisk(row) }));
  const topRisk = scored
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
    .slice(0, Math.max(Number(topSampleLimit || 5), 0))
    .map((row) => ({
      id: row.id,
      incident_id: row.incident_id,
      public_id: row.ioc_public_id || null,
      ioc_type: row.ioc_type,
      risk_score: Number(row.risk_score || 0),
      threat_class: row.primary_threat_classification || 'unknown',
      tags: asTextArray(row.tags, 6),
      source: row.ioc_source_name || null,
      observed_hosts_count: Number(row.asset_count || 0),
      event_count: Number(row.event_count || 0),
      reason_summary: cleanText(row.reason, 180) || null
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
