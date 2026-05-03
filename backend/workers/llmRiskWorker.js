import '../lib/ensure-db-password.js';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker } from 'bullmq';
import { getRedisUrl } from '../lib/redis-url.js';
import { calculateIncidentRisk } from '../lib/riskEngine.js';
import { createLlmRiskAdvisor } from '../risk/llmRiskAdvisor.js';
import { buildIncidentStatsSnapshot } from '../risk/llmRiskCommon.js';
import { enrichIncidentContextWithRelatedIocs, summarizeRelatedIocSignals } from '../risk/incidentAiInsightContext.js';

const { Pool } = pg;

const redisUrl = getRedisUrl();
const llmRiskQueueName = process.env.LLM_RISK_QUEUE_NAME || 'llm-risk-jobs';
const concurrency = Math.max(Number(process.env.LLM_RISK_WORKER_CONCURRENCY || 1), 1);

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const advisor = createLlmRiskAdvisor({ redis });

function normSourceType(ev = {}) {
  const st = String(ev?.source_type || '').toLowerCase();
  if (st) return st;
  const p = String(ev?.parser_source || '').toLowerCase();
  if (/(proxy|url|http|webproxy|swg)/.test(p)) return 'proxy';
  if (/(^|\s)dns(\s|$)|resolver|query/.test(p)) return 'dns';
  if (/(waf|f5|asm|modsecurity|nginx-waf)/.test(p)) return 'waf';
  if (/(endpoint|edr|xdr|sysmon|process|file)/.test(p)) return 'endpoint';
  if (/(firewall|traffic|forti|palo|pan-os|checkpoint|netflow)/.test(p)) return 'firewall';
  return 'generic';
}

function eventOutcome(ev = {}) {
  const action = String(ev?.match_context?.action || ev?.normalized_event_json?.action || '').toLowerCase();
  const status = Number(ev?.normalized_event_json?.status || ev?.match_context?.status || 0);
  if (['accept', 'accepted', 'allow', 'allowed', 'permit', 'pass'].includes(action)) return 'allowed_or_successful';
  if (['deny', 'denied', 'drop', 'blocked', 'block', 'reject'].includes(action)) return 'blocked_or_denied';
  if (status >= 200 && status < 400) return 'allowed_or_successful';
  if (status === 401 || status === 403 || status === 407) return 'blocked_or_denied';
  if (status >= 400) return 'failed';
  return 'unknown';
}

async function loadIncident(id) {
  const q = await pool.query(
    `WITH ev AS (
       SELECT
         COUNT(*)::bigint AS event_count,
         COUNT(DISTINCT COALESCE(NULLIF(m.destination_ip, ''), NULLIF(m.host_name, '')))::int AS asset_count,
         SUM(CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('accept','accepted','allow','allowed','permit') THEN 1 ELSE 0 END)::bigint AS accepted_connections,
         SUM(CASE WHEN LOWER(COALESCE(m.match_context->>'action', '')) IN ('deny','denied','drop','blocked','block') THEN 1 ELSE 0 END)::bigint AS blocked_connections,
         SUM(CASE
               WHEN LOWER(COALESCE(m.match_context->>'direction', '')) = 'inbound'
                 OR LOWER(COALESCE(m.match_context->>'flow', '')) = 'inbound'
               THEN 1 ELSE 0
             END)::bigint AS inbound_events,
         SUM(CASE
               WHEN LOWER(COALESCE(m.match_context->>'direction', '')) = 'outbound'
                 OR LOWER(COALESCE(m.match_context->>'flow', '')) = 'outbound'
               THEN 1 ELSE 0
             END)::bigint AS outbound_events,
         SUM(CASE
               WHEN LOWER(COALESCE(m.match_context->>'list', '')) = 'blacklist'
                 OR LOWER(COALESCE(m.match_context->>'threat_list', '')) = 'blacklist'
                 OR LOWER(COALESCE(m.source_name, '')) LIKE '%blacklist%'
               THEN 1 ELSE 0
             END)::bigint AS blacklist_hits,
         CASE
           WHEN BOOL_OR(LOWER(COALESCE(m.confidence, '')) = 'high') THEN 'high'
           WHEN BOOL_OR(LOWER(COALESCE(m.confidence, '')) = 'medium') THEN 'medium'
           WHEN BOOL_OR(LOWER(COALESCE(m.confidence, '')) = 'low') THEN 'low'
           ELSE NULL
         END AS confidence
       FROM ioc_match_events m
       WHERE m.activity_id = $1::uuid
     )
     SELECT
       a.*,
       ev.event_count,
       ev.asset_count,
       ev.accepted_connections,
       ev.blocked_connections,
       ev.inbound_events,
       ev.outbound_events,
       ev.blacklist_hits,
       ev.confidence,
       NULL::text[] AS tags,
       COALESCE(prev.previous_incident_count, 0)::int AS previous_incident_count,
       COALESCE(prev.previous_verdict, 'unknown') AS previous_verdict
     FROM ioc_activity a
     CROSS JOIN ev
     LEFT JOIN LATERAL (
       SELECT
         COUNT(*)::int AS previous_incident_count,
         COALESCE((
           SELECT LOWER(COALESCE(a3.verdict, 'unknown'))
           FROM ioc_activity a3
           WHERE a3.ioc_value = a.ioc_value
             AND a3.ioc_type = a.ioc_type
             AND a3.id <> a.id
           ORDER BY a3.updated_at DESC
           LIMIT 1
         ), 'unknown') AS previous_verdict
       FROM ioc_activity a2
       WHERE a2.ioc_value = a.ioc_value
         AND a2.ioc_type = a.ioc_type
         AND a2.id <> a.id
     ) prev ON true
     WHERE a.id = $1::uuid
     LIMIT 1`,
    [id]
  );

  const incident = q.rows?.[0] || null;
  if (!incident) return null;

  const evQ = await pool.query(
    `SELECT
       id, activity_id, matched_ioc, ioc_type, source_type, parser_source, detection_type,
       host_name, event_time, created_at, normalized_event_json, match_context
     FROM ioc_match_events
     WHERE activity_id = $1::uuid
     ORDER BY COALESCE(last_seen_at, event_time, created_at) DESC, id DESC
     LIMIT 500`,
    [id]
  );

  const rows = evQ.rows || [];
  const sourceTypes = {};
  const detectionTypes = { realtime: 0, retroactive: 0, unknown: 0 };
  const outcomes = { allowed_or_successful: 0, blocked_or_denied: 0, failed: 0, unknown: 0 };
  const methods = { GET: 0, POST: 0, PUT: 0, DELETE: 0, OTHER: 0 };
  const statusCodes = {};
  const statusClasses = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, unknown: 0 };
  const hostCounts = new Map();

  for (const r of rows) {
    const st = normSourceType(r);
    sourceTypes[st] = (sourceTypes[st] || 0) + 1;
    const dt = String(r?.detection_type || '').toLowerCase();
    if (dt === 'realtime') detectionTypes.realtime += 1;
    else if (dt === 'retroactive') detectionTypes.retroactive += 1;
    else detectionTypes.unknown += 1;

    const out = eventOutcome(r);
    outcomes[out] = (outcomes[out] || 0) + 1;

    const method = String(r?.normalized_event_json?.method || r?.match_context?.method || '').toUpperCase();
    if (method === 'GET' || method === 'POST' || method === 'PUT' || method === 'DELETE') methods[method] += 1;
    else if (method) methods.OTHER += 1;

    const status = Number(r?.normalized_event_json?.status || r?.match_context?.status || 0);
    if (Number.isFinite(status) && status > 0) {
      const k = String(status);
      statusCodes[k] = (statusCodes[k] || 0) + 1;
      if (status >= 200 && status < 300) statusClasses['2xx'] += 1;
      else if (status < 400) statusClasses['3xx'] += 1;
      else if (status < 500) statusClasses['4xx'] += 1;
      else statusClasses['5xx'] += 1;
    } else {
      statusClasses.unknown += 1;
    }

    const host = String(r?.normalized_event_json?.src_ip || r?.normalized_event_json?.client_ip || r?.host_name || r?.match_context?.srcip || r?.match_context?.client_ip || '').trim();
    if (host) hostCounts.set(host, (hostCounts.get(host) || 0) + 1);
  }

  const firstTs = rows.length ? new Date(rows[rows.length - 1].event_time || rows[rows.length - 1].created_at).getTime() : NaN;
  const lastTs = rows.length ? new Date(rows[0].event_time || rows[0].created_at).getTime() : NaN;
  const durationMinutes = Number.isFinite(firstTs) && Number.isFinite(lastTs) && lastTs >= firstTs ? Math.round((lastTs - firstTs) / 60000) : 0;
  const eventsPerHour = durationMinutes > 0 ? Number((rows.length / (durationMinutes / 60)).toFixed(2)) : rows.length;

  incident.event_summary = {
    source_types: sourceTypes,
    detection_types: detectionTypes,
    outcomes,
    http: {
      total_requests: rows.length,
      methods,
      status_codes: statusCodes,
      status_classes: statusClasses,
      successful_or_redirect_count: statusClasses['2xx'] + statusClasses['3xx'],
      blocked_or_failed_count: outcomes.blocked_or_denied + outcomes.failed
    },
    hosts: {
      unique_count: hostCounts.size,
      top_hosts: Array.from(hostCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([host, events]) => ({ host, events }))
    },
    persistence: {
      first_event_at: Number.isFinite(firstTs) ? new Date(firstTs).toISOString() : null,
      last_event_at: Number.isFinite(lastTs) ? new Date(lastTs).toISOString() : null,
      duration_minutes: durationMinutes,
      events_per_hour: eventsPerHour
    }
  };

  incident.sample_events = rows.slice(0, 5).map((r) => ({
    detected_at: r.event_time || r.created_at || null,
    source_type: normSourceType(r),
    matched_ioc: r.matched_ioc,
    src_ip: r?.normalized_event_json?.src_ip || r?.normalized_event_json?.client_ip || r?.host_name || r?.match_context?.srcip || r?.match_context?.client_ip || null,
    method: r?.normalized_event_json?.method || r?.match_context?.method || null,
    status: r?.normalized_event_json?.status || r?.match_context?.status || null,
    outcome: eventOutcome(r)
  }));

  console.info(`[llm-payload] incident_id=${incident?.incident_id || id} ioc_type=${incident?.ioc_type || ''} event_count=${rows.length} sample_events=${incident.sample_events.length} source_types=${JSON.stringify(sourceTypes)} duration_minutes=${durationMinutes}`);

  return enrichIncidentContextWithRelatedIocs(incident, { pool });
}

const worker = new Worker(
  llmRiskQueueName,
  async (job) => {
    const incidentId = String(job.data?.incidentId || '').trim();
    const requestedVersion = String(job.data?.version || '').trim();
    if (!incidentId) return { skipped: true, reason: 'missing_incident_id' };

    const incident = await loadIncident(incidentId);
    if (!incident) return { skipped: true, reason: 'incident_not_found' };

    const risk = calculateIncidentRisk(incident);
    const currentVersion = advisor.computeVersion(incident);

    if (requestedVersion && requestedVersion !== currentVersion) {
      return { skipped: true, reason: 'stale_version', requestedVersion, currentVersion };
    }

    const snapshot = buildIncidentStatsSnapshot(incident);
    if (snapshot.total_events < 50 || snapshot.unique_hosts < 2) {
      return { skipped: true, reason: 'below_threshold', total_events: snapshot.total_events, unique_hosts: snapshot.unique_hosts };
    }

    const output = await advisor.evaluateAndCache({
      incident,
      baseRisk: risk.risk_score,
      version: currentVersion
    });

    const relatedSignals = summarizeRelatedIocSignals(incident?.related_iocs);
    console.log('[ai-insight][debug]', {
      incident_id: incident?.incident_id || null,
      context_path: 'worker',
      ...relatedSignals,
      hasAcceptedOrSuccessfulTraffic: output?.hasAcceptedOrSuccessfulTraffic ?? null,
      hasStrongMaliciousContext: output?.hasStrongMaliciousContext ?? null,
      raw_model_adjustment: output?.raw_model_adjustment ?? null,
      final_adjustment: output?.llm_risk_adjustment ?? null,
      normalization_reason: output?.normalization_reason ?? null
    });

    return {
      incidentId,
      context_path: 'worker',
      version: currentVersion,
      raw_model_adjustment: output.raw_model_adjustment ?? null,
      final_adjustment: output.llm_risk_adjustment,
      normalization_reason: output.normalization_reason ?? null,
      detected_positive_factors: output.detected_positive_factors || [],
      detected_negative_factors: output.detected_negative_factors || [],
      confidence: output.llm_risk_confidence,
      reason: output.llm_risk_reason
    };
  },
  { connection: redis, concurrency }
);

worker.on('completed', (job, result) => {
  console.log(`[llm-risk-worker] job ${job.id} completed`, result);
});

worker.on('failed', (job, err) => {
  console.error(`[llm-risk-worker] job ${job?.id} failed`, err?.message || err);
});

console.log(`[llm-risk-worker] listening queue=${llmRiskQueueName} concurrency=${concurrency}`);

async function shutdown(code = 0) {
  try { await worker.close(); } catch {}
  try { await redis.quit(); } catch {}
  try { await pool.end(); } catch {}
  process.exit(code);
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
