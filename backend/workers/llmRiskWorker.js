import '../lib/ensure-db-password.js';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker } from 'bullmq';
import { getRedisUrl } from '../lib/redis-url.js';
import { calculateIncidentRisk } from '../lib/riskEngine.js';
import { createLlmRiskAdvisor } from '../risk/llmRiskAdvisor.js';
import { buildIncidentStatsSnapshot } from '../risk/llmRiskCommon.js';

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

  return q.rows?.[0] || null;
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

    return {
      incidentId,
      version: currentVersion,
      adjustment: output.llm_risk_adjustment,
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