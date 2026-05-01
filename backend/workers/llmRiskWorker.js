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

function ipToLong(ip) {
  const p = String(ip || '').split('.').map((x) => Number(x));
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]) >>> 0;
}

function cidrContains(ip, cidr) {
  const [base, maskStr] = String(cidr || '').split('/');
  const mask = Number(maskStr);
  if (!base || !Number.isInteger(mask) || mask < 0 || mask > 32) return false;
  const ipN = ipToLong(ip);
  const baseN = ipToLong(base);
  if (ipN == null || baseN == null) return false;
  const m = mask === 0 ? 0 : ((0xffffffff << (32 - mask)) >>> 0);
  return (ipN & m) === (baseN & m);
}

function buildIgnoreCidrs() {
  const raw = String(process.env.AI_INSIGHT_HOST_IGNORE_CIDRS || '127.0.0.0/8,169.254.0.0/16,224.0.0.0/4,172.18.0.0/16');
  return raw.split(',').map((x) => x.trim()).filter(Boolean);
}

function isIgnoredHost(ip, cidrs) {
  return cidrs.some((c) => cidrContains(ip, c));
}

async function loadRelatedIocs(activity) {
  if (!activity?.id || String(activity?.ioc_type || '').toLowerCase() !== 'domain') return [];
  const lookbackHours = Math.max(Number(process.env.AI_INSIGHT_RELATED_IOC_LOOKBACK_HOURS || 24), 1);
  const lookforwardHours = Math.max(Number(process.env.AI_INSIGHT_RELATED_IOC_LOOKFORWARD_HOURS || 24), 1);
  const ignoreCidrs = buildIgnoreCidrs();

  const dnsQ = await pool.query(
    `SELECT
       COALESCE(NULLIF(m.match_context->>'response_ip',''), NULLIF(m.destination_ip,'')) AS response_ip,
       MIN(m.event_time) AS first_seen,
       MAX(m.event_time) AS last_seen,
       ARRAY_REMOVE(ARRAY_AGG(DISTINCT NULLIF(COALESCE(m.match_context->>'client_ip', m.host_name),'')), NULL) AS client_ips
     FROM ioc_match_events m
     WHERE m.activity_id = $1::uuid
       AND LOWER(COALESCE(m.ioc_type,'')) = 'domain'
     GROUP BY 1
     HAVING COALESCE(NULLIF(m.match_context->>'response_ip',''), NULLIF(m.destination_ip,'')) ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'`,
    [activity.id]
  );

  const out = [];
  for (const row of dnsQ.rows || []) {
    const responseIp = row.response_ip;
    const inIoc = await pool.query(`SELECT 1 FROM ioc_activity WHERE ioc_type='ip' AND ioc_value=$1 LIMIT 1`, [responseIp]);

    const traffic = await pool.query(
      `SELECT
         SUM(CASE WHEN LOWER(COALESCE(match_context->>'action','')) IN ('accept','accepted','allow','allowed','permit') THEN 1 ELSE 0 END)::bigint AS accepted_count,
         SUM(CASE WHEN LOWER(COALESCE(match_context->>'action','')) IN ('deny','denied','drop','blocked','block') THEN 1 ELSE 0 END)::bigint AS blocked_count,
         MIN(event_time) AS first_seen,
         MAX(event_time) AS last_seen,
         ARRAY_REMOVE(ARRAY_AGG(DISTINCT NULLIF(COALESCE(match_context->>'srcip', host_name),'')), NULL) AS internal_hosts,
         ARRAY_REMOVE(ARRAY_AGG(DISTINCT (match_context->>'service')), NULL) AS services,
         ARRAY_REMOVE(ARRAY_AGG(DISTINCT (match_context->>'dstport')), NULL) AS ports,
         SUM(COALESCE(NULLIF(match_context->>'sentbyte','')::bigint,0))::bigint AS sent_bytes,
         SUM(COALESCE(NULLIF(match_context->>'rcvdbyte','')::bigint,0))::bigint AS received_bytes
       FROM ioc_match_events
       WHERE event_time BETWEEN ($2::timestamptz - ($4 || ' hours')::interval) AND ($3::timestamptz + ($5 || ' hours')::interval)
         AND (
           COALESCE(match_context->>'dstip', destination_ip) = $1
           OR COALESCE(match_context->>'srcip', host_name) = $1
         )`,
      [responseIp, activity.first_seen, activity.last_seen, lookbackHours, lookforwardHours]
    );

    const t = traffic.rows?.[0] || {};
    const rawDnsClientIps = row.client_ips || [];
    const rawTrafficHosts = t.internal_hosts || [];
    const ignoredHosts = [];
    const filteredDnsClientHosts = rawDnsClientIps.filter((ip) => {
      const ignored = isIgnoredHost(ip, ignoreCidrs);
      if (ignored) ignoredHosts.push(ip);
      return !ignored;
    });
    const filteredTrafficInternalHosts = rawTrafficHosts.filter((ip) => {
      const ignored = isIgnoredHost(ip, ignoreCidrs);
      if (ignored && !ignoredHosts.includes(ip)) ignoredHosts.push(ip);
      return !ignored;
    });

    const acceptedCount = Number(t.accepted_count || 0);
    const sameHost = filteredDnsClientHosts.some((ip) => filteredTrafficInternalHosts.includes(ip));
    const hasValidAttribution = filteredDnsClientHosts.length > 0 && filteredTrafficInternalHosts.length > 0;

    let chainType = 'linked_ioc_without_accepted_traffic';
    let attributionStatus = null;
    let riskSignal = 'low_to_medium';
    if (acceptedCount > 0 && sameHost) {
      chainType = 'same_host_dns_to_connection';
      riskSignal = 'high';
    } else if (acceptedCount > 0 && filteredTrafficInternalHosts.length > 0) {
      chainType = 'environment_level_related_activity';
      riskSignal = 'medium';
    } else if (acceptedCount > 0) {
      chainType = 'accepted_traffic_to_related_ioc';
      riskSignal = 'medium';
      attributionStatus = 'accepted_traffic_without_valid_host_attribution';
    } else if (filteredDnsClientHosts.length === 0) {
      attributionStatus = 'no_valid_dns_client_after_filter';
    }

    out.push({
      relationship: 'dns_response_ip',
      source_ioc: activity.ioc_value,
      source_ioc_type: 'domain',
      related_ioc: responseIp,
      related_ioc_type: 'ip',
      related_ioc_in_ioc_list: inIoc.rowCount > 0,
      chain_type: chainType,
      attribution_status: attributionStatus,
      raw_dns_client_ips: rawDnsClientIps,
      filtered_dns_client_hosts: filteredDnsClientHosts,
      raw_traffic_hosts: rawTrafficHosts,
      filtered_traffic_internal_hosts: filteredTrafficInternalHosts,
      ignored_hosts: ignoredHosts,
      ignore_cidrs_used: ignoreCidrs,
      dns: {
        query: activity.ioc_value,
        response_ip: responseIp,
        client_ips: filteredDnsClientHosts,
        first_seen: row.first_seen,
        last_seen: row.last_seen
      },
      traffic: {
        accepted_count: acceptedCount,
        blocked_count: Number(t.blocked_count || 0),
        unique_internal_hosts: filteredTrafficInternalHosts.length,
        internal_hosts: filteredTrafficInternalHosts,
        ports: (t.ports || []).map((x) => Number(x)).filter(Boolean),
        services: t.services || [],
        first_seen: t.first_seen || null,
        last_seen: t.last_seen || null,
        sent_bytes: Number(t.sent_bytes || 0),
        received_bytes: Number(t.received_bytes || 0)
      },
      risk_signal: riskSignal
    });
  }

  return out;
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
  incident.related_iocs = await loadRelatedIocs(incident);
  return incident;
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

    if (String(incident?.incident_id || '') === '869') {
      console.log('[llm-risk-worker][debug-869] related_iocs', JSON.stringify(incident.related_iocs || []));
      console.log('[llm-risk-worker][debug-869] output', JSON.stringify(output || {}));
    }

    return {
      incidentId,
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