import './lib/ensure-db-password.js';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import IORedis from 'ioredis';
import { Queue } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import {
  signUserToken,
  apiAuthGate,
  csrfProtection,
  appendAuthCookie,
  clearAuthCookie,
  appendCsrfCookie,
  clearCsrfCookie
} from './lib/auth.js';
import { rbacHttpPolicy, requireRole, ROLES } from './lib/rbac.js';
import { registerUserManagementRoutes } from './routes/users.js';
import { registerPublishedFeedRoutes } from './routes/publishedFeeds.js';
import { registerApiKeyRoutes } from './routes/apiKeys.js';
import { registerPublicFeedRoutes } from './routes/publicFeeds.js';
import { registerAuditLogRoutes } from './routes/auditLogs.js';
import { registerIocExportRoutes } from './routes/iocExport.js';
import { registerRdapEnrichmentRoutes } from './routes/rdapEnrichment.js';
import { registerDnsmaniaEnrichmentRoutes } from './routes/dnsmaniaEnrichment.js';
import { registerIpEnrichmentRoutes } from './routes/ipEnrichment.js';
import { registerAbuseIpdbEnrichmentRoutes } from './routes/abuseipdbEnrichment.js';
import { registerSpamhausDropEnrichmentRoutes } from './routes/spamhausDropEnrichment.js';
import {
  registerAnalystIntelligenceRoutes,
  enrichItemsWithAnalystIntelligenceCounts,
  mergeAnalystIntelligenceItem
} from './routes/analystIntelligence.js';
import { registerIocExpirationRoutes, serializeExpirationPolicy } from './routes/iocExpiration.js';
import { registerIocDeleteRoute } from './routes/iocDelete.js';
import { formatExpirationSummary, buildIocExpirationSummary, recomputeIocGlobalStatus } from './lib/iocExpiration.js';
import {
  archiveIntegrationFeed,
  findActivePurgeJobForFeed,
  FEED_PURGE_JOB_NAME,
  previewFeedDataPurge,
  restoreIntegrationFeed,
  validatePurgeConfirmName
} from './lib/feedLifecycle.js';
import { categoryToLegacyType, isValidCategory } from './lib/tagHelpers.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './lib/auditConstants.js';
import { resolveRunCounters } from './lib/integrationRunCounters.js';
import {
  computeSuppressionEffectiveStatus,
  normalizeSuppressionStatusFilter,
  SUPPRESSION_STATUS_CASE_SQL
} from './lib/iocSuppressionStatus.js';
import { registerRouteModule, logRegisteredRouteModules } from './lib/routeRegistry.js';
import { runReadinessChecks, buildHealthPayload } from './lib/healthChecks.js';
import {
  loadIntegrationQueueHealthSnapshot,
  runIntegrationQueueRecover
} from './lib/integrationQueueApi.js';
import { parseActionReason } from './lib/reasonValidation.js';
import { regenerateAllEnabledFeeds } from './lib/feedPublisherService.js';
import { buildFeedMetricsHints } from './lib/feedMetricsHints.js';
import { assertCustomFeedSettingsAllowed } from './lib/customThreatFeedAccess.js';
import { normalizeRdapTarget } from './lib/domainRoot.js';
import { getIpinfoLiteConfig } from './services/ipinfoLiteService.js';
import { getAbuseIpdbConfig } from './services/abuseipdbService.js';
import { getSpamhausDropConfig, getSpamhausDropSyncState } from './lib/spamhausDropSync.js';
import { getRdapProviderAdminSummary } from './services/rdapEnrichmentService.js';
import { getDnsmaniaProviderAdminSummary } from './services/dnsmaniaEnrichmentService.js';
import { createAuditLogService } from './lib/auditLogService.js';
import { buildIocConfidenceSummary, buildIocConfidenceSummaryForDetails, buildDisplayConfidenceForItems, buildConfidenceProvenance, buildConfidenceSourceDescription, computeItemStoredConfidence, validateConfidenceInput, normalizeConfidence as normalizeIocConfidence, computeInheritedEffectiveConfidence } from './lib/iocConfidence.js';
import {
  enrichItemsWithActiveSourceCounts,
  fetchObservableMembershipSummary,
  fetchIocListStats,
  fetchActiveIocListPage,
  fetchIocStatsLastUpdate,
  iocStatusSqlClause,
  parseIocListStatusFilter,
  activeObservableHasActiveSourceSql,
  applyActiveListScope
} from './lib/iocActiveSources.js';
import {
  buildIocDetailsSourceEvidence,
  fetchFeedSourceEvidenceForItems
} from './lib/iocFeedSourceEvidence.js';
import { buildFileInformation } from './lib/iocFileInformation.js';
import { buildFeedIntelligence } from './lib/feedTagNormalization.js';
import {
  applySourceTagOverrides,
  feedTagsIncludeSourceTag,
  hideSourceTag,
  listActiveSourceTagOverrides,
  restoreSourceTag
} from './lib/iocSourceTagOverrides.js';
import {
  buildIocStatsCacheKey,
  readIocStatsCache,
  writeIocStatsCache
} from './lib/iocStatsCache.js';
import {
  formatIocListStatsApiResponse,
  getIocListStatsSnapshot,
  isIocListStatsRefreshInProgress,
  queueIocListStatsRefresh,
  readIocListBrowseGlobalTotal,
  IOC_LIST_STATS_CACHE_TTL_MS
} from './lib/iocListStatsSnapshot.js';
import {
  IOC_LIST_BROWSE_CAP,
  normalizeIocListPageSize,
  buildIocListPagination
} from './lib/iocListPagination.js';
import {
  decorateIocListItems,
  resolveIocListStatusScope
} from './lib/iocListDisplay.js';
import {
  hasIocConfidenceColumns,
  hasConfidenceProvenanceColumns,
  iocConfidenceJoinSql,
  iocConfidenceSelectSql
} from './lib/schemaCapabilities.js';
import { registerIocConfidenceRoutes } from './routes/iocConfidence.js';
import { registerIocSourceRoutes } from './routes/iocSources.js';
import { registerCustomThreatFeedRoutes } from './routes/customThreatFeeds.js';
import { registerThreatActorRoutes } from './routes/threatActors.js';
import { registerThreatClassificationRoutes } from './routes/threatClassifications.js';
import { registerIocThreatMetadataRoutes, buildThreatMetadataFields, enrichItemsWithThreatMetadata, mergeThreatMetadataItem, batchLoadFeedClassifications, mergeFeedClassificationsIntoItem } from './routes/iocThreatMetadata.js';
import { loadThreatClassificationRegistry, buildThreatClassificationResponseFields } from './lib/threatClassification.js';
import { parseThreatClassificationFilterParam } from './lib/iocThreatClassifications.js';
import { createManualIoc } from './lib/manualIocCreate.js';
import { createManualSuppression } from './lib/manualSuppressionCreate.js';
import { findActiveRunningJobForSource, recoverStaleRunningJobs } from './lib/integrationQueueRecovery.js';
import { MANUAL_JOB_PRIORITY } from './lib/integrationQueueConfig.js';
import { computeNextRunAt, computeNextWeeklyRunAt, buildRepeatableNextRunMap, buildHourlySlotMap, getSystemScheduleTimezone, isAllowedScheduleCron, isRunOnceSchedule } from './lib/integrationSchedule.js';
import { getUsomFullReconciliationScheduleConfig, syncSingleFeedSchedule } from './lib/integrationFeedScheduleSync.js';
import {
  buildUsomReconciliationHealth,
  decideUsomEnqueue,
  inferUsomRunMode,
  isScheduledRepeatIteration,
  normalizeUsomRunMode,
  USOM_FULL_RECONCILIATION_MODE,
  USOM_INCREMENTAL_MODE
} from './lib/usomReconciliation.js';
import { resolveManualIntegrationRunMode } from './lib/integrationManualRun.js';
import {
  AUTH_KEY_FEED_KEYS,
  formatFeedCredentialsSummary,
  sanitizeFeedErrorMessage,
  URLHAUS_FEED_KEY,
  testUrlhausConnection
} from './lib/urlhausIntegration.js';
import { MALWAREBAZAAR_FEED_KEY, testMalwareBazaarConnection } from './lib/malwarebazaarIntegration.js';
import {
  THREATFOX_FEED_KEY,
  testThreatFoxConnection,
  validateThreatFoxRecentDays
} from './lib/threatfoxIntegration.js';
import {
  ALIENVAULT_OTX_FEED_KEY,
  testOtxConnection
} from './lib/alienvaultOtxIntegration.js';
import {
  formatIntegrationJobDisplayName,
  withIntegrationJobDisplayName
} from './lib/integrationJobLabels.js';
import {
  VT_PROVIDER,
  VT_NOT_INDEXED_MESSAGE,
  buildVtNotIndexedResponse,
  isVtResourceNotFound,
  vtHttpErrorMessage
} from './lib/virustotalEnrichment.js';

const { Pool } = pg;

const app = express();
const port = process.env.PORT || 3000;
const demoEmail = String(process.env.DEMO_EMAIL || '').trim();
const demoPassword = String(process.env.DEMO_PASSWORD || '').trim();

// Single shared pool: no new Client() per request; connections are reused (recommended for latency).
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

loadThreatClassificationRegistry(pool).catch((err) => {
  console.warn('[threat-classifications] registry preload skipped:', err?.message || err);
});

const redisUrl = getRedisUrl();
const queueName = process.env.QUEUE_NAME || 'integration-imports';
const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const importQueue = new Queue(queueName, { connection: redis });
const auditLogService = createAuditLogService(pool);

// Geo cache refresh tuning (local/kÄ±sÄ±tlÄ± ortam iÃ§in dÃ¼ÅŸÃ¼rÃ¼lebilir)

/** IOC list timing: IOC_LIST_TIMING=1 or query ?timing=1 to log searchStringParse, dbConnectionAcquired, dbQuery, countQuery, resultMapping, jsonSerialization, responseSent (ms). */
const IOC_LIST_TIMING = process.env.IOC_LIST_TIMING === '1' || process.env.IOC_LIST_TIMING === 'true';
/** Integrations list timing: INTEGRATIONS_TIMING=1 logs base feed, latest run, queue, and total handler durations (ms). */
const INTEGRATIONS_TIMING = process.env.INTEGRATIONS_TIMING === '1' || process.env.INTEGRATIONS_TIMING === 'true';
const INTEGRATIONS_META_QUERY_TIMEOUT_MS = Math.max(Number(process.env.INTEGRATIONS_META_QUERY_TIMEOUT_MS || 5000), 1000);
/** Hash-only (sha256:/md5:/sha1: no asn/country) uses single SELECT + JS group by default. Set IOC_LIST_USE_CTE_FOR_HASH=1 to force the full CTE path. */
const IOC_LIST_USE_CTE_FOR_HASH = process.env.IOC_LIST_USE_CTE_FOR_HASH === '1' || process.env.IOC_LIST_USE_CTE_FOR_HASH === 'true';

// In-memory cache for IOC stats/summary (status-scoped; invalidated on feed purge).

const IOC_DETAILS_CACHE_TTL_MS = Math.max(Number(process.env.IOC_DETAILS_CACHE_TTL_MS || 15000), 1000);
const iocDetailsCache = new Map();

function invalidateIocDetailsCache(publicId) {
  if (publicId) iocDetailsCache.delete(String(publicId));
}

/** Same observable+source may have duplicate ioc_items rows (e.g. category change on re-import). Prefer MIN(id) for lifecycle display â€” matches IOC list public_id. */
function pickIocLifecycleRow(rows, seedRow) {
  if (!seedRow || !rows?.length) return seedRow;
  const sourceUrl = String(seedRow.source_url ?? '');
  const sameSource = rows.filter(
    (r) => r.source_name === seedRow.source_name && String(r.source_url ?? '') === sourceUrl
  );
  if (sameSource.length <= 1) return seedRow;
  return sameSource.reduce(
    (min, r) => (Number(r.id) < Number(min.id) ? r : min),
    sameSource[0]
  );
}

app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(apiAuthGate);
app.use(csrfProtection);
app.use(rbacHttpPolicy);

let geoCacheRefreshInProgress = false;
let geoCacheDebounceTimer = null;

function parseRedisInfo(raw = '') {
  return raw
    .split('\r\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .reduce((acc, line) => {
      const idx = line.indexOf(':');
      if (idx === -1) return acc;
      const key = line.slice(0, idx);
      const value = line.slice(idx + 1);
      acc[key] = value;
      return acc;
    }, {});
}

function safeTs(v) {
  return String(v || '1970-01-01 00:00:00.000').replace(/'/g, "''");
}

function safeHash(v) {
  const n = String(v == null ? '0' : v).replace(/[^0-9]/g, '');
  return n || '0';
}

function isoFromEpochMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return new Date(n).toISOString();
}

function isValidIpv4(input) {
  const parts = String(input || '').split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function extractIpv4ForGeo(observable, observableType) {
  const raw = String(observable || '').trim();
  const type = String(observableType || '').toLowerCase();
  if (!raw) return null;

  if (type === 'ip') {
    const ip = raw.split('/')[0].trim();
    return isValidIpv4(ip) ? ip : null;
  }

  if (type === 'url') {
    try {
      const u = new URL(raw);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
      const host = u.hostname;
      return isValidIpv4(host) ? host : null;
    } catch {
      return null;
    }
  }

  return null;
}

function parseNoteKeyValues(note) {
  const out = {};
  const raw = String(note || '').trim();
  if (!raw) return out;

  const parts = raw.split('|').map((p) => p.trim()).filter(Boolean);
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const key = part.slice(0, idx).trim().toLowerCase();
    const value = part.slice(idx + 1).trim();
    if (!key || !value) continue;
    out[key] = value;
  }

  return out;
}

/** Squid / explicit HTTP proxy evidence in a raw syslog line (shared list + detail context). */
function rawLooksLikeSquidOrHttpProxy(raw) {
  return /\bsquid[_\s-]?proxy\b|\bTCP_(?:TUNNEL|MISS|HIT|DENIED|REFRESH|MEM_HIT|CLIENT_REFRESH)\/[0-9-]{3}|\bCONNECT\s+[^\s]+:[0-9]+|\bHIER_DIRECT\//i.test(String(raw || ''));
}

function mergeIncidentEventsPageEvidence(pgRow, relEv, bulkHit) {
  const id = Number(pgRow?.id || 0);
  const relRaw = String(relEv?.raw_message_sample || '').trim();
  const bulkRaw = String(bulkHit?.raw_message || '').trim();
  const relSquid = rawLooksLikeSquidOrHttpProxy(relRaw);
  const bulkSquid = rawLooksLikeSquidOrHttpProxy(bulkRaw);
  if (bulkSquid && !relSquid) {
    return {
      match_event_id: id,
      raw_message_sample: bulkRaw,
      parser_source: String(bulkHit?.parser_source || relEv?.parser_source || ''),
      source_type: String(bulkHit?.source_type || relEv?.source_type || ''),
      evidence_lane: 'bulk_squid_over_related'
    };
  }
  if (relRaw) {
    return {
      match_event_id: Number(relEv?.match_event_id || id),
      raw_message_sample: relRaw,
      parser_source: String(relEv?.parser_source || ''),
      source_type: String(relEv?.source_type || ''),
      evidence_lane: 'incident_related_logs'
    };
  }
  if (bulkRaw) {
    return {
      match_event_id: id,
      raw_message_sample: bulkRaw,
      parser_source: String(bulkHit?.parser_source || ''),
      source_type: String(bulkHit?.source_type || ''),
      evidence_lane: 'syslog_logs_bulk'
    };
  }
  return null;
}

async function refreshGeoCache(limit = 20000) {
  if (geoCacheRefreshInProgress) return;
  geoCacheRefreshInProgress = true;
  try {
    const q = `
      WITH missing AS (
        SELECT DISTINCT
          CASE
            WHEN i.observable_type = 'ip'
              AND i.observable ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/\d{1,2})?$'
            THEN i.observable::inet
            ELSE NULL
          END AS ip
        FROM ioc_items i
        LEFT JOIN ioc_ip_geo_cache c
          ON c.ip = CASE
            WHEN i.observable_type = 'ip'
              AND i.observable ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/\d{1,2})?$'
            THEN i.observable::inet
            ELSE NULL
          END
        WHERE i.observable_type = 'ip' AND c.ip IS NULL
        LIMIT $1
      ), with_num AS (
        SELECT
          m.ip,
          ((split_part(host(m.ip::inet), '.', 1)::bigint << 24)
          + (split_part(host(m.ip::inet), '.', 2)::bigint << 16)
          + (split_part(host(m.ip::inet), '.', 3)::bigint << 8)
          +  split_part(host(m.ip::inet), '.', 4)::bigint) AS ip_num
        FROM missing m
        WHERE m.ip IS NOT NULL
      )
      INSERT INTO ioc_ip_geo_cache (ip, country_code, asn, as_name, updated_at)
      SELECT
        w.ip,
        NULLIF(UPPER(TRIM(a.country_code)), '') AS country_code,
        a.asn,
        a.as_name,
        NOW()
      FROM with_num w
      LEFT JOIN LATERAL (
        SELECT r.asn, COALESCE(o.country_code, r.country) AS country_code, r.asn_owner AS as_name
        FROM asn_lookup r
        LEFT JOIN asn_country_overrides o ON o.asn = r.asn
        WHERE w.ip_num BETWEEN r.start_ip_int AND r.end_ip_int
        ORDER BY (r.end_ip_int - r.start_ip_int) ASC
        LIMIT 1
      ) a ON TRUE
      ON CONFLICT (ip)
      DO UPDATE SET
        country_code = EXCLUDED.country_code,
        asn = EXCLUDED.asn,
        as_name = EXCLUDED.as_name,
        updated_at = NOW()
    `;
    await pool.query(q, [limit]);
  } finally {
    geoCacheRefreshInProgress = false;
  }
}

/** Yeni IOC eklendiÄŸinde tek tek aÄŸÄ±r refresh yerine debounce: kÄ±sa sÃ¼re iÃ§inde tek seferde hafif limit ile Ã§alÄ±ÅŸÄ±r. */
function scheduleGeoCacheRefreshAfterAdd() {
  // Threat map removed: geo cache refresh disabled.
}

// schema migrations are handled by migrate.js

app.get('/healthz', (_req, res) => {
  res.json(buildHealthPayload('ok', { process: 'ok' }));
});

app.get('/readyz', async (_req, res) => {
  const result = await runReadinessChecks(pool, redis);
  const payload = buildHealthPayload(result.ok ? 'ok' : 'error', result.checks);
  if (!result.ok) {
    payload.error = result.error;
    return res.status(503).json(payload);
  }
  return res.json(payload);
});

app.get('/health', async (_req, res) => {
  try {
    const result = await runReadinessChecks(pool, redis);
    if (result.ok) {
      return res.json({
        ok: true,
        service: 'backend',
        db: 'up',
        ...buildHealthPayload('ok', result.checks)
      });
    }
    return res.status(500).json({
      ok: false,
      service: 'backend',
      db: result.checks.postgres === 'ok' ? 'up' : 'down',
      ...buildHealthPayload('error', result.checks),
      error: result.error
    });
  } catch {
    res.status(500).json({ ok: false, service: 'backend', db: 'down' });
  }
});

app.get('/api/system/status', async (req, res) => {
  const email = req.user?.email ? String(req.user.email).trim() : '';
  let userTimezone = 'UTC';

  if (email) {
    try {
      const { rows } = await pool.query('SELECT timezone FROM user_preferences WHERE email = $1', [email]);
      const tz = rows[0]?.timezone;
      if (tz) {
        userTimezone = tz;
      }
    } catch (err) {
      console.warn('[system-status] failed to load user timezone', err.message);
    }
  }

  const generatedAt = new Date().toISOString();
  const payload = { generated_at: generatedAt };
  payload.user_timezone = userTimezone;

  const database = { ok: false };
  try {
    const [versionRes, sizeRes, connectionsRes] = await Promise.all([
      pool.query('SELECT version() AS version, current_database() AS database'),
      pool.query('SELECT pg_database_size(current_database())::bigint AS size_bytes'),
      pool.query(
        `SELECT
           COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE state = 'active')::int AS active,
           COUNT(*) FILTER (WHERE state = 'idle')::int AS idle
         FROM pg_stat_activity
         WHERE datname = current_database()`
      )
    ]);

    const sizeBytes = Number(sizeRes.rows[0]?.size_bytes || 0);

    database.ok = true;
    database.version = versionRes.rows[0]?.version || null;
    database.current_database = versionRes.rows[0]?.database || null;
    database.size_bytes = sizeBytes;
    database.size_mb = Number((sizeBytes / (1024 * 1024)).toFixed(2));
    database.connections = {
      total: Number(connectionsRes.rows[0]?.total || 0),
      active: Number(connectionsRes.rows[0]?.active || 0),
      idle: Number(connectionsRes.rows[0]?.idle || 0)
    };
  } catch (err) {
    database.error = err.message;
  }
  payload.database = database;


  const redisInfo = { ok: false };
  try {
    const [pong, infoRaw] = await Promise.all([redis.ping(), redis.info('server')]);
    const info = parseRedisInfo(infoRaw || '');
    redisInfo.ok = pong === 'PONG';
    redisInfo.version = info.redis_version || null;
    redisInfo.mode = info.redis_mode || null;
    redisInfo.uptime_seconds = Number(info.uptime_in_seconds || 0);
    redisInfo.connected_clients = Number(info.connected_clients || 0);
    redisInfo.memory_used_mb = info.used_memory ? Number((Number(info.used_memory) / (1024 * 1024)).toFixed(2)) : null;
  } catch (err) {
    redisInfo.error = err.message;
  }
  payload.redis = redisInfo;

  const queues = {};
  try {
    const integrationCounts = await importQueue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed');
    queues.integration_imports = integrationCounts;
  } catch (err) {
    queues.error = err.message;
  }
  payload.queues = queues;

  let integrations = { active_feeds: 0, total_feeds: 0 };
  try {
    const [feedsRes, lastQueueRes, lastRunRes] = await Promise.all([
      pool.query('SELECT COUNT(*) FILTER (WHERE active = TRUE) AS active_feeds, COUNT(*)::int AS total_feeds FROM integration_feeds'),
      pool.query('SELECT job_id, status, queued_at, started_at, finished_at FROM integration_queue_jobs ORDER BY queued_at DESC LIMIT 1'),
      pool.query('SELECT job_type, status, started_at, finished_at FROM integration_runs ORDER BY started_at DESC LIMIT 1')
    ]);

    integrations = {
      active_feeds: Number(feedsRes.rows[0]?.active_feeds || 0),
      total_feeds: Number(feedsRes.rows[0]?.total_feeds || 0),
      last_queue_job: lastQueueRes.rows[0] || null,
      last_run: lastRunRes.rows[0] || null
    };
  } catch (err) {
    integrations.error = err.message;
  }
  payload.integrations = integrations;

  let mapSnapshot;
  try {
    const [snapshotRes, stateRes] = await Promise.all([
      pool.query(`
        SELECT snapshot_time, total_records, unique_ips, countries
        FROM dashboard_map_display_snapshot
        WHERE singleton = TRUE
        LIMIT 1
      `),
      pool.query(`
        SELECT full_rebuild_pending, last_run_at, snapshot_last_refreshed_at
        FROM dashboard_map_job_state
        WHERE singleton = TRUE
        LIMIT 1
      `)
    ]);
    const snapshot = snapshotRes.rows[0] || null;
    const state = stateRes.rows[0] || null;
    mapSnapshot = {
      total_records: Number(snapshot?.total_records || 0),
      unique_ips: Number(snapshot?.unique_ips || 0),
      snapshot_time: snapshot?.snapshot_time || null,
      full_rebuild_pending: Boolean(state?.full_rebuild_pending),
      last_run_at: state?.last_run_at || null,
      snapshot_last_refreshed_at: state?.snapshot_last_refreshed_at || null
    };
  } catch (err) {
    mapSnapshot = { error: err.message };
  }
  payload.map_snapshot = mapSnapshot;

  let telemetry = {};
  try {
    const [iocTotalRes, iocTodayRes] = await Promise.all([
      pool.query('SELECT COUNT(*)::bigint AS count FROM ioc_items'),
      pool.query(
        `SELECT COUNT(*)::bigint AS count
         FROM ioc_items
         WHERE created_at >= (
           date_trunc('day', NOW() AT TIME ZONE $1)
         ) AT TIME ZONE $1`,
        [userTimezone]
      )
    ]);

    telemetry = {
      ioc_total: Number(iocTotalRes.rows[0]?.count || 0),
      ioc_today: Number(iocTodayRes.rows[0]?.count || 0)
    };
  } catch (err) {
    telemetry = { error: err.message };
  }
  payload.telemetry = telemetry;

  payload.services = { backend: { ok: true } };

  return res.json(payload);
});

const FEED_JOB_TYPE_BY_KEY = {
  'et-blockrules': 'hourly_import',
  'usom-trcert': 'usom_import',
  'urlhaus-abusech': 'urlhaus_import',
  'threatfox-abusech': 'threatfox_import',
  'malwarebazaar-abusech': 'malwarebazaar_import',
  'phishtank-opendnsrr': 'phishtank_import'
};

function integrationsTimingLog(enabled, label, startMs) {
  if (!enabled) return;
  console.log(`[integrations] ${label}: ${Date.now() - startMs}ms`);
}

function wantsIntegrationsQueue(req) {
  const q = req.query || {};
  return Object.prototype.hasOwnProperty.call(q, 'queue_page')
    || Object.prototype.hasOwnProperty.call(q, 'queue_search')
    || Object.prototype.hasOwnProperty.call(q, 'queue_window');
}

function feedJobType(key) {
  return FEED_JOB_TYPE_BY_KEY[key] || key;
}

function metricInt(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function pickMetricsSourceRow(lr, lq) {
  if (!lr && !lq) return null;
  if (!lr) return lq;
  if (!lq) return lr;
  const lrTs = Date.parse(lr.finished_at || lr.started_at || 0) || 0;
  const lqTs = Date.parse(lq.finished_at || lq.started_at || lq.queued_at || 0) || 0;
  return lqTs > lrTs ? lq : lr;
}

function buildLastRunMetrics(row) {
  if (!row) {
    return {
      available: false,
      processed: 0,
      inserted: null,
      updated: null,
      duplicate: null,
      skipped: null,
      suppressed: null,
      failed: null
    };
  }

  // All counter interpretation lives in resolveRunCounters so that every importer's
  // rows — migrated or legacy — are read identically. `unchanged` is canonical;
  // `duplicate` comes back as a deprecated alias of it.
  const counters = resolveRunCounters(row);
  const { processed, inserted, updated, unchanged, skipped, suppressed, failed } = counters;
  const breakdownSum = inserted + updated + unchanged + skipped + suppressed + failed;

  // Pre-migration runs stored only records_processed (legacy inserted count).
  const legacyMissing = processed > 0 && breakdownSum === 0;

  if (legacyMissing) {
    return {
      available: false,
      processed,
      inserted: null,
      updated: null,
      unchanged: null,
      reactivated: null,
      removed: null,
      duplicate: null,
      skipped: null,
      suppressed: null,
      failed: null
    };
  }

  return {
    available: true,
    ...counters
  };
}

function flatMetricsFromLastRun(lastRunMetrics) {
  const m = lastRunMetrics || buildLastRunMetrics(null);
  if (!m.available) {
    return {
      last_records_processed: m.processed,
      last_records_inserted: null,
      last_records_updated: null,
      last_records_unchanged: null,
      last_records_reactivated: null,
      last_records_removed: null,
      last_records_duplicate: null,
      last_records_skipped: null,
      last_records_suppressed: null,
      last_records_failed: null
    };
  }
  return {
    last_records_processed: m.processed,
    last_records_inserted: m.inserted,
    last_records_updated: m.updated,
    last_records_unchanged: m.unchanged,
    last_records_reactivated: m.reactivated,
    last_records_removed: m.removed,
    // DEPRECATED alias of last_records_unchanged.
    last_records_duplicate: m.duplicate,
    last_records_skipped: m.skipped,
    last_records_suppressed: m.suppressed,
    last_records_failed: m.failed
  };
}

function resolveFeedHealthState(feedActive, lastStatus, consecutiveFailures, metricsHints = []) {
  if (feedActive === false) return 'disabled';
  const st = String(lastStatus || '').toLowerCase();
  if (st === 'failed' || st === 'fail') return 'failed';
  if (Array.isArray(metricsHints) && metricsHints.includes('high_failed')) return 'warning';
  if (Number(consecutiveFailures || 0) > 0) return 'warning';
  if (st === 'running' || st === 'queued') return 'warning';
  if (st === 'success') return 'success';
  if (st === 'never') return 'warning';
  return 'warning';
}

function pickRunMetrics(row) {
  const m = buildLastRunMetrics(row);
  return flatMetricsFromLastRun(m);
}

function computeConsecutiveFailures(runs, jobType) {
  const ordered = (runs || [])
    .filter((r) => r.job_type === jobType)
    .sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
  let count = 0;
  for (const run of ordered) {
    if (run.status === 'failed') count += 1;
    else break;
  }
  return count;
}

function buildIntegrationHealthSummary(integrations) {
  const feedRows = (integrations || []).filter((i) => i.key !== 'asn_enrichment');
  const activeFeeds = feedRows.filter((i) => i.active !== false);
  const failingFeeds = feedRows.filter((i) => {
    const st = String(i.status || i.last_status || '').toLowerCase();
    const health = String(i.health_state || '').toLowerCase();
    return st === 'failed' || st === 'fail' || health === 'failed' || health === 'degraded' || Number(i.consecutive_failures || 0) > 0;
  });
  const successfulFeeds24h = feedRows.filter((i) => {
    const finished = i.last_success_at || i.last_finished_at;
    if (!finished) return false;
    const ts = new Date(finished).getTime();
    return Number.isFinite(ts) && ts >= Date.now() - 24 * 60 * 60 * 1000;
  });
  const lastRunInsertedTotal = feedRows.reduce((acc, i) => acc + metricInt(i.last_run_metrics?.inserted ?? i.last_records_inserted), 0);
  const lastRunProcessedTotal = feedRows.reduce((acc, i) => acc + metricInt(i.last_run_metrics?.processed ?? i.last_records_processed), 0);

  return {
    total_feeds: feedRows.length,
    active_feeds: activeFeeds.length,
    enabled_feeds: activeFeeds.length,
    inactive_feeds: feedRows.length - activeFeeds.length,
    failing_feeds: failingFeeds.length,
    successful_feeds_24h: successfulFeeds24h.length,
    last_run_inserted_total: lastRunInsertedTotal,
    last_run_new_total: lastRunInsertedTotal,
    last_run_processed_total: lastRunProcessedTotal
  };
}

function mergeIntegrationListRow(feed, latestRunByJobType, latestQueueByKey, lastSuccessByJobType, consecutiveFailures, asnLastUpdatedAt, expirationByKey, latestPurgeByKey) {
  const jobType = feedJobType(feed.key);
  const lr = latestRunByJobType.get(jobType);
  const lq = latestQueueByKey.get(feed.key);
  const lastSuccess = lastSuccessByJobType.get(jobType);
  const purgeJob = latestPurgeByKey?.get(feed.key);
  const purgeStatusRaw = purgeJob ? String(purgeJob.status || '').toLowerCase() : '';
  const purgeActive = purgeStatusRaw === 'queued' || purgeStatusRaw === 'running';
  const purgeFinishedAt = Date.parse(purgeJob?.finished_at || purgeJob?.started_at || purgeJob?.queued_at || 0) || 0;
  const importSucceededAt = Date.parse(lastSuccess?.finished_at || lastSuccess?.started_at || 0) || 0;
  const completedPurgeIsCurrent = purgeStatusRaw === 'success' && purgeFinishedAt >= importSucceededAt;
  const purgeStatus = purgeStatusRaw === 'queued'
    ? 'queued'
    : purgeStatusRaw === 'running'
      ? 'running'
      : completedPurgeIsCurrent
        ? 'completed'
        : purgeStatusRaw === 'failed'
          ? 'failed'
          : null;
  const purgeStatusLabel = purgeStatus === 'queued'
    ? 'Purge queued'
    : purgeStatus === 'running'
      ? 'Purge running'
      : purgeStatus === 'completed'
        ? 'Purge completed'
        : purgeStatus === 'failed'
          ? 'Purge failed'
          : null;
  const metricsRow = pickMetricsSourceRow(lr, lq);
  const lastRunMetrics = buildLastRunMetrics(metricsRow);
  const runMetrics = flatMetricsFromLastRun(lastRunMetrics);
  const feedActive = feed.active !== false;
  const policyRow = expirationByKey?.get(feed.key);
  const expiration_policy = policyRow ? serializeExpirationPolicy(policyRow, policyRow.feed_id) : null;
  const expiration_summary = formatExpirationSummary(expiration_policy);

  if (feed.key === 'asn_enrichment') {
    return {
      ...feed,
      active: feedActive,
      expiration_policy,
      expiration_summary,
      status: asnLastUpdatedAt ? 'success' : 'never',
      last_status: asnLastUpdatedAt ? 'success' : 'never',
      health_state: feedActive ? (asnLastUpdatedAt ? 'success' : 'warning') : 'disabled',
      last_run_at: asnLastUpdatedAt || null,
      last_started_at: asnLastUpdatedAt || null,
      last_finished_at: null,
      last_success_at: asnLastUpdatedAt || null,
      last_error: null,
      consecutive_failures: 0,
      last_run_metrics: lastRunMetrics,
      ...runMetrics,
      total_records: null
    };
  }

  const lastStatus = lr?.status || lq?.status || 'never';
  const lastError = (lastStatus === 'failed' || lastStatus === 'fail')
    ? (lr?.error_message || lq?.error_message || null)
    : null;
  const consecutive = consecutiveFailures.get(jobType) || 0;
  const metricsHints = buildFeedMetricsHints(lastRunMetrics);

  return {
    ...feed,
    active: feedActive,
    expiration_policy,
    expiration_summary,
    purge_status: purgeStatus,
    purge_status_label: purgeStatusLabel,
    purge_job_id: purgeJob?.job_id || null,
    purge_active: purgeActive,
    status: lastStatus,
    last_status: lastStatus,
    health_state: resolveFeedHealthState(feedActive, lastStatus, consecutive, metricsHints),
    last_run_at: lr?.finished_at || lr?.started_at || lq?.finished_at || lq?.started_at || lq?.queued_at || null,
    last_started_at: lr?.started_at || lq?.started_at || lq?.queued_at || null,
    last_finished_at: lr?.finished_at || lq?.finished_at || null,
    last_success_at: lastSuccess?.finished_at || lastSuccess?.started_at || (lastStatus === 'success' ? (lr?.finished_at || lr?.started_at || null) : null),
    last_error: lastError,
    consecutive_failures: consecutive,
    last_run_metrics: lastRunMetrics,
    last_run_details: lr?.run_details || null,
    metrics_hints: metricsHints,
    ...runMetrics,
    total_records: runMetrics.last_records_processed
  };
}

function mergeUsomReconciliationFields(feed, latestByMode, lastSuccessByMode, now = new Date()) {
  if (feed.key !== 'usom-trcert') return feed;
  const latestIncremental = latestByMode.get(USOM_INCREMENTAL_MODE) || null;
  const latestFull = latestByMode.get(USOM_FULL_RECONCILIATION_MODE) || null;
  const successfulIncremental = lastSuccessByMode.get(USOM_INCREMENTAL_MODE) || null;
  const successfulFull = lastSuccessByMode.get(USOM_FULL_RECONCILIATION_MODE) || null;
  const reconciliation = buildUsomReconciliationHealth({
    latestFullRun: latestFull,
    lastSuccessfulFullRun: successfulFull,
    now,
    warningDays: Number(process.env.USOM_FULL_RECONCILIATION_MAX_AGE_DAYS || 8),
    degradedDays: Math.max(
      14,
      Number(process.env.USOM_FULL_RECONCILIATION_MAX_AGE_DAYS || 8) + 1
    )
  });
  const baseHealth = String(feed.health_state || 'warning');
  const effectiveHealth = reconciliation.state === 'degraded'
    ? 'degraded'
    : reconciliation.state === 'warning' && baseHealth === 'success'
      ? 'warning'
      : baseHealth;
  const latestModeRun = [latestIncremental, latestFull]
    .filter(Boolean)
    .sort((a, b) => Date.parse(b.finished_at || b.started_at || 0) - Date.parse(a.finished_at || a.started_at || 0))[0] || null;

  return {
    ...feed,
    health_state: feed.active === false ? 'disabled' : effectiveHealth,
    reconciliation_health_state: reconciliation.state,
    reconciliation_warning: reconciliation.warning,
    full_reconciliation_age_days: reconciliation.age_days,
    last_incremental_run: latestIncremental,
    last_incremental_success_at: successfulIncremental?.finished_at || successfulIncremental?.started_at || null,
    last_full_reconciliation_run: latestFull,
    last_full_reconciliation_success_at: successfulFull?.finished_at || successfulFull?.started_at || null,
    last_run_mode: inferUsomRunMode(latestModeRun || {}),
    last_run_details: feed.last_run_details || latestFull?.run_details || latestIncremental?.run_details || null,
    last_error: latestFull && ['failed', 'fail'].includes(String(latestFull.status || '').toLowerCase())
      ? latestFull.error_message
      : feed.last_error
  };
}

async function queryIntegrationsMetaWithTimeout(queryPromise, fallbackRows = []) {
  try {
    const res = await Promise.race([
      queryPromise,
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error('integrations meta query timeout')), INTEGRATIONS_META_QUERY_TIMEOUT_MS);
      })
    ]);
    return res;
  } catch {
    return { rows: fallbackRows };
  }
}

app.get('/api/integrations', async (req, res) => {
  const handlerStart = Date.now();
  const timingEnabled = INTEGRATIONS_TIMING || req.query?.timing === '1';

  try {
    const queuePage = Math.max(Number(req.query?.queue_page || 1) || 1, 1);
    const requestedSize = Number(req.query?.queue_page_size || 25) || 25;
    const queuePageSize = Math.min(Math.max(requestedSize, 1), 50);
    const queueOffset = (queuePage - 1) * queuePageSize;
    const queueSearch = String(req.query?.queue_search || '').trim();
    const queueWindow = String(req.query?.queue_window || '24h').trim();
    const queueWindowSql = queueWindow === '7d' ? "NOW() - INTERVAL '7 days'" : "NOW() - INTERVAL '24 hours'";
    const loadQueue = wantsIntegrationsQueue(req);

    const includeArchived = String(req.query?.include_archived || '').trim() === '1';

    const feedsQ = `
      SELECT
        f.key,
        f.integration_id,
        f.name,
        f.source_url,
        f.schedule_cron AS schedule,
        f.trust_level,
        f.active,
        f.feed_kind,
        f.archived_at,
        f.default_confidence,
        f.credentials,
        f.created_at
      FROM integration_feeds f
      WHERE ($1::boolean OR f.archived_at IS NULL)
        AND COALESCE(f.feed_kind, 'built_in') <> 'custom'
      ORDER BY f.archived_at NULLS FIRST, f.active DESC, f.created_at ASC, f.name ASC
    `;

    const recentQ = `
      SELECT
        q.job_id,
        q.integration_key,
        COALESCE(
          f.name,
          CASE WHEN q.integration_key = 'unknown' AND q.job_name = 'phishtank-import' THEN 'PhishTank online-valid' END,
          q.integration_key
        ) AS integration_name,
        q.job_name AS name,
        q.status AS state,
        COALESCE(q.started_at, q.queued_at) AS timestamp,
        q.error_message AS failed_reason,
        q.records_processed,
        q.started_at,
        q.finished_at,
        q.triggered_by,
        CASE
          WHEN q.integration_key = 'usom-trcert' AND COALESCE(q.triggered_by, '') LIKE '%full_reconciliation%'
            THEN 'full_reconciliation'
          WHEN q.integration_key = 'usom-trcert' THEN 'incremental'
          ELSE NULL
        END AS run_mode
      FROM integration_queue_jobs q
      LEFT JOIN integration_feeds f ON f.key = q.integration_key
      ORDER BY q.queued_at DESC
      LIMIT 20
    `;

    const baseStart = Date.now();
    const expirationPoliciesQ = `
      SELECT
        f.key AS feed_key,
        f.integration_id AS feed_id,
        p.enabled,
        p.expiration_mode,
        p.ttl_days,
        p.grace_days,
        p.observable_type,
        p.updated_at
      FROM integration_feeds f
      LEFT JOIN threat_feed_expiration_policies p
        ON p.feed_id = f.integration_id AND p.observable_type = 'all'
    `;
    const [feedsRes, repeatableNextByKey, expirationPoliciesRes] = await Promise.all([
      pool.query(feedsQ, [includeArchived]),
      importQueue.getRepeatableJobs()
        .then((rows) => buildRepeatableNextRunMap(rows))
        .catch(() => new Map()),
      pool.query(expirationPoliciesQ)
    ]);
    const expirationByKey = new Map(
      (expirationPoliciesRes.rows || []).map((row) => [String(row.feed_key || '').trim(), row])
    );
    const now = new Date();
    const usomFullSchedule = getUsomFullReconciliationScheduleConfig();
    const activeFeeds = feedsRes.rows.filter((feed) => feed.active !== false);
    const slotMap = buildHourlySlotMap(activeFeeds.map((feed) => ({ key: feed.key, schedule: feed.schedule })));
    feedsRes.rows = feedsRes.rows.map((feed) => {
      const { credentials, ...rest } = feed;
      const credentialsSummary = AUTH_KEY_FEED_KEYS.has(feed.key)
        ? formatFeedCredentialsSummary(feed.key, credentials)
        : null;
      const base = { ...rest, credentials_summary: credentialsSummary, feed_kind: feed.feed_kind || 'built_in' };
      if (feed.archived_at) {
        return { ...base, next_run_at: null, next_incremental_run_at: null, next_full_reconciliation_run_at: null };
      }
      if (feed.active === false) {
        return { ...base, next_run_at: null, next_incremental_run_at: null, next_full_reconciliation_run_at: null };
      }
      const bullNext = repeatableNextByKey.get(`${feed.key}::${USOM_INCREMENTAL_MODE}`) || repeatableNextByKey.get(feed.key);
      const computedNext = computeNextRunAt(feed.schedule, feed.key, now, slotMap);
      const nextRunAt = isRunOnceSchedule(feed.schedule) ? null : (bullNext || computedNext);
      const fullBullNext = feed.key === 'usom-trcert'
        ? repeatableNextByKey.get(`${feed.key}::${USOM_FULL_RECONCILIATION_MODE}`)
        : null;
      const fullComputedNext = feed.key === 'usom-trcert' && usomFullSchedule.enabled
        ? computeNextWeeklyRunAt(usomFullSchedule.cron, now, usomFullSchedule.timezone)
        : null;
      const nextFull = fullBullNext || fullComputedNext;
      return {
        ...base,
        next_run_at: nextRunAt ? nextRunAt.toISOString() : null,
        next_incremental_run_at: nextRunAt ? nextRunAt.toISOString() : null,
        next_full_reconciliation_run_at: nextFull ? nextFull.toISOString() : null,
        full_reconciliation_schedule: feed.key === 'usom-trcert'
          ? {
              enabled: usomFullSchedule.enabled,
              cron: usomFullSchedule.cron,
              timezone: usomFullSchedule.timezone
            }
          : null
      };
    });
    integrationsTimingLog(timingEnabled, 'integration base query', baseStart);

    const feedKeys = feedsRes.rows.map((r) => r.key);
    const jobTypes = [...new Set(feedKeys.map((key) => feedJobType(key)))];

    const latestRunsQ = `
      SELECT DISTINCT ON (job_type)
        job_type, status, started_at, finished_at,
        records_processed, records_inserted, records_updated,
        records_duplicate, records_unchanged, records_reactivated, records_removed,
        records_skipped, records_suppressed, records_failed,
        error_message, run_details, triggered_by
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
      ORDER BY job_type, started_at DESC
    `;

    const lastSuccessRunsQ = `
      SELECT DISTINCT ON (job_type)
        job_type, status, started_at, finished_at
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
        AND status = 'success'
      ORDER BY job_type, started_at DESC
    `;

    const usomRunsByModeQ = `
      SELECT DISTINCT ON (effective_run_mode)
        job_type, status, started_at, finished_at,
        records_processed, records_inserted, records_updated,
        records_duplicate, records_unchanged, records_reactivated, records_removed,
        records_skipped, records_suppressed, records_failed,
        error_message, run_details, triggered_by, effective_run_mode AS run_mode
      FROM (
        SELECT r.*,
          COALESCE(
            NULLIF(r.run_mode, ''),
            CASE
              WHEN COALESCE(r.run_details->>'run_mode', '') = 'full_reconciliation'
                OR COALESCE(r.triggered_by, '') LIKE '%full_reconciliation%'
                THEN 'full_reconciliation'
              ELSE 'incremental'
            END
          ) AS effective_run_mode
        FROM integration_runs r
        WHERE r.job_type = 'usom_import'
      ) mode_runs
      ORDER BY effective_run_mode, started_at DESC
    `;

    const usomSuccessRunsByModeQ = `
      SELECT DISTINCT ON (effective_run_mode)
        job_type, status, started_at, finished_at, error_message, run_details, triggered_by,
        effective_run_mode AS run_mode
      FROM (
        SELECT r.*,
          COALESCE(
            NULLIF(r.run_mode, ''),
            CASE
              WHEN COALESCE(r.run_details->>'run_mode', '') = 'full_reconciliation'
                OR COALESCE(r.triggered_by, '') LIKE '%full_reconciliation%'
                THEN 'full_reconciliation'
              ELSE 'incremental'
            END
          ) AS effective_run_mode
        FROM integration_runs r
        WHERE r.job_type = 'usom_import'
          AND r.status = 'success'
          AND COALESCE(r.run_details->>'reconciliation_complete', 'true') <> 'false'
      ) mode_runs
      ORDER BY effective_run_mode, started_at DESC
    `;

    const recentFailuresQ = `
      SELECT job_type, status, started_at
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
      ORDER BY job_type, started_at DESC
      LIMIT 300
    `;

    const latestQueueQ = `
      SELECT DISTINCT ON (integration_key_norm)
        integration_key_norm AS integration_key,
        status, started_at, queued_at, finished_at,
        records_processed, records_inserted, records_updated,
        records_duplicate, records_unchanged, records_reactivated, records_removed,
        records_skipped, records_suppressed, records_failed,
        error_message
      FROM (
        SELECT
          CASE
            WHEN integration_key = 'unknown' AND job_name = 'phishtank-import' THEN 'phishtank-opendnsrr'
            ELSE integration_key
          END AS integration_key_norm,
          status, started_at, queued_at, finished_at,
          records_processed, records_inserted, records_updated,
          records_duplicate, records_unchanged, records_reactivated, records_removed,
        records_skipped, records_suppressed, records_failed,
          error_message
        FROM integration_queue_jobs
        WHERE integration_key = ANY($1::text[])
           OR (integration_key = 'unknown' AND job_name = 'phishtank-import')
      ) qn
      ORDER BY integration_key_norm, COALESCE(started_at, queued_at) DESC
    `;

    const asnQ = `SELECT MAX(updated_at) AS last_updated_at FROM asn_lookup`;

    const latestPurgeQ = `
      SELECT DISTINCT ON (integration_key)
        integration_key, job_id, status, queued_at, started_at, finished_at, error_message, records_processed
      FROM integration_queue_jobs
      WHERE job_name = 'feed_data_purge'
        AND integration_key = ANY($1::text[])
      ORDER BY integration_key, COALESCE(started_at, queued_at) DESC
    `;

    const latestRunStart = Date.now();
    const [latestRunsRes, lastSuccessRunsRes, recentFailuresRes, latestQueueRes, latestPurgeRes, asnRes, recentRes, usomRunsByModeRes, usomSuccessRunsByModeRes] = await Promise.all([
      jobTypes.length
        ? queryIntegrationsMetaWithTimeout(pool.query(latestRunsQ, [jobTypes]))
        : Promise.resolve({ rows: [] }),
      jobTypes.length
        ? queryIntegrationsMetaWithTimeout(pool.query(lastSuccessRunsQ, [jobTypes]))
        : Promise.resolve({ rows: [] }),
      jobTypes.length
        ? queryIntegrationsMetaWithTimeout(pool.query(recentFailuresQ, [jobTypes]))
        : Promise.resolve({ rows: [] }),
      feedKeys.length
        ? queryIntegrationsMetaWithTimeout(pool.query(latestQueueQ, [feedKeys]))
        : Promise.resolve({ rows: [] }),
      feedKeys.length
        ? queryIntegrationsMetaWithTimeout(pool.query(latestPurgeQ, [feedKeys]))
        : Promise.resolve({ rows: [] }),
      feedKeys.includes('asn_enrichment')
        ? queryIntegrationsMetaWithTimeout(pool.query(asnQ))
        : Promise.resolve({ rows: [{ last_updated_at: null }] }),
      pool.query(recentQ),
      feedKeys.includes('usom-trcert')
        ? queryIntegrationsMetaWithTimeout(pool.query(usomRunsByModeQ))
        : Promise.resolve({ rows: [] }),
      feedKeys.includes('usom-trcert')
        ? queryIntegrationsMetaWithTimeout(pool.query(usomSuccessRunsByModeQ))
        : Promise.resolve({ rows: [] })
    ]);
    integrationsTimingLog(timingEnabled, 'latest run query', latestRunStart);

    const latestRunByJobType = new Map(latestRunsRes.rows.map((r) => [r.job_type, r]));
    const lastSuccessByJobType = new Map(lastSuccessRunsRes.rows.map((r) => [r.job_type, r]));
    const consecutiveFailures = new Map(
      jobTypes.map((jt) => [jt, computeConsecutiveFailures(recentFailuresRes.rows, jt)])
    );
    const latestQueueByKey = new Map(latestQueueRes.rows.map((r) => [r.integration_key, r]));
    const latestPurgeByKey = new Map(latestPurgeRes.rows.map((r) => [r.integration_key, r]));
    const latestUsomByMode = new Map(usomRunsByModeRes.rows.map((r) => [r.run_mode, r]));
    const lastSuccessfulUsomByMode = new Map(usomSuccessRunsByModeRes.rows.map((r) => [r.run_mode, r]));
    const asnLastUpdatedAt = asnRes.rows[0]?.last_updated_at || null;

    const integrations = feedsRes.rows.map((feed) => mergeUsomReconciliationFields(
      mergeIntegrationListRow(feed, latestRunByJobType, latestQueueByKey, lastSuccessByJobType, consecutiveFailures, asnLastUpdatedAt, expirationByKey, latestPurgeByKey),
      latestUsomByMode,
      lastSuccessfulUsomByMode,
      now
    ));
    const healthSummary = buildIntegrationHealthSummary(integrations);

    let queue = {
      counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 },
      jobs: []
    };

    if (loadQueue) {
    const queueStart = Date.now();
    try {
      const searchParams = [];
      let searchWhere = '';
      if (queueSearch) {
        searchParams.push(`%${queueSearch}%`);
        searchWhere = `
          AND (
            q.job_id ILIKE $1
            OR q.integration_key ILIKE $1
            OR q.job_name ILIKE $1
            OR q.status ILIKE $1
            OR COALESCE(q.error_message, '') ILIKE $1
            OR COALESCE(f.name, q.integration_key) ILIKE $1
          )
        `;
      }

      const countSql = `
        SELECT status, COUNT(*)::int AS cnt
        FROM integration_queue_jobs
        WHERE queued_at >= ${queueWindowSql}
        GROUP BY status
      `;

      const totalSql = `
        SELECT COUNT(*)::int AS total
        FROM integration_queue_jobs q
        LEFT JOIN integration_feeds f ON f.key = q.integration_key
        WHERE q.queued_at >= ${queueWindowSql}
        ${searchWhere}
      `;

      const jobsSql = `
        SELECT
          q.job_id AS id,
          q.integration_key,
          COALESCE(
            f.name,
            CASE WHEN q.integration_key = 'unknown' AND q.job_name = 'phishtank-import' THEN 'PhishTank online-valid' END,
            q.integration_key
          ) AS integration_name,
          f.integration_id,
          q.job_name AS name,
          q.status AS state,
          COALESCE(q.started_at, q.queued_at) AS timestamp,
          q.error_message AS failed_reason,
          q.records_processed,
          q.started_at,
          q.finished_at
        FROM integration_queue_jobs q
        LEFT JOIN integration_feeds f ON f.key = q.integration_key
        WHERE q.queued_at >= ${queueWindowSql}
        ${searchWhere}
        ORDER BY q.queued_at DESC
        LIMIT $${searchParams.length + 1}
        OFFSET $${searchParams.length + 2}
      `;

      const [countRows, totalRows, jobsRows] = await Promise.all([
        pool.query(countSql),
        pool.query(totalSql, searchParams),
        pool.query(jobsSql, [...searchParams, queuePageSize, queueOffset])
      ]);

      const mapped = { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 };
      for (const r of countRows.rows) {
        if (r.status === 'queued') mapped.waiting += r.cnt;
        else if (r.status === 'running') mapped.active += r.cnt;
        else if (r.status === 'failed') mapped.failed += r.cnt;
        else if (r.status === 'success') mapped.completed += r.cnt;
      }

      const total = Number(totalRows.rows[0]?.total || 0);
      queue = {
        counts: mapped,
        jobs: jobsRows.rows.map(withIntegrationJobDisplayName),
        pagination: {
          page: queuePage,
          page_size: queuePageSize,
          total,
          total_pages: Math.max(1, Math.ceil(total / queuePageSize))
        },
        filters: {
          search: queueSearch,
          window: queueWindow
        }
      };
    } catch {
      // queue telemetry optional
    }
    integrationsTimingLog(timingEnabled, 'queue query', queueStart);

    try {
      const snapshot = await loadIntegrationQueueHealthSnapshot(pool, importQueue);
      const lastFailedQ = await pool.query(
        `SELECT error_message, integration_key, finished_at
         FROM integration_queue_jobs
         WHERE status = 'failed' AND error_message IS NOT NULL
         ORDER BY COALESCE(finished_at, queued_at) DESC
         LIMIT 1`
      );
      const lastFailed = lastFailedQ.rows[0] || null;
      queue = {
        ...queue,
        queue_health: snapshot.health,
        bull_counts: snapshot.bull_counts,
        db_counts: snapshot.db_counts,
        source_locks: snapshot.source_locks,
        oldest_waiting_age_seconds: snapshot.oldest_waiting_age_seconds,
        worker_count: snapshot.worker_count,
        last_failure_reason: lastFailed?.error_message || null,
        last_failure_at: lastFailed?.finished_at || null,
        last_failure_integration_key: lastFailed?.integration_key || null
      };
    } catch (err) {
      console.warn('[integrations] queue health snapshot failed', err.message);
    }
    }

    integrationsTimingLog(timingEnabled, 'endpoint total', handlerStart);

    return res.json({
      integrations,
      health_summary: healthSummary,
      schedule_reference_timezone: getSystemScheduleTimezone(),
      recent_runs: recentRes.rows.map(withIntegrationJobDisplayName),
      queue
    });
  } catch (err) {
    integrationsTimingLog(timingEnabled, 'endpoint total (error)', handlerStart);
    return res.status(500).json({ message: 'Failed to fetch integrations', detail: err.message });
  }
});

const INTEGRATION_JOBS = {
  'et-blockrules': 'hourly-import',
  'usom-trcert': 'usom-import',
  'urlhaus-abusech': 'urlhaus-import',
  'threatfox-abusech': 'threatfox-import',
  'malwarebazaar-abusech': 'malwarebazaar-import',
  'phishtank-opendnsrr': 'phishtank-import',
  'alienvault-otx': 'alienvault-otx-import'
};

const TRUST_LEVELS = new Set(['guvenilir', 'orta', 'not_categorized']);
const SCHEDULE_CRONS = new Set(['*/5 * * * *', '*/15 * * * *', '*/30 * * * *', '0 * * * *', '0 0 * * *', 'run_once']);

async function loadActiveIntegrationFeedKeys() {
  const q = await pool.query(
    `SELECT key FROM integration_feeds
     WHERE active = TRUE
       AND archived_at IS NULL
       AND schedule_cron <> 'run_once'
       AND key = ANY($1::text[])`,
    [Object.keys(INTEGRATION_JOBS)]
  );
  return q.rows.map((row) => String(row.key));
}

function integrationFeedActor(req) {
  const userId = req.user?.publicId && /^[0-9a-f-]{36}$/i.test(req.user.publicId)
    ? req.user.publicId
    : null;
  return {
    userId,
    username: req.user?.username || req.user?.email || 'unknown',
    actor_type: 'user',
    source: 'api'
  };
}

async function assertIntegrationFeedActive(key) {
  const q = await pool.query(
    'SELECT active, archived_at FROM integration_feeds WHERE key = $1 LIMIT 1',
    [key]
  );
  if (!q.rowCount) return { ok: false, status: 404, message: 'Integration not found' };
  if (q.rows[0].archived_at) {
    return { ok: false, status: 409, message: 'Feed is archived. Restore it before running.' };
  }
  if (!q.rows[0].active) {
    return { ok: false, status: 409, message: 'Feed is disabled. Enable it before running.' };
  }
  return { ok: true };
}

async function loadActiveUsomQueueRows() {
  const [result, activeBullJobs, delayedBullJobs] = await Promise.all([
    pool.query(
      `SELECT job_id, status, triggered_by, queued_at, started_at
       FROM integration_queue_jobs
       WHERE integration_key = 'usom-trcert'
         AND status IN ('queued', 'running')
       ORDER BY COALESCE(started_at, queued_at) ASC`
    ),
    importQueue.getJobs(['waiting', 'active'])
      .catch(() => []),
    importQueue.getJobs(['delayed'])
      .catch(() => [])
  ]);
  const bullJobs = [
    ...(activeBullJobs || []),
    ...(delayedBullJobs || []).filter((job) => !isScheduledRepeatIteration(job))
  ];
  const rows = [...(result.rows || [])];
  const knownIds = new Set(rows.map((row) => String(row.job_id)));
  for (const job of bullJobs || []) {
    if (String(job?.data?.integration_key || '') !== 'usom-trcert') continue;
    if (knownIds.has(String(job.id))) continue;
    rows.push({
      job_id: String(job.id),
      status: 'queued',
      run_mode: job.data?.run_mode,
      triggered_by: job.data?.triggeredBy
    });
  }
  return rows;
}

async function enqueueUsomRun(mode, triggeredBy) {
  const decision = decideUsomEnqueue(mode, await loadActiveUsomQueueRows());
  if (decision.action === 'coalesce') {
    return {
      ok: true,
      queued: false,
      coalesced: true,
      run_mode: mode,
      job_id: decision.existing.job_id,
      reason: decision.reason
    };
  }
  if (decision.action === 'suppress') {
    return {
      ok: false,
      status: 409,
      message: `Incremental run suppressed because full reconciliation job ${decision.existing.job_id} is queued or running.`,
      blocking_job_id: decision.existing.job_id,
      run_mode: mode
    };
  }

  const jobName = INTEGRATION_JOBS['usom-trcert'];
  const trigger = `${triggeredBy}:${mode}`;
  const job = await importQueue.add(
    jobName,
    { triggeredBy: trigger, integration_key: 'usom-trcert', run_mode: mode },
    { priority: MANUAL_JOB_PRIORITY }
  );
  await pool.query(
    `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
     VALUES ($1, 'usom-trcert', $2, 'queued', $3, NOW(), NOW())
     ON CONFLICT (job_id)
     DO UPDATE SET status='queued', triggered_by=$3, updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL`,
    [String(job.id), jobName, trigger]
  );
  return { ok: true, queued: true, coalesced: false, run_mode: mode, job_id: job.id };
}

app.post('/api/integrations/queue/recover', requireRole(ROLES.ADMIN), async (req, res) => {
  const dryRun = String(req.query?.dry_run || req.query?.dryRun || '').toLowerCase() === 'true';
  try {
    const preview = dryRun
      ? await loadIntegrationQueueHealthSnapshot(pool, importQueue)
      : null;
    if (dryRun) {
      return res.json({
        dry_run: true,
        queue_health: preview?.health || null,
        dry_run_reconcile: preview?.dry_run_reconcile || null,
        dry_run_locks: preview?.dry_run_locks || null,
        stale_queued_jobs: preview?.stale_queued_jobs || [],
        stale_queued_count: preview?.stale_queued_count || 0,
        recovery_needed: Boolean(preview?.health?.recovery_needed)
      });
    }

    const result = await runIntegrationQueueRecover(pool, importQueue, { dryRun: false });
    if (!result.reconciled_count && !(result.actions_taken || []).length) {
      return res.json({
        ok: true,
        message: 'No recovery actions were required',
        ...result
      });
    }

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.INTEGRATION_QUEUE_RECOVERY,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: 'integration-imports',
      entityDisplay: queueName,
      severity: AUDIT_SEVERITY.WARNING,
      metadata: {
        reconciled_count: result.reconciled_count,
        actions_taken: result.actions_taken,
        stale_active_jobs: (result.stale_active_jobs || []).map((j) => j.job_id),
        stale_stalled_jobs: (result.stale_stalled_jobs || []).map((j) => j.job_id)
      }
    });

    return res.json({ ok: true, ...result });
  } catch (err) {
    await auditLogService.auditFailure({
      req,
      action: AUDIT_ACTION.INTEGRATION_QUEUE_RECOVERY,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: 'integration-imports',
      entityDisplay: queueName,
      severity: AUDIT_SEVERITY.CRITICAL,
      metadata: { dry_run: dryRun, error: err?.message || String(err) }
    }).catch(() => {});
    return res.status(500).json({ message: 'Queue recovery failed', detail: err.message });
  }
});

app.post('/api/integrations/run-now', async (_req, res) => {
  try {
    const keys = await loadActiveIntegrationFeedKeys();
    const queued = [];
    const skipped = [];

    for (const key of keys) {
      if (key === 'usom-trcert') {
        const result = await enqueueUsomRun(USOM_INCREMENTAL_MODE, 'manual-ui-all');
        if (!result.ok || result.coalesced) {
          skipped.push({
            key,
            blocking_job_id: result.blocking_job_id || result.job_id,
            reason: result.coalesced ? 'duplicate_incremental' : 'full_reconciliation_active'
          });
        } else {
          queued.push({ key, job_id: result.job_id, run_mode: result.run_mode });
        }
        continue;
      }
      const blocking = await findActiveRunningJobForSource(pool, key);
      if (blocking) {
        skipped.push({ key, blocking_job_id: blocking.job_id, reason: 'running' });
        continue;
      }

      const job = await importQueue.add(
        INTEGRATION_JOBS[key],
        { triggeredBy: 'manual-ui-all', integration_key: key },
        { priority: MANUAL_JOB_PRIORITY }
      );
      await pool.query(
        `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
         VALUES ($1, $2, $3, 'queued', 'manual-ui-all', NOW(), NOW())
         ON CONFLICT (job_id)
         DO UPDATE SET status='queued', triggered_by='manual-ui-all', updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL`,
        [String(job.id), key, INTEGRATION_JOBS[key]]
      );
      queued.push({ key, job_id: job.id });
    }

    return res.status(202).json({
      ok: true,
      queued: true,
      count: queued.length,
      job_ids: queued.map((entry) => entry.job_id),
      skipped
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to queue integrations', detail: err.message });
  }
});

app.post('/api/integrations/:key/run-now', async (req, res) => {
  const { key } = req.params;
  const jobName = INTEGRATION_JOBS[key];
  if (!jobName) {
    return res.status(404).json({ message: 'Integration not found' });
  }

  try {
    const modeResult = resolveManualIntegrationRunMode(key, req.body?.run_mode);
    if (!modeResult.ok) {
      return res.status(modeResult.status).json({ message: modeResult.message });
    }
    const runMode = modeResult.runMode;

    const activeCheck = await assertIntegrationFeedActive(key);
    if (!activeCheck.ok) {
      return res.status(activeCheck.status).json({ message: activeCheck.message });
    }

    if (key === 'usom-trcert') {
      const result = await enqueueUsomRun(runMode, 'manual-ui-one');
      if (!result.ok) {
        return res.status(result.status || 409).json(result);
      }
      return res.status(202).json({ ...result, key });
    }

    const blocking = await findActiveRunningJobForSource(pool, key);
    if (blocking) {
      return res.status(409).json({
        message: `A run is already in progress for this feed (job ${blocking.job_id}). Wait for it to finish or recover stale jobs.`,
        blocking_job_id: blocking.job_id,
        integration_key: key
      });
    }

    const job = await importQueue.add(
      jobName,
      { triggeredBy: 'manual-ui-one', integration_key: key },
      { priority: MANUAL_JOB_PRIORITY }
    );
    await pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
       VALUES ($1, $2, $3, 'queued', 'manual-ui-one', NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='queued', triggered_by='manual-ui-one', updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL`,
      [String(job.id), key, jobName]
    );
    return res.status(202).json({ ok: true, queued: true, key, job_id: job.id });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to queue integration run', detail: err.message });
  }
});

app.patch('/api/integrations/:key/active', async (req, res) => {
  const { key } = req.params;
  if (!assertCustomFeedSettingsAllowed(req, key, res)) return;
  if (typeof req.body?.active !== 'boolean') {
    return res.status(400).json({ message: 'active must be a boolean' });
  }

  try {
    const prevQ = await pool.query(
      'SELECT key, integration_id, name, active, archived_at FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!prevQ.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }
    if (prevQ.rows[0].archived_at) {
      return res.status(409).json({ message: 'Archived feeds cannot be enabled or disabled. Restore the feed first.' });
    }

    const prev = prevQ.rows[0];
    const result = await pool.query(
      `UPDATE integration_feeds
       SET active = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, integration_id, name, active, schedule_cron AS schedule, trust_level, source_url, updated_at`,
      [key, req.body.active]
    );

    const after = result.rows[0];

    const { AUDIT_ACTION, AUDIT_ENTITY } = await import('./lib/auditConstants.js');
    const action = after.active
      ? AUDIT_ACTION.INTEGRATION_ENABLED
      : AUDIT_ACTION.INTEGRATION_DISABLED;

    await auditLogService.auditSuccess({
      req,
      action,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(after.integration_id || key),
      entityDisplay: after.name,
      before: { active: Boolean(prev.active) },
      after: { active: Boolean(after.active) },
      metadata: {
        feed_key: after.key,
        feed_name: after.name,
        source: 'ui'
      }
    }).catch((e) => {
      console.warn('[audit] integration active toggle log failed', e?.message || e);
    });

    try {
      await syncSingleFeedSchedule(pool, importQueue, key, { logPrefix: '[integrations]' });
    } catch (syncErr) {
      console.warn('[integrations] active state saved but schedule sync failed', syncErr?.message || syncErr);
    }

    return res.json(after);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update integration active state', detail: err.message });
  }
});

app.get('/api/integrations/:key/purge-preview', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  const { key } = req.params;
  try {
    const previewResult = await previewFeedDataPurge(pool, key);
    if (!previewResult.ok) {
      return res.status(previewResult.status || 400).json({ message: previewResult.message || 'Preview failed' });
    }
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.FEED_DATA_PURGE_PREVIEW,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(previewResult.preview.feed_id || key),
      entityDisplay: previewResult.preview.feed_name || key,
      metadata: previewResult.preview
    }).catch(() => {});
    return res.json(previewResult.preview);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to preview feed purge', detail: err.message });
  }
});

app.post('/api/integrations/:key/purge', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  const { key } = req.params;
  const confirmName = String(req.body?.confirm_name || '').trim();
  try {
    const feedRow = await pool.query(
      'SELECT key, integration_id, name, archived_at FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!feedRow.rowCount) return res.status(404).json({ message: 'Integration not found' });
    const feed = feedRow.rows[0];
    if (!validatePurgeConfirmName(feed.name, confirmName)) {
      return res.status(400).json({
        error: 'confirm_name_mismatch',
        message: 'Feed name confirmation does not match.'
      });
    }
    if (feed.archived_at) {
      return res.status(409).json({ message: 'Archived feeds cannot be purged.' });
    }

    const activePurge = await findActivePurgeJobForFeed(pool, key);
    if (activePurge) {
      return res.status(409).json({
        error: 'purge_already_running',
        message: 'A purge job is already running for this feed.',
        job_id: activePurge.job_id
      });
    }

    const previewResult = await previewFeedDataPurge(pool, key);
    if (!previewResult.ok) {
      return res.status(previewResult.status || 400).json({ message: previewResult.message || 'Preview failed' });
    }

    const actor = integrationFeedActor(req);
    const job = await importQueue.add(
      FEED_PURGE_JOB_NAME,
      {
        triggeredBy: 'feed-purge-api',
        integration_key: key,
        feed_id: feed.integration_id,
        feed_key: key,
        feed_name: feed.name,
        requested_by: actor.username,
        requested_by_user_id: actor.userId,
        reason: String(req.body?.reason || 'manual purge from feed edit').trim() || 'manual purge from feed edit',
        confirm_name: confirmName
      },
      { priority: MANUAL_JOB_PRIORITY }
    );

    await pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
       VALUES ($1, $2, $3, 'queued', $4, NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='queued', triggered_by=$4, updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL`,
      [String(job.id), key, FEED_PURGE_JOB_NAME, actor.username || 'feed-purge-api']
    );

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.FEED_DATA_PURGE_REQUESTED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(feed.integration_id || key),
      entityDisplay: feed.name || key,
      severity: AUDIT_SEVERITY.WARNING,
      metadata: {
        feed_id: feed.integration_id,
        feed_name: feed.name,
        feed_key: key,
        job_id: String(job.id),
        requested_by: actor.username,
        active_memberships_to_purge: previewResult.preview.active_memberships,
        iocs_to_expire_or_remove: previewResult.preview.iocs_only_from_this_feed,
        iocs_shared_with_other_sources: previewResult.preview.iocs_shared_with_other_sources,
        status: 'requested'
      }
    }).catch(() => {});

    return res.status(202).json({
      accepted: true,
      job_id: String(job.id),
      feed_key: key,
      feed_name: feed.name,
      status: 'queued',
      message: 'Purge job started. This may take a few minutes for large feeds.'
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to start purge job', detail: err.message });
  }
});

app.patch('/api/integrations/:key/archive', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  const { key } = req.params;
  try {
    const result = await archiveIntegrationFeed(pool, key, { actor: integrationFeedActor(req) });
    if (!result.ok) {
      return res.status(result.status || 400).json({ message: result.message || 'Archive failed' });
    }
    try {
      await syncSingleFeedSchedule(pool, importQueue, key, { logPrefix: '[integrations]' });
    } catch (syncErr) {
      console.warn('[integrations] archive schedule sync failed', syncErr?.message || syncErr);
    }
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.FEED_ARCHIVED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(result.feed.integration_id || key),
      entityDisplay: result.feed.name,
      metadata: { feed_key: result.feed.key, feed_kind: result.feed.feed_kind }
    }).catch(() => {});
    return res.json(result.feed);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to archive feed', detail: err.message });
  }
});

app.patch('/api/integrations/:key/restore', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  const { key } = req.params;
  try {
    const result = await restoreIntegrationFeed(pool, key);
    if (!result.ok) {
      return res.status(result.status || 400).json({ message: result.message || 'Restore failed' });
    }
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.FEED_RESTORED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(result.feed.integration_id || key),
      entityDisplay: result.feed.name,
      metadata: { feed_key: result.feed.key, feed_kind: result.feed.feed_kind }
    }).catch(() => {});
    return res.json(result.feed);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to restore feed', detail: err.message });
  }
});

app.put('/api/integrations/:key/trust-level', async (req, res) => {
  const { key } = req.params;
  const trustLevel = String(req.body?.trust_level || '').trim();

  if (!TRUST_LEVELS.has(trustLevel)) {
    return res.status(400).json({ message: 'Invalid trust_level' });
  }

  try {
    const prevQ = await pool.query(
      'SELECT key, integration_id, name, trust_level FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!prevQ.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }
    const prev = prevQ.rows[0];

    const result = await pool.query(
      `UPDATE integration_feeds
       SET trust_level = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, integration_id, name, trust_level`,
      [key, trustLevel]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.INTEGRATION_TRUST_LEVEL_CHANGED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(result.rows[0].integration_id || key),
      entityDisplay: result.rows[0].name,
      before: { trust_level: prev.trust_level },
      after: { trust_level: result.rows[0].trust_level },
      metadata: { feed_key: key }
    }).catch((e) => console.warn('[audit] trust level log failed', e?.message || e));

    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update trust level', detail: err.message });
  }
});

app.put('/api/integrations/:key/schedule', async (req, res) => {
  const { key } = req.params;
  if (!assertCustomFeedSettingsAllowed(req, key, res)) return;
  const scheduleCron = String(req.body?.schedule_cron || '').trim();

  if (!isAllowedScheduleCron(scheduleCron)) {
    return res.status(400).json({ message: 'Invalid schedule_cron' });
  }

  try {
    const prevQ = await pool.query(
      'SELECT key, integration_id, name, schedule_cron FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!prevQ.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }
    const prev = prevQ.rows[0];

    const result = await pool.query(
      `UPDATE integration_feeds
       SET schedule_cron = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, integration_id, name, schedule_cron`,
      [key, scheduleCron]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.INTEGRATION_SCHEDULE_CHANGED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(result.rows[0].integration_id || key),
      entityDisplay: result.rows[0].name,
      before: { schedule_cron: prev.schedule_cron },
      after: { schedule_cron: result.rows[0].schedule_cron },
      metadata: { feed_key: key }
    }).catch((e) => console.warn('[audit] schedule log failed', e?.message || e));

    try {
      await syncSingleFeedSchedule(pool, importQueue, key, { logPrefix: '[integrations]' });
    } catch (syncErr) {
      console.warn('[integrations] schedule saved but BullMQ sync failed', syncErr?.message || syncErr);
    }

    if (isRunOnceSchedule(scheduleCron)) {
      console.log('[integrations] feed schedule updated to run_once', { feed_key: key });
    }

    const slotMap = buildHourlySlotMap(
      (await pool.query(`SELECT key, schedule_cron AS schedule FROM integration_feeds WHERE active = TRUE AND schedule_cron <> 'run_once'`)).rows
    );
    const row = result.rows[0];
    const nextRunAt = computeNextRunAt(row.schedule_cron, key, new Date(), slotMap);

    return res.json({
      ...row,
      schedule_reference_timezone: getSystemScheduleTimezone(),
      next_run_at: nextRunAt ? nextRunAt.toISOString() : null
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update schedule', detail: err.message });
  }
});

app.patch('/api/integrations/:key/default-confidence', async (req, res) => {
  const { key } = req.params;
  if (!assertCustomFeedSettingsAllowed(req, key, res)) return;
  const { AUDIT_ACTION, AUDIT_ENTITY } = await import('./lib/auditConstants.js');

  const confCheck = validateConfidenceInput(req.body?.default_confidence);
  if (!confCheck.ok) {
    return res.status(400).json({ message: confCheck.error });
  }

  try {
    const prevQ = await pool.query(
      'SELECT key, integration_id, name, default_confidence FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!prevQ.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }
    const prev = prevQ.rows[0];
    if (normalizeIocConfidence(prev.default_confidence) === confCheck.value) {
      return res.json({
        key: prev.key,
        name: prev.name,
        default_confidence: confCheck.value
      });
    }

    const result = await pool.query(
      `UPDATE integration_feeds
       SET default_confidence = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, integration_id, name, default_confidence`,
      [key, confCheck.value]
    );

    iocDetailsCache.clear();

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.INTEGRATION_FEED_CONFIDENCE_UPDATED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(result.rows[0].integration_id || key),
      entityDisplay: result.rows[0].name,
      before: { default_confidence: prev.default_confidence },
      after: { default_confidence: confCheck.value },
      metadata: {
        feed_key: key,
        feed_name: result.rows[0].name,
        confidence_model: 'inherited',
        bulk_rewrite: false,
        note: 'Only feed default confidence was changed. Inherited effective confidence changes at read time.'
      }
    });

    return res.json(result.rows[0]);
  } catch (err) {
    if (err?.code === '42703') {
      return res.status(503).json({
        message: 'Feed default confidence schema not applied. Run explicit migration: npm run migrate'
      });
    }
    return res.status(500).json({ message: 'Failed to update feed default confidence', detail: err.message });
  }
});

async function resolveFeedCredentialsAuthKey(feedKey, storedCredentials) {
  const fromDb = storedCredentials && typeof storedCredentials === 'object'
    ? String(storedCredentials.auth_key || '').trim()
    : '';
  if (fromDb) return fromDb;

  if (feedKey === URLHAUS_FEED_KEY) return String(process.env.URLHAUS_AUTH_KEY || '').trim();
  if (feedKey === MALWAREBAZAAR_FEED_KEY) return String(process.env.MALWAREBAZAAR_AUTH_KEY || '').trim();
  if (feedKey === THREATFOX_FEED_KEY) return String(process.env.THREATFOX_AUTH_KEY || '').trim();
  return '';
}

app.get('/api/integrations/:key/credentials', async (req, res) => {
  const { key } = req.params;
  if (!AUTH_KEY_FEED_KEYS.has(key)) {
    return res.status(404).json({ message: 'Integration does not support credentials' });
  }

  try {
    const result = await pool.query(
      'SELECT key, credentials FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!result.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    const summary = formatFeedCredentialsSummary(key, result.rows[0].credentials);
    return res.json(summary);
  } catch (err) {
    if (err?.code === '42703') {
      return res.status(503).json({
        message: 'Feed credentials schema not applied. Run explicit migration: npm run migrate'
      });
    }
    return res.status(500).json({ message: 'Failed to load credentials', detail: err.message });
  }
});

app.put('/api/integrations/:key/credentials', async (req, res) => {
  const { key } = req.params;
  if (!AUTH_KEY_FEED_KEYS.has(key)) {
    return res.status(404).json({ message: 'Integration does not support credentials' });
  }

  const authKey = String(req.body?.auth_key || '').trim();
  if (!authKey) {
    return res.status(400).json({ message: 'auth_key is required' });
  }
  const reasonCheck = parseActionReason(req.body);
  if (!reasonCheck.ok) {
    return res.status(400).json({ message: reasonCheck.message });
  }

  try {
    const prevQ = await pool.query(
      'SELECT key, integration_id, name, credentials FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!prevQ.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    const prev = prevQ.rows[0];
    const prevCreds = prev.credentials && typeof prev.credentials === 'object' ? prev.credentials : {};
    const nextCreds = { ...prevCreds, auth_key: authKey };
    if (key === THREATFOX_FEED_KEY && req.body?.recent_days != null) {
      nextCreds.recent_days = validateThreatFoxRecentDays(req.body.recent_days);
    }

    const result = await pool.query(
      `UPDATE integration_feeds
       SET credentials = $2::jsonb, updated_at = NOW()
       WHERE key = $1
       RETURNING key, credentials`,
      [key, JSON.stringify(nextCreds)]
    );

    const summary = formatFeedCredentialsSummary(key, result.rows[0].credentials);
    const { AUDIT_ACTION, AUDIT_ENTITY } = await import('./lib/auditConstants.js');

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.INTEGRATION_CREDENTIALS_CHANGED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(prev.integration_id || key),
      entityDisplay: prev.name,
      before: { auth_key_configured: Boolean(String(prevCreds.auth_key || '').trim()) },
      after: { auth_key_configured: true },
      metadata: {
        feed_key: key,
        feed_name: prev.name,
        source: 'ui',
        reason: reasonCheck.reason
      }
    }).catch((e) => {
      console.warn('[audit] integration credentials log failed', e?.message || e);
    });

    return res.json(summary);
  } catch (err) {
    if (err?.code === '42703') {
      return res.status(503).json({
        message: 'Feed credentials schema not applied. Run explicit migration: npm run migrate'
      });
    }
    return res.status(500).json({ message: 'Failed to save credentials', detail: err.message });
  }
});

app.post('/api/integrations/:key/credentials/test', async (req, res) => {
  const { key } = req.params;
  if (!AUTH_KEY_FEED_KEYS.has(key)) {
    return res.status(404).json({ message: 'Integration does not support credentials' });
  }

  try {
    const feedQ = await pool.query(
      'SELECT key, credentials FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!feedQ.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    const draftKey = String(req.body?.auth_key || '').trim();
    const authKey = draftKey || await resolveFeedCredentialsAuthKey(key, feedQ.rows[0].credentials);
    let result;

    if (key === URLHAUS_FEED_KEY) {
      result = await testUrlhausConnection({ authKey });
    } else if (key === MALWAREBAZAAR_FEED_KEY) {
      result = await testMalwareBazaarConnection({ authKey });
    } else if (key === THREATFOX_FEED_KEY) {
      result = await testThreatFoxConnection({
        authKey,
        days: validateThreatFoxRecentDays(req.body?.recent_days, 1)
      });
    } else if (key === ALIENVAULT_OTX_FEED_KEY) {
      result = await testOtxConnection({ authKey });
    } else {
      return res.status(404).json({ message: 'Integration does not support credentials test' });
    }

    const message = sanitizeFeedErrorMessage(key, result.message);
    if (result.ok) {
      return res.json({ ok: true, message });
    }
    return res.status(400).json({ ok: false, message });
  } catch (err) {
    const message = sanitizeFeedErrorMessage(key, err?.message || 'Connection test failed');
    return res.status(500).json({ ok: false, message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const loginId = String(email || '').trim();

  if (!loginId || password == null || typeof password !== 'string') {
    await auditLogService.auditFailure({
      req,
      action: AUDIT_ACTION.AUTH_LOGIN_FAILED,
      entityType: AUDIT_ENTITY.AUTH,
      entityDisplay: loginId || 'unknown',
      severity: AUDIT_SEVERITY.WARNING,
      metadata: { reason: 'missing_credentials' }
    }).catch(() => {});
    return res.status(401).json({ message: 'Invalid email or password' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, public_id, username, password_hash, role, status FROM users WHERE username = $1',
      [loginId]
    );
    if (rows.length) {
      const u = rows[0];
      const ok = await bcrypt.compare(password, u.password_hash);
      if (ok) {
        if (String(u.status || 'active') === 'passive') {
          await auditLogService.auditFailure({
            req,
            action: AUDIT_ACTION.AUTH_LOGIN_FAILED,
            entityType: AUDIT_ENTITY.AUTH,
            entityId: String(u.public_id || u.id),
            entityDisplay: u.username,
            severity: AUDIT_SEVERITY.WARNING,
            actorUsername: u.username,
            actorRole: u.role,
            metadata: { reason: 'passive_account' }
          }).catch(() => {});
          return res.status(401).json({ message: 'Invalid email or password' });
        }
        const token = signUserToken({
          userId: u.id,
          username: u.username,
          email: u.username,
          role: u.role
        });
        appendAuthCookie(req, res, token);
        appendCsrfCookie(req, res);
        await auditLogService.auditSuccess({
          req,
          action: AUDIT_ACTION.AUTH_LOGIN_SUCCESS,
          entityType: AUDIT_ENTITY.AUTH,
          entityId: String(u.public_id || u.id),
          entityDisplay: u.username,
          severity: AUDIT_SEVERITY.INFO,
          actorPublicId: u.public_id,
          actorUsername: u.username,
          actorEmail: u.username,
          actorRole: u.role,
          metadata: { source: 'database_user' }
        }).catch(() => {});
        return res.json({
          user: {
            email: u.username,
            username: u.username,
            id: u.public_id,
            role: u.role
          }
        });
      }
    }
  } catch {
    /* fall through to env-based demo login if DB unavailable */
  }

  if (demoEmail && demoPassword && loginId === demoEmail && password === demoPassword) {
    const token = signUserToken(loginId);
    appendAuthCookie(req, res, token);
    appendCsrfCookie(req, res);
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.AUTH_LOGIN_SUCCESS,
      entityType: AUDIT_ENTITY.AUTH,
      entityDisplay: loginId,
      severity: AUDIT_SEVERITY.INFO,
      actorUsername: loginId,
      actorEmail: loginId,
      actorRole: ROLES.ADMIN,
      metadata: { source: 'demo_env_login' }
    }).catch(() => {});
    return res.json({
      user: { email: loginId, username: loginId, id: null, role: ROLES.ADMIN }
    });
  }

  await auditLogService.auditFailure({
    req,
    action: AUDIT_ACTION.AUTH_LOGIN_FAILED,
    entityType: AUDIT_ENTITY.AUTH,
    entityDisplay: loginId,
    severity: AUDIT_SEVERITY.WARNING,
    metadata: { reason: 'invalid_credentials' }
  }).catch(() => {});
  return res.status(401).json({ message: 'Invalid email or password' });
});

app.post('/api/auth/logout', async (req, res) => {
  await auditLogService.auditSuccess({
    req,
    action: AUDIT_ACTION.AUTH_LOGOUT,
    entityType: AUDIT_ENTITY.AUTH,
    entityDisplay: String(req.user?.username || req.user?.email || 'unknown'),
    severity: AUDIT_SEVERITY.INFO,
    metadata: { auth_via: req.authVia || 'web' }
  }).catch(() => {});
  clearAuthCookie(req, res);
  clearCsrfCookie(req, res);
  res.status(204).end();
});

app.get('/api/auth/me', async (req, res) => {
  let publicId = null;
  if (req.user?.id != null) {
    try {
      const { rows } = await pool.query('SELECT public_id FROM users WHERE id = $1', [Number(req.user.id)]);
      if (rows.length) publicId = rows[0].public_id;
    } catch {
      // fall through to null id
    }
  }

  res.json({
    user: {
      email: req.user.email,
      username: req.user.username || req.user.email,
      id: publicId,
      role: req.user.role || ROLES.ADMIN
    }
  });
});

app.get('/api/users/me/preferences', async (req, res) => {
  const email = req.user.email;

  try {
    const { rows } = await pool.query('SELECT email, timezone FROM user_preferences WHERE email = $1', [email]);
    if (!rows.length) {
      return res.json({ email, timezone: null });
    }
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch preferences', detail: err.message });
  }
});

app.put('/api/users/me/preferences', async (req, res) => {
  const email = req.user.email;
  const timezone = String(req.body?.timezone || '').trim();

  if (!timezone) {
    return res.status(400).json({ message: 'timezone is required' });
  }

  try {
    const q = `
      INSERT INTO user_preferences (email, timezone, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (email)
      DO UPDATE SET timezone = EXCLUDED.timezone, updated_at = NOW()
      RETURNING email, timezone
    `;
    const { rows } = await pool.query(q, [email, timezone]);
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to save preferences', detail: err.message });
  }
});

registerUserManagementRoutes(app, pool, auditLogService);
registerRouteModule('users');
registerPublicFeedRoutes(app, pool);
registerRouteModule('public_feeds');
registerPublishedFeedRoutes(app, pool, auditLogService);
registerRouteModule('published_feeds');
registerApiKeyRoutes(app, pool, auditLogService);
registerRouteModule('api_keys');
registerAuditLogRoutes(app, pool);
registerIocExportRoutes(app, pool);
registerRouteModule('audit');

registerRdapEnrichmentRoutes(app, pool, auditLogService);
registerRouteModule('rdap_enrichment');
registerDnsmaniaEnrichmentRoutes(app, pool, auditLogService);
registerRouteModule('dnsmania_enrichment');
registerIpEnrichmentRoutes(app, pool, auditLogService);
registerAbuseIpdbEnrichmentRoutes(app, pool, auditLogService);
registerRouteModule('abuseipdb_enrichment');
registerSpamhausDropEnrichmentRoutes(app, pool, auditLogService, { importQueue });
registerAnalystIntelligenceRoutes(app, pool, auditLogService);
registerRouteModule('analyst_intelligence');
registerRouteModule('ip_enrichment');
registerIocExpirationRoutes(app, pool, auditLogService);
registerRouteModule('ioc_expiration');
registerIocConfidenceRoutes(app, pool, auditLogService, {
  invalidateDetailsCache: invalidateIocDetailsCache
});
registerRouteModule('ioc_confidence');
registerIocSourceRoutes(app, pool, auditLogService);
registerCustomThreatFeedRoutes(app, pool, auditLogService, {
  importQueue,
  manualJobPriority: MANUAL_JOB_PRIORITY
});
registerRouteModule('custom_threat_feeds');
registerThreatClassificationRoutes(app, pool, auditLogService);
registerThreatActorRoutes(app, pool, auditLogService);
registerIocThreatMetadataRoutes(app, pool, auditLogService, {
  invalidateDetailsCache: invalidateIocDetailsCache
});
registerRouteModule('threat_classifications');
registerRouteModule('threat_actors');
registerRouteModule('ioc_threat_metadata');
registerRouteModule('ioc_sources');
registerRouteModule('tags_inline');

function isAdminUser(req) {
  const role = String(req.user?.role || '').trim().toLowerCase();
  return role === ROLES.ADMIN;
}

function isReadOnlyUser(req) {
  const role = String(req.user?.role || '').trim().toLowerCase();
  return role === ROLES.READONLY;
}

function isAnalystUser(req) {
  const role = String(req.user?.role || '').trim().toLowerCase();
  return role === ROLES.ANALYST;
}

function canReadSuppression(req) {
  return isAdminUser(req) || isAnalystUser(req) || isReadOnlyUser(req);
}

function isSuppressionActiveRow(row) {
  if (!row) return false;
  if (!row.active) return false;
  if (!row.expires_at) return true;
  const exp = Date.parse(row.expires_at);
  return Number.isFinite(exp) && exp > Date.now();
}

/**
 * Recompute the effective status of every ioc_items row matching a suppression's
 * (value, type). Called after a suppression is created/enabled/disabled/deleted so
 * the IOC lifecycle status flips to/from 'suppressed' immediately (req #6/#7).
 * Best-effort: failures are logged, never fatal to the suppression mutation.
 */
async function recomputeIocsForSuppression(iocValue, iocType, actor = { actor_type: 'user', source: 'web' }) {
  try {
    const { rows } = await pool.query(
      `SELECT id, observable_type FROM ioc_items
       WHERE lower(observable) = lower($1) AND lower(observable_type) = lower($2)`,
      [iocValue, iocType]
    );
    for (const row of rows || []) {
      await recomputeIocGlobalStatus(pool, row.id, row.observable_type, {
        audit: auditLogService,
        actor
      }).catch((e) => console.warn('[suppression] recompute failed', e?.message || e));
    }
  } catch (e) {
    console.warn('[suppression] recompute lookup failed', e?.message || e);
  }
}

function parsePositiveInt(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) return null;
  return n;
}

function normalizeTagName(value) {
  return String(value || '').trim().toLowerCase();
}

const TAG_TYPES = new Set(['threat', 'actor', 'technique', 'context']);

app.get('/api/tags', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });

  try {
    const q = await pool.query(
      `SELECT id, name, type, enabled
       FROM tags
       WHERE enabled = TRUE
       ORDER BY type ASC, name ASC`
    );
    return res.json(q.rows);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch tags', detail: err.message });
  }
});

app.get('/api/admin/tags', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const includeInactive = String(req.query?.include_inactive ?? 'true') !== 'false';
  try {
    const q = await pool.query(
      `SELECT id, name, slug, description, color, category, type, enabled, created_at, updated_at
       FROM tags
       ${includeInactive ? '' : 'WHERE enabled = TRUE'}
       ORDER BY enabled DESC, category ASC NULLS LAST, name ASC`
    );
    return res.json({ tags: q.rows.map((r) => ({
      id: r.id,
      name: r.name,
      slug: r.slug,
      description: r.description,
      color: r.color,
      category: r.category || r.type || 'custom',
      is_active: Boolean(r.enabled),
      created_at: r.created_at,
      updated_at: r.updated_at
    })) });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch tags', detail: err.message });
  }
});

app.post('/api/admin/tags', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const name = String(req.body?.name || '').trim();
  if (!name) return res.status(400).json({ message: 'name is required' });
  const slug = String(req.body?.slug || name).trim().toLowerCase().replace(/[^a-z0-9-_]+/g, '-').replace(/^-+|-+$/g, '');
  const category = String(req.body?.category || 'custom').trim().toLowerCase();
  if (!isValidCategory(category)) {
    return res.status(400).json({ message: `category must be one of: behavior, campaign, theme, targeting, source-context, review-state, vulnerability, custom` });
  }
  const legacyType = categoryToLegacyType(category);
  const enabled = req.body?.is_active !== false;
  try {
    const q = await pool.query(
      `INSERT INTO tags (name, slug, type, category, description, color, enabled, updated_at)
       VALUES ($1, $2, $3::tag_type, $4, $5, $6, $7, NOW())
       RETURNING id, name, slug, description, color, category, type, enabled, created_at, updated_at`,
      [name.toLowerCase(), slug, legacyType, category, req.body?.description || null, req.body?.color || null, enabled]
    );
    const tag = q.rows[0];
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.TAG_CREATED,
      entityType: AUDIT_ENTITY.TAG,
      entityId: String(tag.id),
      entityDisplay: tag.name,
      after: { name: tag.name, category: tag.category, is_active: Boolean(tag.enabled) }
    });
    return res.status(201).json({ tag: {
      id: q.rows[0].id, name: q.rows[0].name, slug: q.rows[0].slug, description: q.rows[0].description, color: q.rows[0].color,
      category: q.rows[0].category || q.rows[0].type || 'custom', is_active: Boolean(q.rows[0].enabled), created_at: q.rows[0].created_at, updated_at: q.rows[0].updated_at
    } });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ message: 'Tag already exists' });
    return res.status(500).json({ message: 'Failed to create tag', detail: err.message });
  }
});

app.put('/api/admin/tags/:id', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const id = parsePositiveInt(req.params?.id);
  if (!id) return res.status(400).json({ message: 'Invalid id' });
  const fields = [];
  const params = [id];
  if (req.body?.name != null) { params.push(String(req.body.name).trim().toLowerCase()); fields.push(`name = $${params.length}`); }
  if (req.body?.category != null) {
    const c = String(req.body.category).trim().toLowerCase();
    if (!isValidCategory(c)) {
      return res.status(400).json({ message: 'Invalid tag category' });
    }
    params.push(c);
    fields.push(`category = $${params.length}`);
    params.push(categoryToLegacyType(c));
    fields.push(`type = $${params.length}::tag_type`);
  }
  if (req.body?.description != null) { params.push(String(req.body.description).trim() || null); fields.push(`description = $${params.length}`); }
  if (req.body?.color != null) { params.push(String(req.body.color).trim() || null); fields.push(`color = $${params.length}`); }
  if (req.body?.is_active != null) { params.push(Boolean(req.body.is_active)); fields.push(`enabled = $${params.length}`); }
  if (!fields.length) return res.status(400).json({ message: 'No fields to update' });
  fields.push('updated_at = NOW()');
  try {
    const prevQ = await pool.query('SELECT * FROM tags WHERE id = $1', [id]);
    const prev = prevQ.rows[0];
    if (!prev) return res.status(404).json({ message: 'Tag not found' });
    const q = await pool.query(`UPDATE tags SET ${fields.join(', ')} WHERE id = $1 RETURNING id,name,slug,description,color,category,type,enabled,created_at,updated_at`, params);
    const r = q.rows[0];
    const action = prev.enabled !== false && r.enabled === false
      ? AUDIT_ACTION.TAG_DISABLED
      : (prev.enabled === false && r.enabled !== false ? AUDIT_ACTION.TAG_ENABLED : AUDIT_ACTION.TAG_UPDATED);
    await auditLogService.auditSuccess({
      req,
      action,
      entityType: AUDIT_ENTITY.TAG,
      entityId: String(r.id),
      entityDisplay: r.name,
      before: { name: prev.name, category: prev.category, is_active: Boolean(prev.enabled) },
      after: { name: r.name, category: r.category, is_active: Boolean(r.enabled) }
    });
    return res.json({ tag: { id:r.id,name:r.name,slug:r.slug,description:r.description,color:r.color,category:r.category||r.type||'custom',is_active:Boolean(r.enabled),created_at:r.created_at,updated_at:r.updated_at } });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update tag', detail: err.message });
  }
});

app.delete('/api/admin/tags/:id', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const id = parsePositiveInt(req.params?.id);
  if (!id) return res.status(400).json({ message: 'Invalid id' });
  try {
    const prevQ = await pool.query('SELECT * FROM tags WHERE id = $1', [id]);
    const prev = prevQ.rows[0];
    if (!prev) return res.status(404).json({ message: 'Tag not found' });
    const q = await pool.query('UPDATE tags SET enabled = FALSE, updated_at = NOW() WHERE id = $1 RETURNING id, name, enabled', [id]);
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.TAG_DISABLED,
      entityType: AUDIT_ENTITY.TAG,
      entityId: String(id),
      entityDisplay: prev.name,
      before: { is_active: Boolean(prev.enabled) },
      after: { is_active: false }
    });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to disable tag', detail: err.message });
  }
});

app.post('/api/tags', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });

  const name = normalizeTagName(req.body?.name);
  const type = String(req.body?.type || '').trim().toLowerCase();

  if (!name) return res.status(400).json({ message: 'name is required' });
  if (!TAG_TYPES.has(type)) return res.status(400).json({ message: 'Invalid type' });

  try {
    const q = await pool.query(
      `INSERT INTO tags (name, type)
       VALUES ($1, $2::tag_type)
       ON CONFLICT (name) DO NOTHING
       RETURNING id, name, type, enabled`,
      [name, type]
    );

    if (!q.rowCount) {
      return res.status(409).json({ message: 'Tag already exists' });
    }

    return res.status(201).json(q.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create tag', detail: err.message });
  }
});

app.patch('/api/tags/:id', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });

  const tagId = parsePositiveInt(req.params?.id);
  if (!tagId) return res.status(400).json({ message: 'Invalid id' });
  if (typeof req.body?.enabled !== 'boolean') {
    return res.status(400).json({ message: 'enabled must be boolean' });
  }

  try {
    const q = await pool.query(
      `UPDATE tags
       SET enabled = $2
       WHERE id = $1
       RETURNING id, name, type, enabled`,
      [tagId, req.body.enabled]
    );

    if (!q.rowCount) return res.status(404).json({ message: 'Tag not found' });
    return res.json(q.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update tag', detail: err.message });
  }
});

app.get('/api/ioc/:id/tags', async (req, res) => {
  const iocId = parsePositiveInt(req.params?.id);
  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });

  try {
    const q = await pool.query(
      `SELECT
         i.id AS ioc_id,
         t.id,
         t.name,
         t.type
       FROM ioc_items i
       LEFT JOIN ioc_tags it
         ON it.ioc_id = i.id
        AND it.ioc_observable_type = i.observable_type
       LEFT JOIN tags t ON t.id = it.tag_id
       WHERE i.id = $1
       ORDER BY t.type ASC NULLS LAST, t.name ASC NULLS LAST`,
      [iocId]
    );

    if (!q.rowCount) return res.status(404).json({ message: 'IOC not found' });

    return res.json(q.rows.filter((row) => row.id != null).map((row) => ({
      id: row.id,
      name: row.name,
      type: row.type
    })));
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch IOC tags', detail: err.message });
  }
});

app.post('/api/ioc/:id/tags', async (req, res) => {
  const iocId = parsePositiveInt(req.params?.id);
  const tagId = parsePositiveInt(req.body?.tag_id);

  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  if (!tagId) return res.status(400).json({ message: 'Invalid tag_id' });

  try {
    const iocExists = await pool.query(
      `SELECT id, public_id, observable, observable_type
       FROM ioc_items WHERE id = $1 LIMIT 1`,
      [iocId]
    );
    if (!iocExists.rowCount) return res.status(404).json({ message: 'IOC not found' });

    const ioc = iocExists.rows[0];
    const iocObservableType = String(ioc.observable_type || '').trim();

    const tagExists = await pool.query(
      `SELECT id, name, type, category FROM tags WHERE id = $1 AND enabled = TRUE LIMIT 1`,
      [tagId]
    );
    if (!tagExists.rowCount) return res.status(404).json({ message: 'Tag not found or disabled' });
    const tag = tagExists.rows[0];

    const insertQ = await pool.query(
      `INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, created_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (ioc_id, tag_id) DO NOTHING
       RETURNING tag_id`,
      [iocId, iocObservableType, tagId, req.user?.id ?? null]
    );

    if (insertQ.rowCount) {
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_TAG_ADDED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: ioc.public_id ? String(ioc.public_id) : String(iocId),
        entityDisplay: ioc.observable || String(iocId),
        subjectIocId: iocId,
        subjectIocType: iocObservableType || null,
        subjectIocValue: ioc.observable || null,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: String(iocId),
          subject_ioc_id: String(iocId),
          subject_ioc_type: iocObservableType || null,
          subject_ioc_value: ioc.observable || null,
          tag_id: tag.id,
          tag_name: tag.name,
          tag_type: tag.type,
          tag_category: tag.category
        }
      }).catch(() => {});
    }

    return res.status(201).json({ ok: true });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to add IOC tag', detail: err.message });
  }
});

app.delete('/api/ioc/:id/tags/:tagId', async (req, res) => {
  const iocId = parsePositiveInt(req.params?.id);
  const tagId = parsePositiveInt(req.params?.tagId);

  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  if (!tagId) return res.status(400).json({ message: 'Invalid tag id' });

  try {
    const iocExists = await pool.query(
      `SELECT id, public_id, observable, observable_type
       FROM ioc_items WHERE id = $1 LIMIT 1`,
      [iocId]
    );
    if (!iocExists.rowCount) return res.status(404).json({ message: 'IOC not found' });
    const ioc = iocExists.rows[0];

    const tagQ = await pool.query(
      `SELECT id, name, type, category FROM tags WHERE id = $1 LIMIT 1`,
      [tagId]
    );
    const tag = tagQ.rows[0] || null;

    const deleteQ = await pool.query(
      `DELETE FROM ioc_tags
       WHERE ioc_id = $1
         AND tag_id = $2
         AND ioc_observable_type = (
           SELECT observable_type FROM ioc_items WHERE id = $1 LIMIT 1
         )
       RETURNING tag_id`,
      [iocId, tagId]
    );

    if (deleteQ.rowCount) {
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_TAG_REMOVED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: ioc.public_id ? String(ioc.public_id) : String(iocId),
        entityDisplay: ioc.observable || String(iocId),
        subjectIocId: iocId,
        subjectIocType: ioc.observable_type || null,
        subjectIocValue: ioc.observable || null,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: String(iocId),
          subject_ioc_id: String(iocId),
          subject_ioc_type: ioc.observable_type || null,
          subject_ioc_value: ioc.observable || null,
          tag_id: tagId,
          tag_name: tag?.name || null,
          tag_type: tag?.type || null,
          tag_category: tag?.category || null
        }
      }).catch(() => {});
    }

    return res.status(204).end();
  } catch (err) {
    return res.status(500).json({ message: 'Failed to delete IOC tag', detail: err.message });
  }
});

app.get('/api/ioc/:id/tags/source/hidden', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  const iocId = parsePositiveInt(req.params?.id);
  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  try {
    const iocExists = await pool.query('SELECT id FROM ioc_items WHERE id = $1 LIMIT 1', [iocId]);
    if (!iocExists.rowCount) return res.status(404).json({ message: 'IOC not found' });
    const rows = await listActiveSourceTagOverrides(pool, iocId);
    return res.json({
      items: rows.map((r) => ({
        id: Number(r.id),
        tag: r.tag_value,
        tag_normalized: r.tag_normalized,
        source: r.source_name,
        source_name: r.source_name,
        hidden_at: r.created_at,
        action: r.action
      }))
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to list hidden source tags', detail: err.message });
  }
});

app.post('/api/ioc/:id/tags/source/hide', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  const iocId = parsePositiveInt(req.params?.id);
  const tagValue = String(req.body?.tag || req.body?.tag_value || '').trim();
  const sourceName = String(req.body?.source || req.body?.source_name || '').trim();

  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  if (!tagValue) return res.status(400).json({ message: 'tag is required' });
  if (!sourceName) return res.status(400).json({ message: 'source is required' });

  try {
    const iocExists = await pool.query(
      `SELECT id, public_id, observable, observable_type
       FROM ioc_items WHERE id = $1 LIMIT 1`,
      [iocId]
    );
    if (!iocExists.rowCount) return res.status(404).json({ message: 'IOC not found' });
    const ioc = iocExists.rows[0];

    // Resolve sibling items for same observable so evidence/tags match details view
    const siblings = await pool.query(
      `SELECT id FROM ioc_items
       WHERE observable = $1 AND observable_type = $2`,
      [ioc.observable, ioc.observable_type]
    );
    const iocItemIds = siblings.rows.map((r) => Number(r.id)).filter((id) => Number.isFinite(id));
    const evidenceRows = await fetchFeedSourceEvidenceForItems(pool, {
      iocItemIds,
      observableType: ioc.observable_type
    });
    const feedIntelligence = buildFeedIntelligence(evidenceRows);
    if (!feedTagsIncludeSourceTag(feedIntelligence.tags, tagValue, sourceName)) {
      return res.status(404).json({
        message: 'Source tag not found on this IOC',
        code: 'source_tag_not_found'
      });
    }

    const result = await hideSourceTag(pool, {
      iocId,
      iocObservableType: ioc.observable_type,
      tagValue,
      sourceName,
      createdBy: req.user?.id ?? null
    });

    if (result.created) {
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SOURCE_TAG_HIDDEN,
        entityType: AUDIT_ENTITY.IOC,
        entityId: ioc.public_id ? String(ioc.public_id) : String(iocId),
        entityDisplay: ioc.observable || String(iocId),
        subjectIocId: iocId,
        subjectIocType: ioc.observable_type || null,
        subjectIocValue: ioc.observable || null,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: String(iocId),
          subject_ioc_id: String(iocId),
          subject_ioc_type: ioc.observable_type || null,
          subject_ioc_value: ioc.observable || null,
          tag: tagValue,
          tag_normalized: result.row.tag_normalized,
          source: sourceName,
          source_name: sourceName
        }
      }).catch(() => {});
      invalidateIocDetailsCache(ioc.public_id);
    }

    return res.json({
      ok: true,
      created: result.created,
      item: {
        id: Number(result.row.id),
        tag: result.row.tag_value,
        tag_normalized: result.row.tag_normalized,
        source: result.row.source_name,
        source_name: result.row.source_name,
        hidden_at: result.row.created_at
      }
    });
  } catch (err) {
    if (err?.code === 'invalid_tag' || err?.code === 'invalid_source') {
      return res.status(400).json({ message: err.message, code: err.code });
    }
    return res.status(500).json({ message: 'Failed to hide source tag', detail: err.message });
  }
});

app.post('/api/ioc/:id/tags/source/restore', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  const iocId = parsePositiveInt(req.params?.id);
  const tagValue = String(req.body?.tag || req.body?.tag_value || '').trim();
  const sourceName = String(req.body?.source || req.body?.source_name || '').trim();

  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  if (!tagValue) return res.status(400).json({ message: 'tag is required' });
  if (!sourceName) return res.status(400).json({ message: 'source is required' });

  try {
    const iocExists = await pool.query(
      `SELECT id, public_id, observable, observable_type
       FROM ioc_items WHERE id = $1 LIMIT 1`,
      [iocId]
    );
    if (!iocExists.rowCount) return res.status(404).json({ message: 'IOC not found' });
    const ioc = iocExists.rows[0];

    const result = await restoreSourceTag(pool, {
      iocId,
      tagValue,
      sourceName,
      restoredBy: req.user?.id ?? null
    });

    if (result.restored) {
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SOURCE_TAG_RESTORED,
        entityType: AUDIT_ENTITY.IOC,
        entityId: ioc.public_id ? String(ioc.public_id) : String(iocId),
        entityDisplay: ioc.observable || String(iocId),
        subjectIocId: iocId,
        subjectIocType: ioc.observable_type || null,
        subjectIocValue: ioc.observable || null,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          ioc_id: String(iocId),
          subject_ioc_id: String(iocId),
          subject_ioc_type: ioc.observable_type || null,
          subject_ioc_value: ioc.observable || null,
          tag: result.row.tag_value || tagValue,
          tag_normalized: result.row.tag_normalized,
          source: result.row.source_name || sourceName,
          source_name: result.row.source_name || sourceName
        }
      }).catch(() => {});
      invalidateIocDetailsCache(ioc.public_id);
    }

    return res.json({
      ok: true,
      restored: result.restored,
      item: result.row
        ? {
          id: Number(result.row.id),
          tag: result.row.tag_value,
          tag_normalized: result.row.tag_normalized,
          source: result.row.source_name,
          source_name: result.row.source_name,
          restored_at: result.row.restored_at
        }
        : null
    });
  } catch (err) {
    if (err?.code === 'invalid_tag' || err?.code === 'invalid_source') {
      return res.status(400).json({ message: err.message, code: err.code });
    }
    return res.status(500).json({ message: 'Failed to restore source tag', detail: err.message });
  }
});

app.post('/api/ioc/ip', async (req, res) => {
  try {
    const result = await createManualIoc(pool, req.body || {}, {
      req,
      user: req.user,
      audit: auditLogService,
      onAfterInsert: async () => {
        scheduleGeoCacheRefreshAfterAdd();
      }
    });

    if (result.status === 201 && result.body?.id) {
      await pool.query(
        `INSERT INTO dashboard_map_pending_events (event_type, ioc_id, observable, observable_type)
         VALUES ('add', $1, $2, $3)`,
        [result.body.id, result.body.observable, result.body.observable_type]
      ).catch(() => {});
    }

    return res.status(result.status).json(result.body);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create record', detail: err.message });
  }
});

registerIocDeleteRoute(app, pool, auditLogService, { invalidateDetailsCache: invalidateIocDetailsCache });

async function finalizeIocListPageItems(pool, pageItems, opts = {}) {
  const enriched = await enrichItemsWithActiveSourceCounts(pool, pageItems, opts);
  const [confMap, threatMetaMap, analystMap, feedClassMap] = await Promise.all([
    buildDisplayConfidenceForItems(pool, enriched, {
      includeInactiveMemberships: Boolean(opts.includeInactiveMemberships)
    }),
    enrichItemsWithThreatMetadata(pool, pageItems),
    enrichItemsWithAnalystIntelligenceCounts(pool, pageItems),
    batchLoadFeedClassifications(pool, pageItems)
  ]);
  return enriched.map((it) => {
    const c = confMap.get(`${Number(it.id)}|${String(it.observable_type)}`) || {};
    const merged = mergeThreatMetadataItem({ ...it, ...c }, threatMetaMap);
    const withFeed = mergeFeedClassificationsIntoItem(merged, feedClassMap);
    return mergeAnalystIntelligenceItem(withFeed, analystMap);
  });
}

async function mapIocListPageItems(pool, pageItems, { statusFilter, hasSearch, byItemIds = false } = {}) {
  const finalized = await finalizeIocListPageItems(pool, pageItems, {
    byItemIds,
    includeInactiveMemberships: hasSearch
  });
  const scoped = hasSearch ? finalized : applyActiveListScope(finalized, statusFilter);
  return decorateIocListItems(scoped);
}

async function getCachedIocListGlobalTotal(pool, statusFilter = 'active') {
  if (statusFilter === 'active') {
    const snapTotal = await readIocListBrowseGlobalTotal(pool);
    if (snapTotal != null) return snapTotal;
    return null;
  }
  const sf = parseIocListStatusFilter(statusFilter);
  const lastUpdate = await fetchIocStatsLastUpdate(pool);
  const cacheKey = buildIocStatsCacheKey(sf, lastUpdate);
  const cached = readIocStatsCache(cacheKey);
  if (cached?.total != null) return Number(cached.total);
  return null;
}

function resolveIocListMode({ q, fullScan, classificationFilter, source_name, confidence, asn, country }) {
  if (q) return 'search';
  if (fullScan || classificationFilter.length || source_name || confidence || asn || country) return 'filter';
  return 'browse';
}

async function handleIocList(req, res) {
  const timingEnabled = IOC_LIST_TIMING || req.query.timing === '1';
  const t = timingEnabled ? { requestReceived: Date.now() } : null;

  const { source_name, confidence, q, asn, country, page = '1', page_size = '25' } = req.query;
  const qTrimmed = String(q || '').trim();
  const hasSearch = qTrimmed.length > 0;
  const browseStatusFilter = parseIocListStatusFilter(req.query.status ?? 'active');
  const statusFilter = resolveIocListStatusScope(hasSearch, browseStatusFilter);
  const statusClause = hasSearch ? null : iocStatusSqlClause(statusFilter);
  const classificationFilter = parseThreatClassificationFilterParam(
    req.query.threat_classification ?? req.query.threat_classifications
  );
  const currentPage = Math.max(Number(page) || 1, 1);
  const limit = normalizeIocListPageSize(page_size);
  const offset = (currentPage - 1) * limit;

  const filters = [];
  const params = [];
  let prefixedHashSearch = null;
  let prefixedObservableSearch = null;

  if (statusClause) {
    filters.push(statusClause);
  }

  if (source_name) {
    params.push(`%${source_name}%`);
    filters.push(`source_name ILIKE $${params.length}`);
  }

  if (confidence) {
    params.push(confidence);
    filters.push(`confidence = $${params.length}`);
  }

  if (classificationFilter.length) {
    params.push(classificationFilter);
    filters.push(`EXISTS (
      SELECT 1 FROM ioc_threat_classifications itc
      WHERE itc.ioc_id = ioc_items.id
        AND itc.ioc_observable_type = ioc_items.observable_type
        AND itc.classification_slug = ANY($${params.length}::text[])
    )`);
  }

  if (q) {
    const qv = String(q).trim();
    if (qv.length < 3) {
      return res.json({
        items: [],
        pagination: buildIocListPagination({
          mode: 'search',
          matchCount: 0,
          page: currentPage,
          pageSize: limit,
          statusFilter
        }),
        note: 'Search term must be at least 3 characters'
      });
    }

    const prefixedHash = qv.match(/^(md5|sha1|sha256|ssdeep|imphash|tlsh)\s*:\s*(.+)$/i);
    if (prefixedHash) {
      const hashType = prefixedHash[1].toLowerCase();
      const hashValue = String(prefixedHash[2] || '').trim().toLowerCase();
      if (hashValue.length < 3) {
        return res.json({
          items: [],
          pagination: buildIocListPagination({
            mode: 'search',
            matchCount: 0,
            page: currentPage,
            pageSize: limit,
            statusFilter
          }),
          note: 'Hash value must be at least 3 characters'
        });
      }

      const noteExprByType = {
        md5: "LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'md5=', 2), '|', 1), ''))",
        sha1: "LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'sha1=', 2), '|', 1), ''))",
        sha256: "LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'sha256=', 2), '|', 1), ''))",
        ssdeep: "LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'ssdeep=', 2), '|', 1), ''))",
        imphash: "LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'imphash=', 2), '|', 1), ''))",
        tlsh: "LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'tlsh=', 2), '|', 1), ''))"
      };

      params.push(hashType);
      const typeIdx = params.length;
      params.push(hashValue);
      const exactIdx = params.length;
      const noteExpr = noteExprByType[hashType];

      prefixedHashSearch = { typeIdx, exactIdx, noteExpr };
      filters.push(`(
        (observable_type = $${typeIdx} AND LOWER(observable) = $${exactIdx})
        OR (${noteExpr} = $${exactIdx})
      )`);
    } else {
      const prefixedObs = qv.match(/^(ip|ip6|ipv6|domain|url)\s*:\s*(.+)$/i);
      if (prefixedObs) {
        const obsType = prefixedObs[1].toLowerCase() === 'ip6' ? 'ipv6' : prefixedObs[1].toLowerCase();
        let obsValue = String(prefixedObs[2] || '').trim();
        if (obsType === 'domain' || obsType === 'url') obsValue = obsValue.toLowerCase();
        if (obsValue.length < 2) {
          return res.json({
            items: [],
            pagination: buildIocListPagination({
              mode: 'search',
              matchCount: 0,
              page: currentPage,
              pageSize: limit,
              statusFilter
            }),
            note: 'Observable value must be at least 2 characters'
          });
        }
        params.push(obsType, obsValue);
        const typeIdx = params.length - 1;
        const valueIdx = params.length;
        prefixedObservableSearch = { typeIdx, valueIdx };
        filters.push(obsType === 'domain' || obsType === 'url'
          ? `(observable_type = $${typeIdx} AND LOWER(observable) = $${valueIdx})`
          : `(observable_type = $${typeIdx} AND observable = $${valueIdx})`);
      } else {
        const isMd5 = /^[a-f0-9]{32}$/i.test(qv);
      const isSha1 = /^[a-f0-9]{40}$/i.test(qv);
      const isSha256 = /^[a-f0-9]{64}$/i.test(qv);
      const isTlsh = /^[a-f0-9]{70,72}$/i.test(qv);
      const isSsdeep = /^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$/.test(qv);
      const isImphash = /^[a-f0-9]{32}$/i.test(qv);
      const isHashLike = isMd5 || isSha1 || isSha256 || isTlsh || isSsdeep || isImphash;

      if (isHashLike) {
        params.push(qv.toLowerCase());
        const exactIdx = params.length;
        const regexEscaped = qv.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        params.push(`(^|\\|\\s*)(md5|sha1|sha256|ssdeep|imphash|tlsh)\\s*=\\s*${regexEscaped}(\\s*\\||$)`);
        const noteRegexIdx = params.length;

        filters.push(`(
          LOWER(observable) = $${exactIdx}
          OR COALESCE(note, '') ~* $${noteRegexIdx}
        )`);
      } else {
        params.push(`%${qv}%`);
        filters.push(`(
          observable ILIKE $${params.length}
          OR source_name ILIKE $${params.length}
          OR COALESCE(category, '') ILIKE $${params.length}
          OR COALESCE(note, '') ILIKE $${params.length}
        )`);
      }
    }
  }
  }

  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const fullScan = Boolean(source_name || confidence || (q && !prefixedHashSearch) || asn || country);
  // Filtre varken 20M+ satÄ±rda full scan Ã¶nlemek: sadece son N gÃ¼n (varsayÄ±lan 365)
  const maxAgeDays = Math.min(Math.max(Number(process.env.IOC_LIST_MAX_AGE_DAYS || 365) || 365, 30), 3650);
  const recentClause = fullScan ? ` WHERE created_at > now() - interval '1 day' * $${params.length + 1}` : '';
  const recentParam = fullScan ? maxAgeDays : null;

  if (t) t.searchStringParse = Date.now();

  const asnValueEarly = asn ? Number(asn) : null;
  const countryValueEarly = country ? `%${country}%` : null;
  const useHashFastPathEarly = prefixedHashSearch && asnValueEarly == null && countryValueEarly == null;
  const useObservableOnlyPath = prefixedObservableSearch && asnValueEarly == null && countryValueEarly == null;
  const isDefaultActiveBrowse = !hasSearch
    && browseStatusFilter === 'active'
    && !fullScan
    && classificationFilter.length === 0;

  if (isDefaultActiveBrowse) {
    if (t) t.searchStringParse = Date.now();
    try {
      const listMode = resolveIocListMode({
        q, fullScan, classificationFilter, source_name, confidence, asn, country
      });
      const globalTotal = await getCachedIocListGlobalTotal(pool, browseStatusFilter);
      const paginationMeta = buildIocListPagination({
        mode: 'browse',
        globalTotal: globalTotal ?? undefined,
        globalTotalUnknown: globalTotal == null,
        page: currentPage,
        pageSize: limit,
        statusFilter: browseStatusFilter
      });

      if (t) t.dbQueryStart = Date.now();
      const browseRows = currentPage > paginationMeta.page_count
        ? []
        : await fetchActiveIocListPage(pool, { limit, offset, browseCap: IOC_LIST_BROWSE_CAP });
      if (t) t.dbQueryEnd = Date.now();

      if (t) t.beforeResultMapping = Date.now();
      const pageItems = browseRows.map((row) => ({
        ...row,
        source_count: 0,
        source_names: [],
        confidence_set: [],
        category_set: []
      }));
      const items = await mapIocListPageItems(pool, pageItems, {
        statusFilter: browseStatusFilter,
        hasSearch: false,
        byItemIds: true
      });
      if (t) t.afterResultMapping = Date.now();

      const payload = {
        items,
        pagination: paginationMeta
      };
      if (t) {
        t.beforeJsonStringify = Date.now();
        const payloadStr = JSON.stringify(payload);
        t.afterJsonStringify = Date.now();
        t.responseBytes = Buffer.byteLength(payloadStr, 'utf8');
        t.beforeSend = Date.now();
        res.on('finish', () => {
          t.responseSent = Date.now();
          const d = (name, start, end) => (end != null && start != null ? `${name}=${end - start}ms` : '');
          const parts = [
            d('dbQuery', t.dbQueryStart, t.dbQueryEnd),
            d('resultMapping', t.beforeResultMapping, t.afterResultMapping),
            d('jsonStringify', t.beforeJsonStringify, t.afterJsonStringify),
            d('responseSent', t.beforeSend, t.responseSent),
            `total=${t.responseSent - t.requestReceived}ms`,
            'queries=2',
            `rows=${browseRows.length}`,
            `responseBytes=${t.responseBytes}`,
            'path=browse'
          ].filter(Boolean);
          console.log('[ioc/list timing]', parts.join(' '), 'q=' + (req.query?.q ?? ''));
        });
        res.setHeader('Content-Type', 'application/json');
        return res.send(payloadStr);
      }
      return res.json(payload);
    } catch (err) {
      return res.status(500).json({ message: 'Failed to fetch IOC list', detail: err.message });
    }
  }

  let client = null;
  if (t) {
    t.beforeConnect = Date.now();
    client = await pool.connect();
    t.dbConnectionAcquired = Date.now();
  }
  const db = client || pool;

  try {
    // Exact match on ioc_observables first: one table, all IOC types (md5, sha1, sha256, ip, domain, url). No type filter.
    const qv = String(q || '').trim();
    let exactObservableValue = null;
    if (q && qv.length >= 2 && asnValueEarly == null && countryValueEarly == null) {
      if (prefixedHashSearch) exactObservableValue = params[prefixedHashSearch.exactIdx - 1];
      else if (prefixedObservableSearch) exactObservableValue = params[prefixedObservableSearch.valueIdx - 1];
      else {
        const isHashLike = /^[a-f0-9]{32}$/i.test(qv) || /^[a-f0-9]{40}$/i.test(qv) || /^[a-f0-9]{64}$/i.test(qv) ||
          /^\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+$/.test(qv) || /^[a-f0-9]{70,72}$/i.test(qv);
        exactObservableValue = isHashLike ? qv.toLowerCase() : qv;
      }
    }
    // Exact observable lookups are fastest via ioc_observables index; use this
    // path for both plain and prefixed queries (including url:/domain:/ip:).
    if (exactObservableValue != null) {
      const obsLimit = Math.min(limit, 100);
      // ioc_observables (025): observable_value, ioc_public_id; join ioc_items for full row
      const obsStatusClause = iocStatusSqlClause(statusFilter, 'i');
      const obsQ = `
        SELECT i.id, i.public_id, i.observable, i.observable_type, i.source_name, i.source_url, i.confidence, i.category, i.note, i.created_at, i.status
        FROM ioc_observables o
        JOIN ioc_items i ON i.public_id = o.ioc_public_id
        WHERE o.observable_value = $1
        ${obsStatusClause ? `AND ${obsStatusClause}` : ''}
        ORDER BY i.created_at DESC
        LIMIT $2`;
      if (t) t.dbQueryStart = Date.now();
      const obsRes = await db.query(obsQ, [exactObservableValue, obsLimit]);
      if (t) t.dbQueryEnd = Date.now();
      const rows = obsRes.rows;
      if (rows.length > 0) {
        const grouped = new Map();
        for (const r of rows) {
          const key = `${r.observable_type}::${r.observable}`;
          if (!grouped.has(key)) {
            grouped.set(key, {
              id: r.id,
              public_id: r.public_id,
              observable: r.observable,
              observable_type: r.observable_type,
              ip: r.observable,
              first_seen_at: r.created_at,
              last_seen_at: r.created_at,
              status: r.status || 'active',
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.first_seen_at) g.first_seen_at = r.created_at;
          if (r.created_at > g.last_seen_at) {
            g.last_seen_at = r.created_at;
            g.status = r.status || g.status || 'active';
          }
          if (r.source_name) g._sources.add(r.source_name);
          if (r.confidence) g._conf.add(r.confidence);
          if (r.category) g._cat.add(r.category);
        }

        const pageItems = Array.from(grouped.values()).map((g) => ({
          id: g.id,
          public_id: g.public_id,
          observable: g.observable,
          observable_type: g.observable_type,
          ip: g.ip,
          status: g.status || 'active',
          first_seen_at: g.first_seen_at,
          last_seen_at: g.last_seen_at,
          source_count: g._sources.size,
          source_names: Array.from(g._sources).sort(),
          confidence_set: Array.from(g._conf).sort(),
          category_set: Array.from(g._cat).sort(),
          asn: null,
          country_code: null,
          as_name: null
        }));
        const finalItems = await mapIocListPageItems(pool, pageItems, { statusFilter, hasSearch });
        const payload = {
          items: finalItems,
          pagination: buildIocListPagination({
            mode: 'search',
            matchCount: finalItems.length,
            page: 1,
            pageSize: limit,
            statusFilter
          })
        };
        if (t) {
          t.beforeJsonStringify = Date.now();
          const payloadStr = JSON.stringify(payload);
          t.afterJsonStringify = Date.now();
          t.responseBytes = Buffer.byteLength(payloadStr, 'utf8');
          res.on('finish', () => {
            t.responseSent = Date.now();
            const d = (name, start, end) => (end != null && start != null ? `${name}=${end - start}ms` : '');
            const parts = [d('dbQuery', t.dbQueryStart, t.dbQueryEnd), `rows=${rows.length}`, 'path=ioc_observables'].filter(Boolean);
            console.log('[ioc/list timing]', parts.join(' '), 'q=' + (req.query?.q ?? ''));
          });
        }
        res.setHeader('Content-Type', 'application/json');
        return res.send(JSON.stringify(payload));
      }
    }

    // Hash-only default: single SELECT + group in Node (no CTE, no geo). Set IOC_LIST_USE_CTE_FOR_HASH=1 to use CTE.
    const useMinimalHashPath = useHashFastPathEarly && prefixedHashSearch && !IOC_LIST_USE_CTE_FOR_HASH;
    if (useMinimalHashPath) {
      // Hash search: ioc_file_hash only. Primary match (observable = $1) or note match (e.g. imphash=, ssdeep=).
      const hashValueOnly = params[prefixedHashSearch.exactIdx - 1];
      const noteExpr = prefixedHashSearch.noteExpr;
      const obsLimit = Math.max(Math.min(limit * 50, 500), 100);
      const hashStatusClause = iocStatusSqlClause(statusFilter);
      const exactHashQ = `
        SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at, status
        FROM ioc_file_hash
        WHERE observable = $1 OR (${noteExpr}) = $1
        ${hashStatusClause ? `AND ${hashStatusClause}` : ''}
        ORDER BY created_at DESC
        LIMIT $2`;
      if (t) t.dbQueryStart = Date.now();
      const simpleRes = await db.query(exactHashQ, [hashValueOnly, obsLimit]);
      if (t) t.dbQueryEnd = Date.now();
      const rows = simpleRes.rows;
      if (t) {
        t.beforeResultMapping = Date.now();
        t.beforePagination = Date.now();
      }
      const pageItems = (() => {
        if (rows.length === 0) return [];
        const grouped = new Map();
        for (const r of rows) {
          const key = `${r.observable_type}::${r.observable}`;
          if (!grouped.has(key)) {
            grouped.set(key, {
              id: r.id,
              public_id: r.public_id,
              observable: r.observable,
              observable_type: r.observable_type,
              ip: r.observable,
              first_seen_at: r.created_at,
              last_seen_at: r.created_at,
              status: r.status || 'active',
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.first_seen_at) g.first_seen_at = r.created_at;
          if (r.created_at > g.last_seen_at) {
            g.last_seen_at = r.created_at;
            g.status = r.status || g.status || 'active';
          }
          if (r.source_name) g._sources.add(r.source_name);
          if (r.confidence) g._conf.add(r.confidence);
          if (r.category) g._cat.add(r.category);
        }
        return Array.from(grouped.values()).map((g) => ({
          id: g.id,
          public_id: g.public_id,
          observable: g.observable,
          observable_type: g.observable_type,
          ip: g.ip,
          status: g.status || 'active',
          first_seen_at: g.first_seen_at,
          last_seen_at: g.last_seen_at,
          source_count: g._sources.size,
          source_names: Array.from(g._sources).sort(),
          confidence_set: Array.from(g._conf).sort(),
          category_set: Array.from(g._cat).sort(),
          asn: null,
          country_code: null,
          as_name: null
        }));
      })();
      const totalExact = pageItems.length;
      if (t) {
        t.afterPagination = Date.now();
        t.afterResultMapping = Date.now();
        t.beforeJsonSerialize = Date.now();
      }
      const finalItems = await mapIocListPageItems(pool, pageItems, { statusFilter, hasSearch });
      const payload = {
        items: finalItems,
        pagination: buildIocListPagination({
          mode: 'search',
          matchCount: totalExact,
          page: 1,
          pageSize: limit,
          statusFilter
        })
      };
      if (t) {
        t.beforeJsonStringify = Date.now();
        const payloadStr = JSON.stringify(payload);
        t.afterJsonStringify = Date.now();
        t.responseBytes = Buffer.byteLength(payloadStr, 'utf8');
        t.beforeSend = Date.now();
        res.on('finish', () => {
          t.responseSent = Date.now();
          const d = (name, start, end) => (end != null && start != null ? `${name}=${end - start}ms` : '');
          const parts = [
            d('searchStringParse', t.requestReceived, t.searchStringParse),
            t.beforeConnect != null && t.dbConnectionAcquired != null ? d('dbConnectionAcquired', t.beforeConnect, t.dbConnectionAcquired) : '',
            d('dbQuery', t.dbQueryStart, t.dbQueryEnd),
            d('paginationLogic', t.beforePagination, t.afterPagination),
            d('resultMapping', t.beforeResultMapping, t.afterResultMapping),
            d('jsonStringify', t.beforeJsonStringify, t.afterJsonStringify),
            d('responseSent', t.beforeSend, t.responseSent),
            `total=${t.responseSent - t.requestReceived}ms`,
            `queries=1`,
            `rows=${rows.length}`,
            `responseBytes=${t.responseBytes}`
          ].filter(Boolean);
          console.log('[ioc/list timing]', parts.join(' '), 'path=exactHash', 'q=' + (req.query?.q ?? ''));
        });
        res.setHeader('Content-Type', 'application/json');
        return res.send(payloadStr);
      }
      return res.json(payload);
    }

    if (useObservableOnlyPath) {
      const obsType = params[prefixedObservableSearch.typeIdx - 1];
      const obsValue = params[prefixedObservableSearch.valueIdx - 1];
      const partitionTable = { ip: 'ioc_ip', ipv6: 'ioc_ipv6', domain: 'ioc_domain', url: 'ioc_url' }[obsType];
      const whereClause = (obsType === 'domain' || obsType === 'url') ? 'LOWER(observable) = $1' : 'observable = $1';
      const obsLimit = Math.max(Math.min(limit * 50, 500), 100);
      const partStatusClause = iocStatusSqlClause(statusFilter);
      const obsQ = `
        SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at, status
        FROM ${partitionTable}
        WHERE ${whereClause}
        ${partStatusClause ? `AND ${partStatusClause}` : ''}
        ORDER BY created_at DESC
        LIMIT $2`;
      if (t) t.dbQueryStart = Date.now();
      const obsRes = await db.query(obsQ, [obsValue, obsLimit]);
      if (t) t.dbQueryEnd = Date.now();
      const rows = obsRes.rows;
      const pageItems = (() => {
        if (rows.length === 0) return [];
        const grouped = new Map();
        for (const r of rows) {
          const key = `${r.observable_type}::${r.observable}`;
          if (!grouped.has(key)) {
            grouped.set(key, {
              id: r.id,
              public_id: r.public_id,
              observable: r.observable,
              observable_type: r.observable_type,
              ip: r.observable,
              first_seen_at: r.created_at,
              last_seen_at: r.created_at,
              status: r.status || 'active',
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.first_seen_at) g.first_seen_at = r.created_at;
          if (r.created_at > g.last_seen_at) {
            g.last_seen_at = r.created_at;
            g.status = r.status || g.status || 'active';
          }
          if (r.source_name) g._sources.add(r.source_name);
          if (r.confidence) g._conf.add(r.confidence);
          if (r.category) g._cat.add(r.category);
        }
        return Array.from(grouped.values()).map((g) => ({
          id: g.id,
          public_id: g.public_id,
          observable: g.observable,
          observable_type: g.observable_type,
          ip: g.ip,
          status: g.status || 'active',
          first_seen_at: g.first_seen_at,
          last_seen_at: g.last_seen_at,
          source_count: g._sources.size,
          source_names: Array.from(g._sources).sort(),
          confidence_set: Array.from(g._conf).sort(),
          category_set: Array.from(g._cat).sort(),
          asn: null,
          country_code: null,
          as_name: null
        }));
      })();
      const finalItems = await mapIocListPageItems(pool, pageItems, { statusFilter, hasSearch });
      const payload = {
        items: finalItems,
        pagination: buildIocListPagination({
          mode: 'search',
          matchCount: finalItems.length,
          page: 1,
          pageSize: limit,
          statusFilter
        })
      };
      if (t) {
        t.beforeJsonStringify = Date.now();
        const payloadStr = JSON.stringify(payload);
        t.afterJsonStringify = Date.now();
        t.responseBytes = Buffer.byteLength(payloadStr, 'utf8');
        res.on('finish', () => {
          t.responseSent = Date.now();
          const d = (name, start, end) => (end != null && start != null ? `${name}=${end - start}ms` : '');
          const parts = [
            d('dbQuery', t.dbQueryStart, t.dbQueryEnd),
            `total=${t.responseSent - t.requestReceived}ms`,
            'path=partition'
          ].filter(Boolean);
          console.log('[ioc/list timing]', parts.join(' '), 'q=' + (req.query?.q ?? ''));
        });
      }
      res.setHeader('Content-Type', 'application/json');
      return res.send(JSON.stringify(payload));
    }

    // Literal observable_type for prefixed hash so PostgreSQL uses concrete plan and index (avoids generic plan).
    const hashTypeLiteral = prefixedHashSearch && ['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh'].includes(params[prefixedHashSearch.typeIdx - 1])
      ? params[prefixedHashSearch.typeIdx - 1]
      : null;
    const sourceSql = prefixedHashSearch && hashTypeLiteral
      ? `SELECT id, public_id, observable, observable_type, source_name, confidence, category, threat_classification, threat_actor_id, note, created_at, status
         FROM ioc_items
         WHERE (
           (observable_type = '${hashTypeLiteral}' AND LOWER(observable) = $1)
           OR (${prefixedHashSearch.noteExpr} = $1)
         )`
      : prefixedHashSearch
      ? `SELECT id, public_id, observable, observable_type, source_name, confidence, category, threat_classification, threat_actor_id, note, created_at, status
         FROM ioc_items
         WHERE (
           (observable_type = $${prefixedHashSearch.typeIdx} AND LOWER(observable) = $${prefixedHashSearch.exactIdx})
           OR (${prefixedHashSearch.noteExpr} = $${prefixedHashSearch.exactIdx})
         )`
      : fullScan
        ? `SELECT id, public_id, observable, observable_type, source_name, confidence, category, threat_classification, threat_actor_id, note, created_at, status FROM ioc_items${recentClause} ORDER BY created_at DESC LIMIT ${IOC_LIST_BROWSE_CAP}`
        : `SELECT id, public_id, observable, observable_type, source_name, confidence, category, threat_classification, threat_actor_id, note, created_at, status
           FROM ioc_items
           ORDER BY created_at DESC
           LIMIT ${IOC_LIST_BROWSE_CAP}`;

    const scopedGroupSql = !hasSearch && browseStatusFilter === 'active'
      ? `, scoped AS (
          SELECT * FROM grouped g
          WHERE ${activeObservableHasActiveSourceSql('g.observable', 'g.observable_type')}
        )`
      : ', scoped AS (SELECT * FROM grouped g)';

    const base = `
      WITH combined AS (
        ${sourceSql}
      ), filtered AS (
        SELECT * FROM combined
        ${where}
      ), grouped AS (
        SELECT
          MIN(id)::int AS id,
          (ARRAY_AGG(public_id ORDER BY id ASC))[1]::text AS public_id,
          observable,
          observable_type,
          MIN(created_at) AS first_seen_at,
          MAX(created_at) AS last_seen_at,
          (ARRAY_AGG(COALESCE(status, 'active') ORDER BY created_at DESC))[1] AS status,
          COUNT(*)::int AS source_count,
          ARRAY_AGG(DISTINCT source_name ORDER BY source_name) AS source_names,
          ARRAY_AGG(DISTINCT confidence ORDER BY confidence) AS confidence_set,
          ARRAY_AGG(DISTINCT COALESCE(category, '') ORDER BY COALESCE(category, '')) FILTER (WHERE category IS NOT NULL AND category <> '') AS category_set,
          (ARRAY_AGG(threat_classification ORDER BY id ASC))[1] AS threat_classification,
          (ARRAY_AGG(threat_actor_id ORDER BY id ASC))[1] AS threat_actor_id
        FROM filtered
        GROUP BY observable, observable_type
      )${scopedGroupSql}
    `;

    const asnValue = asn ? Number(asn) : null;
    const countryValue = country ? `%${country}%` : null;
    const numBase = params.length + (fullScan ? 1 : 0);
    const geoJoin = `LEFT JOIN ioc_ip_geo_cache c ON c.ip = CASE WHEN g.observable_type = 'ip' THEN g.observable::inet ELSE NULL END`;
    const geoWhere = `($${numBase + 1}::int IS NULL OR c.asn = $${numBase + 1}) AND ($${numBase + 2}::text IS NULL OR c.country_code ILIKE $${numBase + 2})`;

    // Fast path: prefixed hash (sha256:/md5:/sha1:) with no asn/country filter â†’ skip geo join (hash results are not IPs).
    const useHashFastPath = prefixedHashSearch && asnValue == null && countryValue == null;
    const hashLiteralParams = useHashFastPath && hashTypeLiteral ? [params[prefixedHashSearch.exactIdx - 1]] : null;
    const listQ = useHashFastPath
      ? `
      ${base}
      SELECT g.id, g.public_id, g.observable, g.observable_type, g.observable AS ip, g.first_seen_at, g.last_seen_at, g.status,
             g.source_count,
             g.source_names, g.confidence_set, g.category_set, g.threat_classification, g.threat_actor_id,
             NULL::bigint AS asn, NULL::text AS country_code, NULL::text AS as_name,
             COUNT(*) OVER()::int AS total
      FROM scoped g
      ORDER BY g.last_seen_at DESC
      LIMIT $${hashLiteralParams ? 2 : params.length + 1}
      OFFSET $${hashLiteralParams ? 3 : params.length + 2}
    `
      : `
      ${base}
      , with_geo AS (
        SELECT g.*, g.observable AS ip, c.asn, c.country_code, c.as_name,
               COUNT(*) OVER()::int AS total
        FROM scoped g
        ${geoJoin}
        WHERE ${geoWhere}
      )
      SELECT id, public_id, observable, observable_type, ip, first_seen_at, last_seen_at, status, source_count,
             source_names, confidence_set, category_set, threat_classification, threat_actor_id,
             asn, country_code, as_name, total
      FROM with_geo
      ORDER BY last_seen_at DESC
      LIMIT $${numBase + 3}
      OFFSET $${numBase + 4}
    `;

    const listParams = useHashFastPath
      ? (hashLiteralParams ? [...hashLiteralParams, limit, offset] : [...params, limit, offset])
      : (fullScan ? [...params, recentParam, asnValue, countryValue, limit, offset] : [...params, asnValue, countryValue, limit, offset]);
    if (t) t.dbQueryStart = Date.now();
    const listRes = await db.query(listQ, listParams);
    if (t) t.dbQueryEnd = Date.now();
    let total = listRes.rows[0]?.total ?? null;
    if (total === null && listRes.rows.length === 0) {
      const countQ = useHashFastPath
        ? `${base} SELECT COUNT(*)::int AS total FROM scoped g`
        : `
        ${base}
        SELECT COUNT(*)::int AS total
        FROM scoped g
        ${geoJoin}
        WHERE ${geoWhere}
      `;
      const countParams = useHashFastPath ? (hashLiteralParams ? hashLiteralParams : [...params]) : (fullScan ? [...params, recentParam, asnValue, countryValue] : [...params, asnValue, countryValue]);
      if (t) t.countQueryStart = Date.now();
      const countRes = await db.query(countQ, countParams);
      if (t) t.countQueryEnd = Date.now();
      total = countRes.rows[0]?.total ?? 0;
    } else if (total === null) {
      total = listRes.rows.length;
    }
    if (t) t.beforeResultMapping = Date.now();
    const itemsRaw = listRes.rows.map(({ total: _drop, ...row }) => row);
    const items = await mapIocListPageItems(pool, itemsRaw, { statusFilter, hasSearch });
    if (t) t.afterResultMapping = Date.now();
    if (t) t.beforeJsonSerialize = Date.now();

    const payload = {
      items,
      pagination: await (async () => {
        const listMode = resolveIocListMode({
          q, fullScan, classificationFilter, source_name, confidence, asn, country
        });
        if (listMode === 'search') {
          return buildIocListPagination({
            mode: 'search',
            matchCount: total,
            page: currentPage,
            pageSize: limit,
            statusFilter
          });
        }
        const globalTotal = await getCachedIocListGlobalTotal(pool, browseStatusFilter);
        return buildIocListPagination({
          mode: listMode,
          globalTotal,
          page: currentPage,
          pageSize: limit,
          statusFilter: browseStatusFilter
        });
      })()
    };
    if (fullScan && recentParam) {
      payload.note = `Filtered list limited to last ${recentParam} days (IOC_LIST_MAX_AGE_DAYS).`;
    }
    if (t) {
      t.beforeJsonStringify = Date.now();
      const payloadStr = JSON.stringify(payload);
      t.afterJsonStringify = Date.now();
      t.responseBytes = Buffer.byteLength(payloadStr, 'utf8');
      t.beforeSend = Date.now();
      res.on('finish', () => {
        t.responseSent = Date.now();
        const d = (name, start, end) => (end != null && start != null ? `${name}=${end - start}ms` : '');
        const queryCount = t.countQueryStart != null && t.countQueryEnd != null ? 2 : 1;
        const parts = [
          d('searchStringParse', t.requestReceived, t.searchStringParse),
          t.beforeConnect != null && t.dbConnectionAcquired != null ? d('dbConnectionAcquired', t.beforeConnect, t.dbConnectionAcquired) : '',
          d('dbQuery', t.dbQueryStart, t.dbQueryEnd),
          t.countQueryStart != null && t.countQueryEnd != null ? d('countQuery', t.countQueryStart, t.countQueryEnd) : '',
          d('resultMapping', t.beforeResultMapping, t.afterResultMapping),
          d('jsonStringify', t.beforeJsonStringify, t.afterJsonStringify),
          d('responseSent', t.beforeSend, t.responseSent),
          `total=${t.responseSent - t.requestReceived}ms`,
          `queries=${queryCount}`,
          `responseBytes=${t.responseBytes}`
        ].filter(Boolean);
        console.log('[ioc/list timing]', parts.join(' '), 'path=cte', 'q=' + (req.query?.q ?? ''));
      });
      res.setHeader('Content-Type', 'application/json');
      return res.send(payloadStr);
    }
    return res.json(payload);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch IOC list', detail: err.message });
  } finally {
    if (client) client.release();
  }
}

app.get('/api/ioc/list', handleIocList);

app.get('/api/ioc/ip/sources', async (req, res) => {
  const { ip } = req.query;
  if (!ip) {
    return res.status(400).json({ message: 'ip is required' });
  }

  try {
    const detailsQ = `
      SELECT
        id,
        observable AS ip,
        source_name,
        source_url,
        confidence,
        category,
        note,
        created_at
      FROM ioc_items
      WHERE observable_type='ip' AND observable = $1
      ORDER BY created_at DESC
    `;
    const { rows } = await pool.query(detailsQ, [ip]);
    return res.json({ ip, sources: rows });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch source details', detail: err.message });
  }
});

app.get('/api/ioc/observable/sources', async (req, res) => {
  const observable = String(req.query?.observable || '').trim();
  const observableType = String(req.query?.type || '').trim();
  if (!observable) {
    return res.status(400).json({ message: 'observable is required' });
  }

  try {
    const params = [observable];
    let typeFilter = '';
    if (observableType) {
      params.push(observableType);
      typeFilter = ' AND observable_type = $2 ';
    }

    const itemRes = await pool.query(
      `SELECT id, public_id, observable, observable_type, source_name, source_url,
              confidence, category, note, created_at, status, ioc_source_id
       FROM ioc_items
       WHERE observable = $1
       ${typeFilter}
       ORDER BY created_at DESC
       LIMIT 500`,
      params
    );
    const rows = itemRes.rows || [];
    if (!rows.length) {
      return res.json({ observable, observable_type: observableType || null, sources: [] });
    }

    const seedRow = rows[0];
    const iocItemIds = rows.map((r) => Number(r.id)).filter((id) => Number.isFinite(id));
    const membershipSummary = await fetchObservableMembershipSummary(pool, {
      observable: seedRow.observable,
      observableType: seedRow.observable_type,
      iocItemIds
    });
    const evidenceRows = await fetchFeedSourceEvidenceForItems(pool, {
      iocItemIds,
      observableType: seedRow.observable_type
    });
    const sources = buildIocDetailsSourceEvidence({
      iocRows: rows,
      membershipSummary,
      evidenceRows
    });

    return res.json({ observable, observable_type: observableType || seedRow.observable_type || null, sources });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch observable source details', detail: err.message });
  }
});

app.get('/api/ioc/details/resolve', async (req, res) => {
  const observable = String(req.query?.observable || '').trim();
  const observableType = String(req.query?.type || '').trim();

  if (!observable) {
    return res.status(400).json({ message: 'observable is required' });
  }

  try {
    const params = [observable];
    let typeFilter = '';
    if (observableType) {
      params.push(observableType);
      typeFilter = ` AND observable_type = $2 `;
    }

    const q = `
      SELECT MIN(public_id)::text AS public_id
      FROM ioc_items
      WHERE observable = $1
      ${typeFilter}
    `;
    const { rows } = await pool.query(q, params);
    const publicId = rows[0]?.public_id || null;
    return res.json({ public_id: publicId });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to resolve IOC detail id', detail: err.message });
  }
});



app.get('/api/ioc/:id/suppression', async (req, res) => {
  if (!canReadSuppression(req)) return res.status(403).json({ message: 'Forbidden' });
  const iocId = parsePositiveInt(req.params?.id);
  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  try {
    const iocQ = await pool.query('SELECT observable, observable_type FROM ioc_items WHERE id = $1 LIMIT 1', [iocId]);
    if (!iocQ.rowCount) return res.status(404).json({ message: 'IOC not found' });
    const iocValue = String(iocQ.rows[0].observable || '').trim();
    const iocType = String(iocQ.rows[0].observable_type || '').trim();
    const supQ = await pool.query(
      `SELECT id, active, scope, source_name, reason, created_by, created_at, updated_at, expires_at, deleted_at
       FROM ioc_suppressions
       WHERE lower(ioc_value) = lower($1)
         AND lower(ioc_type) = lower($2)
         AND active = TRUE
         AND deleted_at IS NULL
         AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY created_at DESC
       LIMIT 1`,
      [iocValue, iocType]
    );
    if (!supQ.rowCount) return res.json({ status: 'not_suppressed', suppression: null });
    return res.json({ status: 'suppressed', suppression: supQ.rows[0] });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch suppression', detail: err.message });
  }
});

app.post('/api/ioc/:id/suppress', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const iocId = parsePositiveInt(req.params?.id);
  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  const scope = String(req.body?.scope || 'global').trim().toLowerCase();
  const sourceName = req.body?.source_name == null ? null : String(req.body.source_name).trim();
  const reason = String(req.body?.reason || '').trim();
  const expiresAtRaw = req.body?.expires_at;
  if (!reason) return res.status(400).json({ message: 'reason is required' });
  if (scope !== 'global') return res.status(400).json({ message: 'Only global scope is supported in phase-1' });
  const expiresAt = expiresAtRaw ? new Date(expiresAtRaw) : null;
  if (expiresAtRaw && Number.isNaN(expiresAt.getTime())) return res.status(400).json({ message: 'Invalid expires_at' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const iocQ = await client.query('SELECT observable, observable_type FROM ioc_items WHERE id = $1 LIMIT 1', [iocId]);
    if (!iocQ.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'IOC not found' });
    }
    const iocValue = String(iocQ.rows[0].observable || '').trim();
    const iocType = String(iocQ.rows[0].observable_type || '').trim();
    const createdBy = String(req.user?.email || req.user?.username || '').trim() || null;

    const upsertQ = await client.query(
      `INSERT INTO ioc_suppressions (ioc_value, ioc_type, scope, source_name, reason, created_by, expires_at, active, updated_at)
       VALUES ($1, $2, 'global', NULL, $3, $4, $5, TRUE, NOW())
       ON CONFLICT (lower(ioc_value), lower(ioc_type), scope, COALESCE(lower(source_name), ''))
         WHERE deleted_at IS NULL
       DO UPDATE SET reason = EXCLUDED.reason,
                     created_by = COALESCE(EXCLUDED.created_by, ioc_suppressions.created_by),
                     expires_at = EXCLUDED.expires_at,
                     active = TRUE,
                     deleted_at = NULL,
                     deleted_by = NULL,
                     updated_at = NOW()
       RETURNING *`,
      [iocValue, iocType, reason, createdBy, expiresAt ? expiresAt.toISOString() : null]
    );

    await client.query('COMMIT');
    const suppression = upsertQ.rows[0];
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.IOC_SUPPRESSION_CREATED,
      entityType: AUDIT_ENTITY.IOC_SUPPRESSION,
      entityId: String(suppression.id),
      entityDisplay: `${iocValue} (${iocType})`,
      severity: AUDIT_SEVERITY.WARNING,
      after: {
        ioc_value: suppression.ioc_value,
        ioc_type: suppression.ioc_type,
        scope: suppression.scope,
        reason: suppression.reason,
        expires_at: suppression.expires_at
      },
      metadata: { ioc_id: iocId, created_by: createdBy }
    }).catch((e) => console.warn('[audit] suppression create log failed', e?.message || e));
    await recomputeIocsForSuppression(iocValue, iocType);
    return res.json({ status: 'suppressed', suppression });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(500).json({ message: 'Failed to suppress IOC', detail: err.message });
  } finally {
    client.release();
  }
});

app.delete('/api/ioc/:id/suppress', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const iocId = parsePositiveInt(req.params?.id);
  if (!iocId) return res.status(400).json({ message: 'Invalid IOC id' });
  const reasonCheck = parseActionReason(req.body);
  if (!reasonCheck.ok) return res.status(400).json({ message: reasonCheck.message });
  try {
    const iocQ = await pool.query('SELECT observable, observable_type FROM ioc_items WHERE id = $1 LIMIT 1', [iocId]);
    if (!iocQ.rowCount) return res.status(404).json({ message: 'IOC not found' });
    const iocValue = String(iocQ.rows[0].observable || '').trim();
    const iocType = String(iocQ.rows[0].observable_type || '').trim();

    const q = await pool.query(
      `UPDATE ioc_suppressions
       SET active = FALSE, updated_at = NOW()
       WHERE lower(ioc_value) = lower($1)
         AND lower(ioc_type) = lower($2)
         AND active = TRUE
         AND deleted_at IS NULL
       RETURNING *`,
      [iocValue, iocType]
    );
    for (const row of q.rows || []) {
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.IOC_SUPPRESSION_DISABLED,
        entityType: AUDIT_ENTITY.IOC_SUPPRESSION,
        entityId: String(row.id),
        entityDisplay: `${row.ioc_value} (${row.ioc_type})`,
        severity: AUDIT_SEVERITY.WARNING,
        before: { active: true, status: 'active', reason: row.reason },
        after: { active: false, status: 'disabled' },
        metadata: {
          ioc_id: iocId,
          ioc_value: row.ioc_value,
          ioc_type: row.ioc_type,
          suppression_id: row.id,
          previous_status: 'active',
          new_status: 'disabled',
          reason: reasonCheck.reason
        }
      }).catch((e) => console.warn('[audit] suppression disable log failed', e?.message || e));
    }
    if (q.rowCount) await recomputeIocsForSuppression(iocValue, iocType);
    return res.json({ ok: true, updated: q.rowCount || 0 });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to disable suppression', detail: err.message });
  }
});

app.post('/api/ioc-suppressions', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const result = await createManualSuppression(pool, req.body || {}, {
    req,
    user: req.user,
    audit: auditLogService
  });
  return res.status(result.status).json(result.body);
});

app.get('/api/ioc-suppressions', async (req, res) => {
  if (!canReadSuppression(req)) return res.status(403).json({ message: 'Forbidden' });
  const page = Math.max(1, Number(req.query?.page || 1));
  const pageSize = Math.min(100, Math.max(1, Number(req.query?.pageSize || 25)));
  const offset = (page - 1) * pageSize;
  const search = String(req.query?.search || '').trim();
  const iocType = String(req.query?.ioc_type || '').trim().toLowerCase();
  const scope = String(req.query?.scope || '').trim().toLowerCase();
  const activeParam = String(req.query?.active || '').trim().toLowerCase();
  const expires = String(req.query?.expires || 'all').trim().toLowerCase();
  const statusFilter = normalizeSuppressionStatusFilter(req.query?.status || '');
  const createdBy = String(req.query?.created_by || '').trim();

  // Non-status filters shared by the list, count, and summary-stats queries so
  // the summary cards show true global counts (not page-level) for the current
  // search/type filters, independent of the selected status tab.
  const filterWhere = ['s.deleted_at IS NULL'];
  const filterParams = [];
  if (search) { filterParams.push(`%${search.toLowerCase()}%`); filterWhere.push(`(lower(s.ioc_value) LIKE $${filterParams.length} OR lower(COALESCE(s.reason,'')) LIKE $${filterParams.length})`); }
  if (iocType) { filterParams.push(iocType); filterWhere.push(`lower(s.ioc_type) = $${filterParams.length}`); }
  if (scope && scope !== 'all') { filterParams.push(scope); filterWhere.push(`lower(s.scope) = $${filterParams.length}`); }
  if (createdBy) { filterParams.push(`%${createdBy.toLowerCase()}%`); filterWhere.push(`lower(COALESCE(s.created_by,'')) LIKE $${filterParams.length}`); }

  const where = [...filterWhere];
  const params = [...filterParams];

  if (statusFilter === 'active') {
    where.push('s.active = TRUE AND (s.expires_at IS NULL OR s.expires_at > NOW())');
  } else if (statusFilter === 'disabled') {
    where.push('s.active = FALSE');
  } else if (statusFilter === 'expired') {
    where.push('s.active = TRUE AND s.expires_at IS NOT NULL AND s.expires_at <= NOW()');
  } else {
    if (activeParam === 'true' || activeParam === 'false') {
      params.push(activeParam === 'true');
      where.push(`s.active = $${params.length}`);
    }
    if (expires === 'active') where.push('s.active = TRUE AND (s.expires_at IS NULL OR s.expires_at > NOW())');
    if (expires === 'expired') where.push('s.active = TRUE AND s.expires_at IS NOT NULL AND s.expires_at <= NOW()');
  }

  const sort = String(req.query?.sort || 'created_at_desc').trim();
  const orderBy = sort === 'created_at_asc' ? 's.created_at ASC' : sort === 'expires_at_asc' ? 's.expires_at ASC NULLS LAST' : sort === 'ioc_value_asc' ? 's.ioc_value ASC' : 's.created_at DESC';

  try {
    params.push(pageSize, offset);
    const baseWhere = where.join(' AND ');
    const q = await pool.query(
      `SELECT s.*,
              ${SUPPRESSION_STATUS_CASE_SQL} AS status
       FROM ioc_suppressions s
       WHERE ${baseWhere}
       ORDER BY ${orderBy}
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    const countParams = params.slice(0, -2);
    const cq = await pool.query(`SELECT COUNT(*)::int AS total FROM ioc_suppressions s WHERE ${baseWhere}`, countParams);

    // Global summary counts across the current non-status filters.
    const statsWhere = filterWhere.join(' AND ');
    const sq = await pool.query(
      `SELECT
         COUNT(*) FILTER (WHERE s.active = TRUE AND (s.expires_at IS NULL OR s.expires_at > NOW()))::int AS active,
         COUNT(*) FILTER (WHERE s.active = FALSE)::int AS disabled,
         COUNT(*) FILTER (WHERE s.active = TRUE AND s.expires_at IS NOT NULL AND s.expires_at <= NOW())::int AS expired,
         COUNT(*)::int AS total
       FROM ioc_suppressions s
       WHERE ${statsWhere}`,
      filterParams
    );
    const statsRow = sq.rows?.[0] || {};
    const stats = {
      active: Number(statsRow.active || 0),
      disabled: Number(statsRow.disabled || 0),
      expired: Number(statsRow.expired || 0),
      total: Number(statsRow.total || 0)
    };
    return res.json({ items: q.rows || [], total: Number(cq.rows?.[0]?.total || 0), page, pageSize, stats });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch IOC suppressions', detail: err.message });
  }
});

app.patch('/api/ioc-suppressions/:id', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const id = parsePositiveInt(req.params?.id);
  if (!id) return res.status(400).json({ message: 'Invalid id' });
  const reasonRaw = req.body?.reason;
  const expiresAtRaw = req.body?.expires_at;
  const activeRaw = req.body?.active !== undefined ? req.body.active : req.body?.enabled;
  const sets = ['updated_at = NOW()'];
  const params = [id];
  let nextActive = null;
  if (reasonRaw !== undefined) {
    const reason = String(reasonRaw || '').trim();
    if (!reason) return res.status(400).json({ message: 'reason is required' });
    params.push(reason); sets.push(`reason = $${params.length}`);
  }
  if (expiresAtRaw !== undefined) {
    if (expiresAtRaw === null || String(expiresAtRaw).trim() === '') {
      sets.push('expires_at = NULL');
    } else {
      const d = new Date(expiresAtRaw);
      if (Number.isNaN(d.getTime())) return res.status(400).json({ message: 'Invalid expires_at' });
      params.push(d.toISOString()); sets.push(`expires_at = $${params.length}::timestamptz`);
    }
  }
  if (activeRaw !== undefined) {
    const active = activeRaw === true || activeRaw === 'true' || activeRaw === 1 || activeRaw === '1';
    if (typeof activeRaw === 'boolean' || ['true', 'false', '1', '0'].includes(String(activeRaw))) {
      nextActive = active;
      params.push(active); sets.push(`active = $${params.length}`);
    } else {
      return res.status(400).json({ message: 'active must be boolean' });
    }
  }
  if (sets.length === 1) return res.status(400).json({ message: 'No fields to update' });
  try {
    const beforeQ = await pool.query('SELECT * FROM ioc_suppressions WHERE id = $1 AND deleted_at IS NULL', [id]);
    if (!beforeQ.rowCount) return res.status(404).json({ message: 'Suppression not found' });
    const before = beforeQ.rows[0];
    const activeChanged = nextActive !== null && Boolean(before.active) !== Boolean(nextActive);
    // Idempotent enable/disable: no-op when active already matches and nothing else changes
    if (nextActive !== null && !activeChanged && reasonRaw === undefined && expiresAtRaw === undefined) {
      const status = computeSuppressionEffectiveStatus(before);
      return res.json({ item: { ...before, status }, noop: true });
    }
    const q = await pool.query(`UPDATE ioc_suppressions SET ${sets.join(', ')} WHERE id = $1 AND deleted_at IS NULL RETURNING *`, params);
    if (!q.rowCount) return res.status(404).json({ message: 'Suppression not found' });
    const after = q.rows[0];
    const prevStatus = computeSuppressionEffectiveStatus(before);
    const newStatus = computeSuppressionEffectiveStatus(after);
    const reasonUnchanged = reasonRaw === undefined || String(before.reason || '') === String(after.reason || '');
    const expBefore = before.expires_at ? new Date(before.expires_at).toISOString() : null;
    const expAfter = after.expires_at ? new Date(after.expires_at).toISOString() : null;
    const expiresUnchanged = expiresAtRaw === undefined || expBefore === expAfter;
    if (!activeChanged && reasonUnchanged && expiresUnchanged) {
      return res.json({ item: { ...after, status: newStatus }, noop: true });
    }
    let auditAction = AUDIT_ACTION.IOC_SUPPRESSION_UPDATED;
    if (activeChanged && nextActive) auditAction = AUDIT_ACTION.IOC_SUPPRESSION_ENABLED;
    else if (activeChanged && !nextActive) auditAction = AUDIT_ACTION.IOC_SUPPRESSION_DISABLED;
    await auditLogService.auditSuccess({
      req,
      action: auditAction,
      entityType: AUDIT_ENTITY.IOC_SUPPRESSION,
      entityId: String(id),
      entityDisplay: `${after.ioc_value} (${after.ioc_type})`,
      severity: AUDIT_SEVERITY.INFO,
      before: { reason: before.reason, expires_at: before.expires_at, active: before.active, status: prevStatus },
      after: { reason: after.reason, expires_at: after.expires_at, active: after.active, status: newStatus },
      metadata: {
        suppression_id: after.id,
        ioc_value: after.ioc_value,
        ioc_type: after.ioc_type,
        scope: after.scope,
        source_name: after.source_name,
        previous_status: prevStatus,
        new_status: newStatus,
        previous_expiration: before.expires_at,
        new_expiration: after.expires_at,
        reason: after.reason
      }
    }).catch((e) => console.warn('[audit] suppression update log failed', e?.message || e));
    if (activeChanged || prevStatus !== newStatus) {
      await recomputeIocsForSuppression(after.ioc_value, after.ioc_type);
    }
    return res.json({ item: { ...after, status: newStatus } });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update suppression', detail: err.message });
  }
});

app.delete('/api/ioc-suppressions/:id', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const id = parsePositiveInt(req.params?.id);
  if (!id) return res.status(400).json({ message: 'Invalid id' });
  const reasonCheck = parseActionReason(req.body);
  if (!reasonCheck.ok) return res.status(400).json({ message: reasonCheck.message });
  try {
    const beforeQ = await pool.query('SELECT * FROM ioc_suppressions WHERE id = $1 AND deleted_at IS NULL', [id]);
    if (!beforeQ.rowCount) return res.status(404).json({ message: 'Suppression not found' });
    const before = beforeQ.rows[0];
    const deletedBy = String(req.user?.email || req.user?.username || '').trim() || null;
    const q = await pool.query(
      `UPDATE ioc_suppressions
       SET active = FALSE,
           deleted_at = NOW(),
           deleted_by = $2,
           updated_at = NOW()
       WHERE id = $1 AND deleted_at IS NULL
       RETURNING *`,
      [id, deletedBy]
    );
    if (!q.rowCount) return res.status(404).json({ message: 'Suppression not found' });
    const after = q.rows[0];
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.IOC_SUPPRESSION_DELETED,
      entityType: AUDIT_ENTITY.IOC_SUPPRESSION,
      entityId: String(id),
      entityDisplay: `${after.ioc_value} (${after.ioc_type})`,
      severity: AUDIT_SEVERITY.WARNING,
      before: {
        active: before.active,
        reason: before.reason,
        expires_at: before.expires_at,
        status: computeSuppressionEffectiveStatus(before)
      },
      after: { active: false, deleted_at: after.deleted_at, status: 'deleted' },
      metadata: {
        suppression_id: id,
        ioc_value: after.ioc_value,
        ioc_type: after.ioc_type,
        scope: after.scope,
        source_name: after.source_name,
        previous_status: computeSuppressionEffectiveStatus(before),
        new_status: 'deleted',
        reason: reasonCheck.reason
      }
    }).catch((e) => console.warn('[audit] suppression delete log failed', e?.message || e));
    await recomputeIocsForSuppression(after.ioc_value, after.ioc_type);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to delete suppression', detail: err.message });
  }
});

app.get('/api/ioc/details', async (req, res) => {
  const requestedPublicId = String(req.query?.public_id || '').trim();

  if (!requestedPublicId) {
    return res.status(400).json({ message: 'public_id is required' });
  }

  const startedAt = Date.now();
  let pgMs = 0;
  let chMs = 0;

  const cached = iocDetailsCache.get(requestedPublicId);
  if (cached && cached.expiresAt > Date.now()) {
    console.log(`[perf][ioc-details] public_id=${requestedPublicId} cache=hit total_ms=${Date.now() - startedAt} pg_ms=0 ch_ms=0`);
    return res.json(cached.payload);
  }
  if (cached) iocDetailsCache.delete(requestedPublicId);

  try {
    const confidenceColumnsReady = await hasIocConfidenceColumns(pool);
    const provenanceColumnsReady = await hasConfidenceProvenanceColumns(pool);
    const confidenceSelect = iocConfidenceSelectSql(confidenceColumnsReady, provenanceColumnsReady);
    const confidenceJoin = iocConfidenceJoinSql(confidenceColumnsReady, provenanceColumnsReady);

    const itemQ = `
      WITH seed AS (
        SELECT observable, observable_type
        FROM ioc_items
        WHERE public_id = $1::uuid
        LIMIT 1
      )
      SELECT
        i.id,
        i.public_id,
        i.observable,
        i.observable_type,
        i.source_name,
        i.source_url,
        i.confidence,
        i.status,
        i.expires_at,
        i.expired_at,
        i.expiration_reason,
        i.reactivated_by_match_at,
        i.threat_classification,
        i.threat_actor_id,
        ta.name AS threat_actor_name,
        tc.name AS threat_classification_label,
        tc.active AS threat_classification_active,
        i.manual_status_override,
        i.manual_status,
        ${confidenceSelect}
        i.category,
        i.note,
        i.created_at,
        i.first_seen_at AS item_first_seen_at,
        i.last_seen_at AS item_last_seen_at
      FROM ioc_items i
      INNER JOIN seed s
        ON i.observable = s.observable
       AND (s.observable_type IS NULL OR i.observable_type = s.observable_type)
      ${confidenceJoin}
      LEFT JOIN threat_actors ta ON ta.id = i.threat_actor_id
      LEFT JOIN threat_classifications tc ON tc.slug = i.threat_classification
      ORDER BY i.created_at DESC
      LIMIT 500
    `;

    const tItem = Date.now();
    const itemRes = await pool.query(itemQ, [requestedPublicId]);
    pgMs += Date.now() - tItem;

    const rows = itemRes.rows;
    if (!rows.length) {
      const payload = { summary: null, sources: [], matches: [], incidents: [], impact: null };
      iocDetailsCache.set(requestedPublicId, { expiresAt: Date.now() + IOC_DETAILS_CACHE_TTL_MS, payload });
      console.log(`[perf][ioc-details] public_id=${requestedPublicId} cache=miss total_ms=${Date.now() - startedAt} pg_ms=${pgMs} ch_ms=${chMs} rows=0 matches=0`);
      return res.json(payload);
    }

    const seedRow = rows.find((r) => String(r.public_id || '') === requestedPublicId) || rows[0];
    const lifecycleRow = pickIocLifecycleRow(rows, seedRow);
    const observable = seedRow.observable;
    const observableType = seedRow.observable_type;

    const signalRawExpr = 'NULL';

    const geoIp = extractIpv4ForGeo(observable, observableType);

    const geoPromise = (async () => {
      if (!geoIp) return { ip: null, asn: null, country_code: null, as_name: null };
      const geoQ = `
        SELECT
          host(i.ip) AS ip,
          COALESCE(c.asn::text, e.asn) AS asn,
          COALESCE(NULLIF(c.country_code, 'UN'), e.country_code) AS country_code,
          COALESCE(c.as_name, e.as_name) AS as_name
        FROM (SELECT $1::inet AS ip) i
        LEFT JOIN ioc_ip_geo_cache c ON c.ip = i.ip
        LEFT JOIN ioc_ip_enrichment e ON e.ip = host(i.ip)
        LIMIT 1
      `;
      const tGeo = Date.now();
      const geoRes = await pool.query(geoQ, [geoIp]);
      pgMs += Date.now() - tGeo;
      if (!geoRes.rows[0]) return { ip: geoIp, asn: null, country_code: null, as_name: null };
      return {
        ip: geoRes.rows[0].ip || geoIp,
        asn: geoRes.rows[0].asn ?? null,
        country_code: geoRes.rows[0].country_code || null,
        as_name: geoRes.rows[0].as_name || null
      };
    })();

    const [geo] = await Promise.all([geoPromise]);

    const incidents = [];
    const impact = null;

    const iocItemIds = rows.map((r) => Number(r.id)).filter((id) => Number.isFinite(id));
    const membershipSummary = await fetchObservableMembershipSummary(pool, {
      observable,
      observableType,
      iocItemIds
    });
    const evidenceRows = await fetchFeedSourceEvidenceForItems(pool, {
      iocItemIds,
      observableType
    });
    const sourceEvidence = buildIocDetailsSourceEvidence({
      iocRows: rows,
      membershipSummary,
      evidenceRows
    });

    // Global expiration = MAX effective expires_at across active sources.
    // Each active source's expires_at is already the effective value (policy or custom override,
    // set by computeMembershipFieldPatch). If any active source has no expiration (null), the IOC
    // is indefinitely active on that source so the global is also null. Falls back to
    // lifecycleRow when there are no active sources (e.g. all-expired or manual-only IOC).
    let globalExpiresAt = lifecycleRow.expires_at || null;
    if (membershipSummary.activeSources.length > 0) {
      if (membershipSummary.activeSources.some((s) => !s.expires_at)) {
        globalExpiresAt = null;
      } else {
        globalExpiresAt = membershipSummary.activeSources
          .map((s) => s.expires_at)
          .reduce((max, d) => !max || new Date(d) > new Date(max) ? d : max, null);
      }
    }

    // next_expiration_at = earliest expires_at among active sources (for analyst awareness).
    // Unlike global expires_at (MAX), this shows when the FIRST source will drop off.
    const datedActiveSources = membershipSummary.activeSources.map((s) => s.expires_at).filter(Boolean);
    const nextExpirationAt = datedActiveSources.length
      ? datedActiveSources.reduce((min, d) => !min || new Date(d) < new Date(min) ? d : min, null)
      : null;

    // expired_source_count = memberships whose status is exactly 'expired' (not purged/removed).
    const expiredSourceCount = membershipSummary.historicalMemberships
      .filter((m) => String(m.status || '').toLowerCase() === 'expired').length;

    // highest_active_source_confidence = best feed/entry confidence ignoring analyst override.
    // Computed from active memberships so expired sources never inflate this value.
    const highestActiveSourceConfidence = (() => {
      const activeMems = membershipSummary.membershipRows.filter(
        (m) => String(m.status || 'active').toLowerCase() === 'active' && !m.purged_at
      );
      if (!activeMems.length) return null;
      const result = computeInheritedEffectiveConfidence({ memberships: activeMems });
      return result?.effective || null;
    })();

    // analyst_intelligence_summary: impact counts for IOC detail overview badge.
    let analystIntelligenceSummary = { total_count: 0, supports_malicious_count: 0, supports_benign_count: 0, needs_review_count: 0, context_only_count: 0 };
    try {
      const iocIds = [...new Set(rows.map((r) => r.id).filter((id) => Number.isFinite(Number(id))))];
      if (iocIds.length) {
        const aiQ = await pool.query(
          `SELECT
             COUNT(*)::int AS total_count,
             COUNT(*) FILTER (WHERE assessment_impact = 'supports_malicious')::int AS supports_malicious_count,
             COUNT(*) FILTER (WHERE assessment_impact = 'supports_benign')::int AS supports_benign_count,
             COUNT(*) FILTER (WHERE assessment_impact = 'needs_review')::int AS needs_review_count,
             COUNT(*) FILTER (WHERE assessment_impact = 'context_only')::int AS context_only_count
           FROM ioc_analyst_intelligence
           WHERE ioc_id = ANY($1::bigint[])
             AND deleted_at IS NULL`,
          [iocIds]
        );
        if (aiQ.rows[0]) analystIntelligenceSummary = aiQ.rows[0];
      }
    } catch (_e) {
      // Non-fatal â€” analyst intelligence table may not exist in older migrations
    }

    const totalSourceMembershipCount = membershipSummary.activeSourceCount + membershipSummary.historicalSourceCount;

    // Global first/last seen: prefer feed membership timestamps over ioc_items.created_at.
    // first_seen_in_feed is set from the feed's own date_added (e.g. URLhaus dateAdded),
    // not our import time â€” so it can predate created_at and is the correct analyst-facing value.
    const globalFirstSeenAt = (() => {
      const mDates = membershipSummary.membershipRows.map((m) => m.first_seen_in_feed).filter(Boolean);
      if (mDates.length) return mDates.reduce((min, d) => new Date(d) < new Date(min) ? d : min);
      const iDates = rows.map((r) => r.item_first_seen_at || r.created_at).filter(Boolean);
      return iDates.length ? iDates.reduce((min, d) => new Date(d) < new Date(min) ? d : min) : null;
    })();

    // Analyst-visible "last changed", not "last polled". Uses last_changed_in_source so
    // an unchanged re-import cannot advance it; falls back to first_seen_in_feed for
    // rows predating migration 121. Must NOT read last_seen_in_feed (technical presence).
    const globalLastSeenAt = (() => {
      const mDates = membershipSummary.membershipRows
        .map((m) => m.last_changed_in_source || m.first_seen_in_feed)
        .filter(Boolean);
      if (mDates.length) return mDates.reduce((max, d) => new Date(d) > new Date(max) ? d : max);
      const iDates = rows.map((r) => r.item_last_seen_at || r.created_at).filter(Boolean);
      return iDates.length ? iDates.reduce((max, d) => new Date(d) > new Date(max) ? d : max) : null;
    })();

    const rawFeedIntelligence = buildFeedIntelligence(evidenceRows);
    let feedIntelligence = rawFeedIntelligence;
    try {
      const overrides = await listActiveSourceTagOverrides(pool, seedRow.id);
      feedIntelligence = applySourceTagOverrides(rawFeedIntelligence, overrides);
    } catch (err) {
      if (String(err?.message || '').includes('ioc_source_tag_overrides')) {
        console.warn('[ioc-details] source tag overrides unavailable:', err.message);
      } else {
        throw err;
      }
    }

    const summary = {
      id: seedRow.id,
      public_id: seedRow.public_id,
      observable,
      observable_type: seedRow.observable_type,
      status: lifecycleRow.status || null,
      expires_at: globalExpiresAt,
      next_expiration_at: nextExpirationAt,
      expiration_summary: buildIocExpirationSummary({
        activeSources: membershipSummary.activeSources,
        historicalMemberships: membershipSummary.historicalMemberships,
        globalExpiresAt
      }),
      expired_at: lifecycleRow.expired_at || null,
      expiration_reason: lifecycleRow.expiration_reason || null,
      reactivated_by_match_at: lifecycleRow.reactivated_by_match_at || null,
      ...(await buildThreatMetadataFields(pool, lifecycleRow)),
      manual_status_override: Boolean(lifecycleRow.manual_status_override),
      manual_status: lifecycleRow.manual_status || null,
      first_seen_at: globalFirstSeenAt,
      last_seen_at: globalLastSeenAt,
      // source_count kept for backward compat but now equals total_source_membership_count
      source_count: totalSourceMembershipCount,
      total_source_membership_count: totalSourceMembershipCount,
      active_source_count: membershipSummary.activeSourceCount,
      expired_source_count: expiredSourceCount,
      historical_source_count: membershipSummary.historicalSourceCount,
      highest_active_source_confidence: highestActiveSourceConfidence,
      analyst_confidence_override: normalizeIocConfidence(seedRow.analyst_confidence_override) || null,
      source_names: membershipSummary.activeSourceNames,
      category_set: [...new Set(rows.map((r) => r.category).filter(Boolean))],
      geo,
      file_information: buildFileInformation(rows, observable, rows[0].observable_type, evidenceRows),
      feed_intelligence: feedIntelligence
    };

    let confidenceDetail = null;
    if (confidenceColumnsReady) {
      confidenceDetail = await buildIocConfidenceSummaryForDetails(pool, {
        rows,
        seedPublicId: requestedPublicId
      });
    } else {
      confidenceDetail = buildIocConfidenceSummary({
        rows,
        seedPublicId: requestedPublicId,
        feedNamesByKey: new Map()
      });
    }
    if (!confidenceDetail?.effective && seedRow?.confidence) {
      const hasSourceEvidence = membershipSummary.activeSourceCount > 0
        || membershipSummary.historicalSourceCount > 0;
      if (hasSourceEvidence) {
        const itemStored = computeItemStoredConfidence(seedRow);
        if (itemStored) {
          confidenceDetail = {
            ...(confidenceDetail || {}),
            ...itemStored,
            confidence: itemStored.effective,
            confidence_level: itemStored.effective,
            source: itemStored.confidence_source,
            source_description: buildConfidenceSourceDescription(
              itemStored.confidence_source,
              itemStored.confidence_source_name,
              { scope: confidenceDetail?.confidence_source_scope || 'active' }
            )
          };
        } else {
          confidenceDetail = {
            ...(confidenceDetail || {}),
            effective: String(seedRow.confidence).toLowerCase(),
            confidence: String(seedRow.confidence).toLowerCase(),
            confidence_level: String(seedRow.confidence).toLowerCase(),
            confidence_source: 'manual_entry',
            source: 'manual_entry',
            source_description: buildConfidenceSourceDescription('manual_entry', null)
          };
        }
      }
    } else if (
      confidenceDetail
      && (confidenceDetail.source === 'unknown' || confidenceDetail.confidence_source === 'unknown')
      && seedRow?.confidence
      && (membershipSummary.activeSourceCount > 0 || membershipSummary.historicalSourceCount > 0)
    ) {
      const itemStored = computeItemStoredConfidence(seedRow);
      if (itemStored?.effective) {
        confidenceDetail = {
          ...confidenceDetail,
          effective: itemStored.effective,
          confidence: itemStored.effective,
          confidence_level: itemStored.effective,
          confidence_source: itemStored.confidence_source,
          confidence_ioc_source_id: itemStored.confidence_ioc_source_id,
          confidence_source_name: itemStored.confidence_source_name,
          source: itemStored.confidence_source,
          source_description: buildConfidenceSourceDescription(
            itemStored.confidence_source,
            itemStored.confidence_source_name,
            { scope: confidenceDetail?.confidence_source_scope || 'active' }
          )
        };
      }
    }
    if (confidenceDetail && !confidenceDetail.confidence_provenance) {
      confidenceDetail.confidence_provenance = buildConfidenceProvenance(confidenceDetail);
    }

    summary.confidence = confidenceDetail?.effective || seedRow?.confidence || null;
    summary.source_name = seedRow?.source_name || null;
    summary.confidence_detail = confidenceDetail;
    summary.confidence_set = confidenceDetail?.confidence_set
      || [...new Set(rows.map((r) => r.confidence).filter(Boolean))];

    const suppressionQ = await pool.query(
      `SELECT id, active, scope, source_name, reason, created_by, created_at, updated_at, expires_at
       FROM ioc_suppressions
       WHERE lower(ioc_value) = lower($1)
         AND lower(ioc_type) = lower($2)
         AND active = TRUE
         AND deleted_at IS NULL
         AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY created_at DESC
       LIMIT 1`,
      [observable, observableType]
    );
    const activeSuppression = suppressionQ.rowCount ? suppressionQ.rows[0] : null;

    // Augment confidence detail with highest_active_source_confidence so the UI
    // can show provenance separately from the effective value when analyst override is active.
    const enrichedConfidenceDetail = confidenceDetail
      ? { ...confidenceDetail, highest_active_source_confidence: highestActiveSourceConfidence }
      : null;

    const payload = {
      summary,
      confidence: enrichedConfidenceDetail,
      sources: sourceEvidence,
      historical_ioc_rows: rows.filter((r) => String(r.status || 'active') !== 'active'),
      active_sources: membershipSummary.activeSources,
      historical_sources: membershipSummary.historicalSources,
      feed_memberships: membershipSummary.membershipRows,
      matches: [],
      incidents,
      impact,
      analyst_intelligence_summary: analystIntelligenceSummary,
      suppression: activeSuppression ? { ...activeSuppression, active: true } : { active: false }
    };

    iocDetailsCache.set(requestedPublicId, { expiresAt: Date.now() + IOC_DETAILS_CACHE_TTL_MS, payload });
    console.log(`[perf][ioc-details] public_id=${requestedPublicId} cache=miss total_ms=${Date.now() - startedAt} pg_ms=${pgMs} ch_ms=${chMs} rows=${rows.length} incidents=${incidents.length}`);

    return res.json(payload);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch IOC details', detail: err.message });
  }
});

app.get('/api/ioc/recent', async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit || 10), 1), 100);

  try {
    const q = `
      SELECT
        i.id,
        i.public_id,
        i.observable,
        i.observable_type,
        i.source_name,
        COALESCE(s.name, i.source_name) AS source_label,
        i.confidence,
        i.category,
        i.created_at,
        i.expires_at,
        c.asn,
        c.country_code,
        c.as_name
      FROM ioc_items i
      LEFT JOIN ioc_sources s ON s.id = i.ioc_source_id
      LEFT JOIN ioc_ip_geo_cache c ON c.ip = CASE WHEN i.observable_type = 'ip' THEN i.observable::inet ELSE NULL END
      ORDER BY i.created_at DESC
      LIMIT ($1)
    `;

    const { rows } = await pool.query(q, [limit]);
    return res.json({ items: rows });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch recent IOC records', detail: err.message });
  }
});

app.get('/api/ioc/map/countries', async (_req, res) => {
  return res.status(410).json({ message: 'Threat World Map feature removed' });
});

app.get('/api/ioc/summary/today', async (req, res) => {
  try {
    const statusFilter = parseIocListStatusFilter(req.query.status ?? 'active');
    const lastUpdate = await fetchIocStatsLastUpdate(pool);
    const cacheKey = buildIocStatsCacheKey(statusFilter, lastUpdate);

    const cached = readIocStatsCache(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    const stats = await fetchIocListStats(pool, statusFilter);
    const payload = {
      last_update: lastUpdate,
      total: stats.total,
      unique_ips: Number(stats.by_type.find((r) => r.observable_type === 'ip')?.count || 0),
      by_source: stats.by_source,
      by_confidence: [],
      by_type: stats.by_type
    };

    writeIocStatsCache(cacheKey, payload);
    return res.json(payload);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch summary', detail: err.message });
  }
});

async function handleIocListStatsGet(_req, res) {
  try {
    const snapshot = await getIocListStatsSnapshot(pool);
    if (!snapshot) {
      queueIocListStatsRefresh(pool).catch((err) => {
        console.error('[ioc/stats] background refresh failed', err?.message || err);
      });
      return res.json(formatIocListStatsApiResponse(null));
    }
    if (snapshot.stale && !isIocListStatsRefreshInProgress()) {
      queueIocListStatsRefresh(pool).catch((err) => {
        console.error('[ioc/stats] stale refresh failed', err?.message || err);
      });
    }
    return res.json(formatIocListStatsApiResponse(snapshot));
  } catch (err) {
    console.error('[ioc/stats] failed', err);
    return res.status(500).json({ message: 'Failed to fetch IOC stats', detail: err.message });
  }
}

app.get('/api/ioc/stats', handleIocListStatsGet);
app.get('/api/iocs/stats', handleIocListStatsGet);

app.post('/api/ioc/stats/refresh', requireRole(ROLES.ADMIN, ROLES.ANALYST), async (req, res) => {
  try {
    if (isIocListStatsRefreshInProgress()) {
      return res.status(202).json({
        ok: true,
        status: 'in_progress',
        queued: false,
        in_progress: true,
        message: 'IOC stats refresh is already running.'
      });
    }
    queueIocListStatsRefresh(pool, { force: false }).catch((err) => {
      console.error('[ioc/stats] manual refresh failed', err?.message || err);
    });
    return res.status(202).json({
      ok: true,
      status: 'queued',
      queued: true,
      in_progress: true,
      message: 'IOC stats refresh started. Updated stats will appear shortly.'
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to queue IOC stats refresh', detail: err.message });
  }
});


async function ensureSeedDemoUser() {
  try {
    const hash = await bcrypt.hash(demoPassword, 12);
    await pool.query(
      `INSERT INTO users (username, password_hash, first_name, last_name, role)
       VALUES ($1, $2, 'Demo', 'User', 'admin'::app_user_role)
       ON CONFLICT (username) DO NOTHING`,
      [String(demoEmail || '').trim(), hash]
    );
  } catch (err) {
    console.warn('[users] demo seed skipped:', err.message);
  }
}

const PUBLISHED_FEED_TICK_MS = Math.max(Number(process.env.PUBLISHED_FEED_TICK_MS || 5 * 60 * 1000), 15 * 1000);
const IOC_LIST_STATS_REFRESH_MS = Math.max(Number(process.env.IOC_LIST_STATS_REFRESH_MS || IOC_LIST_STATS_CACHE_TTL_MS), 60 * 60 * 1000);
let publishedFeedTickInProgress = false;
let iocListStatsRefreshScheduled = false;

async function runIocListStatsRefreshTick() {
  if (iocListStatsRefreshScheduled || isIocListStatsRefreshInProgress()) return;
  iocListStatsRefreshScheduled = true;
  try {
    const snap = await getIocListStatsSnapshot(pool);
    if (snap && !snap.stale) return;
    await queueIocListStatsRefresh(pool);
  } catch (err) {
    console.error('[ioc-list-stats] scheduled refresh failed', err?.message || err);
  } finally {
    iocListStatsRefreshScheduled = false;
  }
}

const VT_TTL_HOURS = Math.max(1, Number(process.env.VIRUSTOTAL_ENRICHMENT_TTL_HOURS || 24));
const VT_TIMEOUT_MS = Math.max(3000, Number(process.env.VIRUSTOTAL_TIMEOUT_MS || 12000));

async function getThreatIntelProviderConfig(provider = VT_PROVIDER) {
  const envKey = String(process.env.VIRUSTOTAL_API_KEY || '').trim();
  const rowRes = await pool.query(`SELECT provider, enabled, api_key, ttl_hours, timeout_ms, last_test_at, last_success_at, last_error_at, last_error_message FROM threat_intel_provider_configs WHERE provider=$1 LIMIT 1`, [provider]);
  const row = rowRes.rows[0] || null;
  const dbKey = String(row?.api_key || '').trim();
  const apiKey = dbKey || envKey;
  return {
    provider,
    enabled: row?.enabled !== false,
    ttl_hours: Math.max(1, Number(row?.ttl_hours || process.env.VIRUSTOTAL_ENRICHMENT_TTL_HOURS || 24)),
    timeout_ms: Math.max(3000, Number(row?.timeout_ms || process.env.VIRUSTOTAL_TIMEOUT_MS || 12000)),
    apiKey,
    configured: Boolean(apiKey),
    source: dbKey ? 'db' : (envKey ? 'env' : 'none'),
    last_test_at: row?.last_test_at || null,
    last_success_at: row?.last_success_at || null,
    last_error_at: row?.last_error_at || null,
    last_error_message: row?.last_error_message || null
  };
}

function maskApiKey(k) {
  const s = String(k || '');
  if (!s) return null;
  const tail = s.slice(-4);
  return `************${tail}`;
}

function toVtUrlId(raw) {
  const b64 = Buffer.from(String(raw || ''), 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return b64;
}

function normalizeVtSummary(iocValue, iocType, payload) {
  const attr = payload?.data?.attributes || {};
  const stats = attr.last_analysis_stats || {};
  const detected = Number(stats.malicious || 0) + Number(stats.suspicious || 0);
  const total = Object.values(stats).reduce((n, v) => n + Number(v || 0), 0);
  const categoryOrder = { malicious: 1, suspicious: 2, harmless: 3, undetected: 4, timeout: 5 };
  const vendorResults = Object.entries(attr.last_analysis_results || {})
    .map(([key, v]) => ({
      engine: String(v?.engine_name || key || '').trim() || key,
      category: v?.category || null,
      result: v?.result || null,
      method: v?.method || null
    }))
    .sort((a, b) => (categoryOrder[a.category] || 99) - (categoryOrder[b.category] || 99));

  const engines = vendorResults
    .filter((v) => v.category === 'malicious' || v.category === 'suspicious')
    .slice(0, 5)
    .map((v) => ({ engine: v.engine, category: v.category, result: v.result }));

  return {
    provider: VT_PROVIDER,
    ioc_value: iocValue,
    ioc_type: iocType,
    permalink: payload?.data?.links?.self || null,
    last_analysis_date: attr.last_analysis_date ? new Date(Number(attr.last_analysis_date) * 1000).toISOString() : null,
    stats: {
      malicious: Number(stats.malicious || 0), suspicious: Number(stats.suspicious || 0), harmless: Number(stats.harmless || 0), undetected: Number(stats.undetected || 0), timeout: Number(stats.timeout || 0)
    },
    detection_ratio: { detected, total },
    reputation: Number.isFinite(Number(attr.reputation)) ? Number(attr.reputation) : null,
    top_engines: engines,
    vendor_results: vendorResults,
    domain: { registrar: attr.registrar || null, categories: Object.values(attr.categories || {}) },
    ip: { asn: attr.asn || null, country: attr.country || null, network: attr.network || null, owner: attr.as_owner || null },
    url: { final_url: attr.last_final_url || null, title: attr.title || null, last_final_url: attr.last_final_url || null },
    file: { sha256: attr.sha256 || null, names: Array.isArray(attr.names) ? attr.names.slice(0, 10) : [], type_description: attr.type_description || null }
  };
}

app.get('/api/ioc/:id/enrichments/virustotal', async (req, res) => {
  try {
    const iocId = Number(req.params.id);
    if (!Number.isFinite(iocId) || iocId <= 0) return res.status(400).json({ message: 'Invalid IOC id' });
    const providerCfg = await getThreatIntelProviderConfig(VT_PROVIDER);
    const keyConfigured = Boolean(providerCfg.apiKey);
    if (!keyConfigured) return res.json({ status: 'api_key_missing' });
    const q = `SELECT status, normalized_summary, error_message, fetched_at, expires_at FROM ioc_enrichments WHERE provider=$1 AND ioc_id=$2 LIMIT 1`;
    const r = await pool.query(q, [VT_PROVIDER, iocId]);
    if (!r.rowCount) return res.json({ status: 'not_found' });
    const row = r.rows[0];
    if (row.status === 'not_found') {
      return res.json(buildVtNotIndexedResponse({
        fetched_at: row.fetched_at,
        expires_at: row.expires_at
      }));
    }
    return res.json({
      status: row.status,
      provider: VT_PROVIDER,
      summary: row.normalized_summary,
      error_message: row.error_message,
      fetched_at: row.fetched_at,
      expires_at: row.expires_at,
      is_error: row.status === 'error'
    });
  } catch {
    return res.status(500).json({ message: 'Failed to fetch VirusTotal enrichment' });
  }
});

app.post('/api/ioc/:id/enrichments/virustotal/refresh', async (req, res) => {
  const iocId = Number(req.params.id);
  if (!Number.isFinite(iocId) || iocId <= 0) return res.status(400).json({ message: 'Invalid IOC id' });

  let item = null;
  let iocType = null;

  try {
    const providerCfg = await getThreatIntelProviderConfig(VT_PROVIDER);
    const vtKey = providerCfg.apiKey;
    if (!vtKey) return res.status(400).json({ status: 'api_key_missing', message: 'VirusTotal API key is not configured' });

    const itemRes = await pool.query(`SELECT id, observable AS ioc_value, lower(observable_type) AS ioc_type FROM ioc_items WHERE id=$1 LIMIT 1`, [iocId]);
    if (!itemRes.rowCount) return res.status(404).json({ message: 'IOC not found' });
    item = itemRes.rows[0];
    iocType = item.ioc_type === 'file_hash' ? 'hash' : item.ioc_type;

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.VT_ENRICHMENT_REQUESTED,
      entityType: AUDIT_ENTITY.ENRICHMENT,
      entityId: item.ioc_value,
      entityDisplay: item.ioc_value,
      severity: AUDIT_SEVERITY.INFO,
      metadata: {
        provider: VT_PROVIDER,
        observable_type: iocType,
        observable_value: item.ioc_value,
        ioc_id: iocId,
        source_page: 'ioc_detail_intelligence'
      }
    }).catch(() => {});

    let endpoint = '';
    if (iocType === 'ip' || iocType === 'ipv6') endpoint = `/ip_addresses/${encodeURIComponent(item.ioc_value)}`;
    else if (iocType === 'domain') endpoint = `/domains/${encodeURIComponent(item.ioc_value)}`;
    else if (iocType === 'url') endpoint = `/urls/${toVtUrlId(item.ioc_value)}`;
    else if (iocType === 'hash' || iocType === 'sha256' || iocType === 'sha1' || iocType === 'md5') endpoint = `/files/${encodeURIComponent(item.ioc_value)}`;
    else return res.status(400).json({ message: 'IOC type not supported for VirusTotal enrichment' });

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), providerCfg.timeout_ms || VT_TIMEOUT_MS);
    let vtRes;
    try {
      vtRes = await fetch(`https://www.virustotal.com/api/v3${endpoint}`, { headers: { 'x-apikey': vtKey }, signal: ctrl.signal });
    } finally { clearTimeout(t); }

    if (vtRes.status === 429) {
      const msg = vtHttpErrorMessage(429);
      await auditLogService.auditFailure({
        req,
        action: AUDIT_ACTION.VT_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: item.ioc_value,
        entityDisplay: item.ioc_value,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { provider: VT_PROVIDER, observable_type: iocType, observable_value: item.ioc_value, ioc_id: iocId, error_message: msg }
      }).catch(() => {});
      return res.status(429).json({ status: 'error', provider: VT_PROVIDER, message: msg, is_error: true });
    }
    if (isVtResourceNotFound(vtRes.status)) {
      const fetchedAt = new Date();
      const expiresAt = new Date(fetchedAt.getTime() + (providerCfg.ttl_hours || VT_TTL_HOURS) * 3600 * 1000);
      const payload = buildVtNotIndexedResponse({
        fetched_at: fetchedAt.toISOString(),
        expires_at: expiresAt.toISOString()
      });
      await pool.query(
        `INSERT INTO ioc_enrichments (ioc_id,ioc_value,ioc_type,provider,status,normalized_summary,raw_response,error_message,fetched_at,expires_at,updated_at)
         VALUES ($1,$2,$3,$4,'not_found',NULL,NULL,$5,$6,$7,NOW())
         ON CONFLICT (provider,ioc_value,ioc_type) DO UPDATE SET
           ioc_id=EXCLUDED.ioc_id,
           status='not_found',
           normalized_summary=NULL,
           raw_response=NULL,
           error_message=EXCLUDED.error_message,
           fetched_at=EXCLUDED.fetched_at,
           expires_at=EXCLUDED.expires_at,
           updated_at=NOW()`,
        [iocId, item.ioc_value, iocType, VT_PROVIDER, VT_NOT_INDEXED_MESSAGE, fetchedAt.toISOString(), expiresAt.toISOString()]
      );
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.VT_ENRICHMENT_NOT_INDEXED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: item.ioc_value,
        entityDisplay: item.ioc_value,
        severity: AUDIT_SEVERITY.INFO,
        metadata: {
          provider: VT_PROVIDER,
          observable_type: iocType,
          observable_value: item.ioc_value,
          ioc_id: iocId,
          http_status: 404,
          message: VT_NOT_INDEXED_MESSAGE
        }
      }).catch(() => {});
      return res.json(payload);
    }
    if (vtRes.status === 401 || vtRes.status === 403) {
      const msg = vtHttpErrorMessage(vtRes.status);
      await auditLogService.auditFailure({
        req,
        action: AUDIT_ACTION.VT_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: item.ioc_value,
        entityDisplay: item.ioc_value,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { provider: VT_PROVIDER, observable_type: iocType, observable_value: item.ioc_value, ioc_id: iocId, error_message: msg, http_status: vtRes.status }
      }).catch(() => {});
      return res.status(502).json({ status: 'error', provider: VT_PROVIDER, message: msg, is_error: true });
    }
    if (!vtRes.ok) {
      const msg = vtHttpErrorMessage(vtRes.status);
      await auditLogService.auditFailure({
        req,
        action: AUDIT_ACTION.VT_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: item.ioc_value,
        entityDisplay: item.ioc_value,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: { provider: VT_PROVIDER, observable_type: iocType, observable_value: item.ioc_value, ioc_id: iocId, error_message: msg, http_status: vtRes.status }
      }).catch(() => {});
      return res.status(502).json({ status: 'error', provider: VT_PROVIDER, message: msg, is_error: true });
    }

    const raw = await vtRes.json();
    const summary = normalizeVtSummary(item.ioc_value, iocType, raw);
    const fetchedAt = new Date();
    const expiresAt = new Date(fetchedAt.getTime() + (providerCfg.ttl_hours || VT_TTL_HOURS) * 3600 * 1000);
    await pool.query(`INSERT INTO ioc_enrichments (ioc_id,ioc_value,ioc_type,provider,status,normalized_summary,raw_response,error_message,fetched_at,expires_at,updated_at)
      VALUES ($1,$2,$3,$4,'success',$5,$6,NULL,$7,$8,NOW())
      ON CONFLICT (provider,ioc_value,ioc_type) DO UPDATE SET ioc_id=EXCLUDED.ioc_id,status='success',normalized_summary=EXCLUDED.normalized_summary,raw_response=EXCLUDED.raw_response,error_message=NULL,fetched_at=EXCLUDED.fetched_at,expires_at=EXCLUDED.expires_at,updated_at=NOW()`,
      [iocId, item.ioc_value, iocType, VT_PROVIDER, summary, raw, fetchedAt.toISOString(), expiresAt.toISOString()]);

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.VT_ENRICHMENT_COMPLETED,
      entityType: AUDIT_ENTITY.ENRICHMENT,
      entityId: item.ioc_value,
      entityDisplay: item.ioc_value,
      severity: AUDIT_SEVERITY.INFO,
      metadata: {
        provider: VT_PROVIDER,
        observable_type: iocType,
        observable_value: item.ioc_value,
        ioc_id: iocId,
        cached: false,
        malicious: summary?.stats?.malicious ?? null,
        suspicious: summary?.stats?.suspicious ?? null,
        undetected: summary?.stats?.undetected ?? null,
        harmless: summary?.stats?.harmless ?? null,
        vt_object_type: summary?.ioc_type ?? iocType
      }
    }).catch(() => {});

    return res.json({ status: 'success', provider: VT_PROVIDER, is_error: false, summary, fetched_at: fetchedAt.toISOString(), expires_at: expiresAt.toISOString() });
  } catch (err) {
    const msg = String(err?.name) === 'AbortError' ? 'VirusTotal enrichment timed out' : 'VirusTotal enrichment failed';
    if (item?.ioc_value) {
      await auditLogService.auditFailure({
        req,
        action: AUDIT_ACTION.VT_ENRICHMENT_FAILED,
        entityType: AUDIT_ENTITY.ENRICHMENT,
        entityId: item.ioc_value,
        entityDisplay: item.ioc_value,
        severity: AUDIT_SEVERITY.WARNING,
        metadata: {
          provider: VT_PROVIDER,
          observable_type: iocType,
          observable_value: item.ioc_value,
          ioc_id: iocId,
          error_message: msg
        }
      }).catch(() => {});
    }
    if (String(err?.name) === 'AbortError') {
      return res.status(504).json({ status: 'error', provider: VT_PROVIDER, message: 'VirusTotal enrichment timed out', is_error: true });
    }
    return res.status(500).json({ status: 'error', provider: VT_PROVIDER, message: 'VirusTotal enrichment failed', is_error: true });
  }
});

app.get('/api/admin/enrichment-providers', async (req, res) => {
  try {
    const cfg = await getThreatIntelProviderConfig(VT_PROVIDER);
    let status = 'not_configured';
    if (cfg.configured && cfg.last_error_at && (!cfg.last_success_at || new Date(cfg.last_error_at) > new Date(cfg.last_success_at))) status = 'error';
    else if (cfg.configured && cfg.last_success_at) status = 'healthy';
    else if (cfg.configured) status = 'configured';

    const ipinfo = await getIpinfoLiteConfig(pool);
    let ipinfoStatus = 'not_configured';
    if (ipinfo.configured && ipinfo.last_error_at && (!ipinfo.last_success_at || new Date(ipinfo.last_error_at) > new Date(ipinfo.last_success_at))) ipinfoStatus = 'error';
    else if (ipinfo.configured && ipinfo.last_success_at) ipinfoStatus = 'healthy';
    else if (ipinfo.configured) ipinfoStatus = 'configured';

    const abuseipdb = await getAbuseIpdbConfig(pool);
    let abuseStatus = 'not_configured';
    if (!abuseipdb.enabled && abuseipdb.configured) abuseStatus = 'disabled';
    else if (abuseipdb.configured && abuseipdb.last_error_at && (!abuseipdb.last_success_at || new Date(abuseipdb.last_error_at) > new Date(abuseipdb.last_success_at))) abuseStatus = 'error';
    else if (abuseipdb.configured && abuseipdb.last_success_at) abuseStatus = 'healthy';
    else if (abuseipdb.configured) abuseStatus = 'configured';

    return res.json({ providers: [
      {
        provider: VT_PROVIDER,
        name: 'VirusTotal',
        enabled: cfg.enabled,
        configured: cfg.configured,
        masked_key: maskApiKey(cfg.apiKey),
        source: cfg.source,
        ttl_hours: cfg.ttl_hours,
        timeout_ms: cfg.timeout_ms,
        status,
        last_test_at: cfg.last_test_at,
        last_success_at: cfg.last_success_at,
        last_error_at: cfg.last_error_at,
        last_error_message: cfg.last_error_message
      },
      {
        provider: ipinfo.provider_key,
        name: ipinfo.display_name,
        enabled: ipinfo.enabled,
        configured: ipinfo.configured,
        masked_key: ipinfo.token_masked,
        source: ipinfo.source,
        base_url: ipinfo.base_url,
        timeout_seconds: ipinfo.timeout_seconds,
        status: ipinfoStatus,
        last_test_at: ipinfo.last_test_at,
        last_success_at: ipinfo.last_success_at,
        last_error_at: ipinfo.last_error_at,
        last_error_message: ipinfo.last_error_message
      },
      {
        provider: abuseipdb.provider_key,
        name: abuseipdb.display_name,
        enabled: abuseipdb.enabled,
        configured: abuseipdb.configured,
        masked_key: abuseipdb.api_key_masked,
        source: abuseipdb.source,
        cache_ttl_hours: abuseipdb.cache_ttl_hours,
        timeout_ms: abuseipdb.timeout_ms,
        max_age_days: abuseipdb.max_age_days,
        verbose: abuseipdb.verbose,
        status: abuseStatus,
        last_test_at: abuseipdb.last_test_at,
        last_success_at: abuseipdb.last_success_at,
        last_error_at: abuseipdb.last_error_at,
        last_error_message: abuseipdb.last_error_message
      },
      getRdapProviderAdminSummary(),
      getDnsmaniaProviderAdminSummary(),
      await (async () => {
        const sdCfg = await getSpamhausDropConfig(pool);
        const sdState = await getSpamhausDropSyncState(pool);
        const v4 = sdState.find((s) => s.list_type === 'drop_v4');
        const v6 = sdState.find((s) => s.list_type === 'drop_v6');
        const lastSuccess = [v4?.last_success_at, v6?.last_success_at].filter(Boolean)
          .reduce((a, b) => (a && new Date(a) > new Date(b) ? a : b), null);
        const anyFailed = [v4?.status, v6?.status].some((s) => s === 'failed');
        const allHealthy = [v4?.status, v6?.status].every((s) => s === 'healthy');
        const sdStatus = !sdCfg.enabled ? 'disabled'
          : !lastSuccess ? 'never_synced'
          : anyFailed ? 'error'
          : allHealthy ? 'healthy'
          : 'running';
        return {
          provider: 'spamhaus_drop',
          name: 'Spamhaus DROP',
          enabled: sdCfg.enabled,
          configured: true,
          sync_interval_hours: sdCfg.sync_interval_hours,
          timeout_ms: sdCfg.timeout_ms,
          status: sdStatus,
          last_success_at: lastSuccess,
          sync_state: sdState
        };
      })(),
    ]});
  } catch { return res.status(500).json({ message: 'Failed to load enrichment providers' }); }
});

app.put('/api/admin/enrichment-providers/virustotal', async (req, res) => {
  try {
    const enabled = req.body?.enabled !== false;
    const ttl = Math.max(1, Number(req.body?.ttl_hours || 24));
    const timeout = Math.max(3000, Number(req.body?.timeout_ms || 12000));
    const apiKey = typeof req.body?.api_key === 'string' ? req.body.api_key.trim() : undefined;
    await pool.query(`INSERT INTO threat_intel_provider_configs(provider,enabled,ttl_hours,timeout_ms,api_key,updated_at)
      VALUES ($1,$2,$3,$4,$5,NOW())
      ON CONFLICT(provider) DO UPDATE SET enabled=$2, ttl_hours=$3, timeout_ms=$4, api_key=COALESCE(NULLIF($5,''), threat_intel_provider_configs.api_key), updated_at=NOW()`,
      [VT_PROVIDER, enabled, ttl, timeout, apiKey]);
    return res.json({ ok: true });
  } catch { return res.status(500).json({ message: 'Failed to update provider config' }); }
});

app.post('/api/admin/enrichment-providers/virustotal/remove-key', async (req, res) => {
  try { await pool.query(`UPDATE threat_intel_provider_configs SET api_key=NULL, updated_at=NOW() WHERE provider=$1`, [VT_PROVIDER]); return res.json({ ok: true }); }
  catch { return res.status(500).json({ message: 'Failed to remove key' }); }
});

app.post('/api/admin/enrichment-providers/virustotal/test', async (req, res) => {
  const now = new Date().toISOString();
  try {
    const cfg = await getThreatIntelProviderConfig(VT_PROVIDER);
    if (!cfg.apiKey) return res.status(400).json({ message: 'VirusTotal API key is not configured' });
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), cfg.timeout_ms || 12000);
    let vtRes;
    try { vtRes = await fetch('https://www.virustotal.com/api/v3/domains/example.com', { headers: { 'x-apikey': cfg.apiKey }, signal: ctrl.signal }); }
    finally { clearTimeout(t); }

    if (vtRes.status === 429) {
      await pool.query(`UPDATE threat_intel_provider_configs SET last_test_at=$2,last_error_at=$2,last_error_message=$3,updated_at=NOW() WHERE provider=$1`, [VT_PROVIDER, now, 'VirusTotal rate limit reached. Try again later.']);
      return res.status(429).json({ message: 'VirusTotal rate limit reached. Try again later.' });
    }
    if (vtRes.status === 401 || vtRes.status === 403) {
      await pool.query(`UPDATE threat_intel_provider_configs SET last_test_at=$2,last_error_at=$2,last_error_message=$3,updated_at=NOW() WHERE provider=$1`, [VT_PROVIDER, now, 'Invalid VirusTotal API key']);
      return res.status(400).json({ message: 'Invalid VirusTotal API key' });
    }
    if (!vtRes.ok) {
      await pool.query(`UPDATE threat_intel_provider_configs SET last_test_at=$2,last_error_at=$2,last_error_message=$3,updated_at=NOW() WHERE provider=$1`, [VT_PROVIDER, now, 'VirusTotal test failed']);
      return res.status(502).json({ message: 'VirusTotal test failed' });
    }
    await pool.query(`UPDATE threat_intel_provider_configs SET last_test_at=$2,last_success_at=$2,last_error_message=NULL,updated_at=NOW() WHERE provider=$1`, [VT_PROVIDER, now]);
    return res.json({ ok: true, message: 'Connection successful' });
  } catch (err) {
    const msg = String(err?.name) === 'AbortError' ? 'VirusTotal test timeout' : 'VirusTotal test failed';
    await pool.query(`UPDATE threat_intel_provider_configs SET last_test_at=$2,last_error_at=$2,last_error_message=$3,updated_at=NOW() WHERE provider=$1`, [VT_PROVIDER, now, msg]).catch(() => {});
    return res.status(500).json({ message: msg });
  }
});

// Read-only diagnostic: source evidence coverage per feed.
// Useful for identifying feeds where membership_fallback evidence is common.
app.get('/api/admin/ioc-evidence-coverage', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  try {
    const { rows } = await pool.query(
      `SELECT
         f.key AS feed_key,
         f.name AS feed_name,
         COUNT(DISTINCT m.ioc_item_id)::int AS total_memberships,
         COUNT(DISTINCT e.ioc_item_id)::int AS with_evidence,
         (COUNT(DISTINCT m.ioc_item_id) - COUNT(DISTINCT e.ioc_item_id))::int AS missing_evidence,
         ROUND(
           100.0 * COUNT(DISTINCT e.ioc_item_id) / NULLIF(COUNT(DISTINCT m.ioc_item_id), 0), 1
         ) AS evidence_pct
       FROM ioc_feed_memberships m
       JOIN integration_feeds f ON f.integration_id = m.feed_id
       LEFT JOIN ioc_feed_source_evidence e
         ON e.ioc_item_id = m.ioc_item_id
         AND e.ioc_observable_type = m.ioc_observable_type
         AND e.feed_id = m.feed_id
       WHERE m.status = 'active' AND m.purged_at IS NULL
       GROUP BY f.key, f.name
       ORDER BY missing_evidence DESC`
    );
    return res.json({ coverage: rows });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to compute evidence coverage', detail: err.message });
  }
});

app.listen(port, async () => {
  console.log(`Backend listening on :${port}`);
  logRegisteredRouteModules();
  if (IOC_LIST_TIMING) {
    console.log('[ioc/list] IOC_LIST_TIMING=1: timing logs enabled (searchStringParse, dbQuery, responseSent, etc.). Use ?timing=1 per request if env not set.');
  }
  await ensureSeedDemoUser();
  runIocListStatsRefreshTick().catch(() => {});
  setInterval(() => {
    runIocListStatsRefreshTick().catch(() => {});
  }, IOC_LIST_STATS_REFRESH_MS);
  regenerateAllEnabledFeeds(pool).catch(() => {});
  setInterval(() => {
    if (publishedFeedTickInProgress) return;
    publishedFeedTickInProgress = true;
    regenerateAllEnabledFeeds(pool)
      .catch((err) => console.error('[published-feeds] tick failed', err?.message || err))
      .finally(() => {
        publishedFeedTickInProgress = false;
      });
  }, PUBLISHED_FEED_TICK_MS);
});
