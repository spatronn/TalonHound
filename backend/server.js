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
  clearCsrfCookie,
  appendRefreshCookie,
  clearRefreshCookie,
  readRefreshCookie,
  getRequestTokenAuthVersion,
  getRequestTokenSessionId
} from './lib/auth.js';
import { createPasswordChangeGate } from './lib/passwordChangeGate.js';
import { bumpAuthVersion, createAuthVersionGate } from './lib/authVersion.js';
import { validateSessionConfig } from './lib/sessionConfig.js';
import {
  createSession,
  rotateRefresh,
  revokeSession,
  revokeAllForUser,
  touchActivity
} from './lib/authSessions.js';
import { ensureDefaultAdminBootstrap } from './lib/defaultAdminBootstrap.js';
import { ensureSystemAdminAccount, SYSTEM_ADMIN_MANUAL_INSTRUCTION } from './lib/systemAdminBootstrap.js';
import { rbacHttpPolicy, requireRole, ROLES } from './lib/rbac.js';
import { ingestCapabilityPolicy, isHumanAdmin, isIngestAuth } from './lib/ingestPrincipal.js';
import { registerUserManagementRoutes } from './routes/users.js';
import { registerAuthPasswordRoutes } from './routes/authPassword.js';
import { registerPublishedFeedRoutes } from './routes/publishedFeeds.js';
import { registerApiKeyRoutes } from './routes/apiKeys.js';
import { registerPublicFeedRoutes } from './routes/publicFeeds.js';
import { registerTaxii21Routes } from './routes/taxii21.js';
import { registerApiV1IocRoutes } from './routes/apiV1Iocs.js';
import { registerApiDocsRoutes } from './routes/apiDocs.js';
import { registerAuditLogRoutes } from './routes/auditLogs.js';
import { registerAuditRetentionRoutes } from './routes/auditRetention.js';
import { registerIocExportRoutes } from './routes/iocExport.js';
import { registerIocSearchExportRoutes } from './routes/iocSearchExports.js';
import { registerIocSavedSearchRoutes } from './routes/iocSavedSearches.js';
import { EXPORT_QUEUE_NAME } from './lib/iocSearchExport/exportConfig.js';
import { registerIocDeepSearchRoutes } from './routes/iocDeepSearches.js';
import { DEEP_SEARCH_QUEUE_NAME } from './lib/iocDeepSearch/deepSearchConfig.js';
import { enqueueDeepSearch } from './lib/iocDeepSearch/enqueueDeepSearch.js';
import { queryFingerprint } from './lib/iocDeepSearch/deepSearchStatus.js';
import { registerBackupRoutes } from './routes/backups.js';
import { BACKUP_QUEUE_NAME } from './lib/backup/config.js';
import {
  parseSearchQuery,
  buildWhereClause,
  getPreviewLimit,
  getQueryTimeoutMs,
  isDslError,
  classifyQuery,
  TIMEOUT_FALLBACK_REASON
} from './lib/iocSearchDsl/index.js';
import {
  buildSearchPageSql,
  buildSearchProbeSql
} from './lib/iocSearchDsl/searchPageSql.js';
import { registerRdapEnrichmentRoutes } from './routes/rdapEnrichment.js';
import { registerIpEnrichmentRoutes } from './routes/ipEnrichment.js';
import { registerAbuseIpdbEnrichmentRoutes } from './routes/abuseipdbEnrichment.js';
import { registerSpamhausDropEnrichmentRoutes } from './routes/spamhausDropEnrichment.js';
import { registerEnrichmentUsageRoutes } from './routes/enrichmentUsage.js';
import { recordEnrichmentUsage } from './lib/enrichmentUsageTelemetry.js';
import {
  registerAnalystIntelligenceRoutes,
  enrichItemsWithAnalystIntelligenceCounts,
  mergeAnalystIntelligenceItem
} from './routes/analystIntelligence.js';
import { registerIocExpirationRoutes, serializeExpirationPolicy } from './routes/iocExpiration.js';
import { registerIocBulkTriageRoutes } from './routes/iocBulkTriage.js';
import { registerIocBulkQueryTriageRoutes } from './routes/iocBulkQueryTriage.js';
import { BULK_QUERY_QUEUE_NAME } from './lib/iocBulkQueryJob/config.js';
import { registerIocDeleteRoute } from './routes/iocDelete.js';
import { registerIocSourceRemovalRoute } from './routes/iocSourceRemoval.js';
import { formatExpirationSummary, buildIocExpirationSummary, recomputeIocGlobalStatus } from './lib/iocExpiration.js';
import { isExplicitIocLifecycleOverride } from './lib/iocStatusOverrideGuards.js';
import {
  archiveIntegrationFeed,
  findActivePurgeJobForFeed,
  FEED_PURGE_JOB_NAME,
  previewFeedDataPurge,
  restoreIntegrationFeed,
  validatePurgeConfirmName
} from './lib/feedLifecycle.js';
import {
  categoryToLegacyType,
  isValidCategory,
  normalizeTagSearch,
  parseExcludeTagIds,
  parseNormalizedTagName,
  parseTagListLimit,
  toPublicTag
} from './lib/tagHelpers.js';
import {
  ensureCatalogTag,
  ensureIocTagAssignment,
  filterFeedIntelligenceByDisabledTags,
  loadDisabledTagNameSet,
  syncIntegrationTagsFromNote
} from './lib/tagCatalogService.js';
import { listAdminTags } from './lib/tagAdminList.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './lib/auditConstants.js';
import { validateHexColor } from './lib/sourceColor.js';
import { resolveRunCounters } from './lib/integrationRunCounters.js';
import {
  computeSuppressionEffectiveStatus,
  normalizeSuppressionStatusFilter,
  SUPPRESSION_STATUS_CASE_SQL
} from './lib/iocSuppressionStatus.js';
import { registerRouteModule, logRegisteredRouteModules } from './lib/routeRegistry.js';
import { runReadinessChecks, buildHealthPayload } from './lib/healthChecks.js';
import {
  normalizeComponentStatus,
  resolveOverallSystemHealth,
  summarizeHealth
} from './lib/systemHealth.js';
import {
  loadSystemTimeConfig,
  buildTimeHealth,
  convertPayloadTimestamps,
  getCachedSystemTimezone,
  assertValidIanaTimezone,
  isValidIanaTimezone,
  clearSystemTimeCache,
  promotePendingSystemTimezone,
  formatTimestampWithOffset,
  adoptSystemTimezoneFromBootstrap,
  isTimezoneRuntimeReady
} from './lib/systemTime.js';
import {
  attachCanonicalIocListTimestamps,
  resolveDetailPlatformImportTimestamp,
  resolveDetailLastConfirmedAt
} from './lib/iocListTimestamps.js';
import { applySessionTimezoneToPool } from './lib/pgSessionTimezone.js';
import { registerSetupRoutes, createSetupGate } from './routes/setup.js';
import { createServiceLogger } from './lib/appLogger.js';
import { setSystemScheduleTimezoneOverride } from './lib/integrationSchedule.js';
import {
  loadIntegrationQueueHealthSnapshot,
  runIntegrationQueueRecover
} from './lib/integrationQueueApi.js';
import { parseActionReason } from './lib/reasonValidation.js';
import { regenerateAllEnabledFeeds, resolvePublishedFeedTickMs, cleanupPublishedFeedLegacyArtifacts } from './lib/feedPublisherService.js';
import { settleWithTimeout } from './lib/promiseTimeout.js';
import { buildFeedMetricsHints } from './lib/feedMetricsHints.js';
import {
  resolveFeedHealthState,
  resolveFeedRuntimeState,
  pickHealthStatus
} from './lib/feedHealth.js';
import { normalizeLastRunResult } from './lib/feedLastRunResult.js';
import {
  mapQueueJobResult,
  QUEUE_JOB_REQUEUE_RESET_SQL
} from './lib/jobResultSnapshot.js';
import { assertCustomFeedSettingsAllowed } from './lib/customThreatFeedAccess.js';
import { normalizeRdapTarget } from './lib/domainRoot.js';
import { getIpinfoLiteConfig } from './services/ipinfoLiteService.js';
import { getAbuseIpdbConfig } from './services/abuseipdbService.js';
import { getSpamhausDropConfig, getSpamhausDropSyncState } from './lib/spamhausDropSync.js';
import { guardProviderEnabled } from './lib/enrichmentProviderRegistry.js';
import { attachProviderHealth } from './lib/enrichmentProviderHealth.js';
import { runProviderHealthProbe } from './lib/enrichmentProviderHealthCheck.js';
import { auditProviderConfigUpdate } from './lib/enrichmentProviderConfigAudit.js';
import { getRdapProviderAdminSummary } from './services/rdapEnrichmentService.js';
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
import {
  buildFileArtifactDetailBlock,
  loadArtifactDetail,
  isFileArtifactsReadEnabled,
  buildGroupedCteBody,
  canonicalizeRowsByIdentity,
  loadArtifactMapsForPublicIds
} from './lib/fileArtifacts/index.js';
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
import { registerIocThreatMetadataRoutes, buildThreatMetadataFields, enrichItemsWithThreatMetadata, mergeThreatMetadataItem, batchLoadFeedClassifications, batchLoadThreatClassificationSuppressions, mergeFeedClassificationsIntoItem } from './routes/iocThreatMetadata.js';
import { loadThreatClassificationRegistry, buildThreatClassificationResponseFields } from './lib/threatClassification.js';
import { parseThreatClassificationFilterParam } from './lib/iocThreatClassifications.js';
import { createManualIoc } from './lib/manualIocCreate.js';
import { createManualSuppression } from './lib/manualSuppressionCreate.js';
import { findActiveRunningJobForSource, recoverStaleRunningJobs } from './lib/integrationQueueRecovery.js';
import { MANUAL_JOB_PRIORITY } from './lib/integrationQueueConfig.js';
import { computeNextRunAt, computeNextWeeklyRunAt, buildRepeatableNextRunMap, buildHourlySlotMap, getSystemScheduleTimezone, isAllowedScheduleCron, isRunOnceSchedule, resolveNextRunAt } from './lib/integrationSchedule.js';
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
import { mergeMalwareBazaarCoverageFields } from './lib/malwarebazaarCoverage.js';
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

// Single shared pool: no new Client() per request; connections are reused (recommended for latency).
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  // The API process shares this pool with the in-process Published Feed
  // regeneration scheduler, so a page-load burst must not starve behind it.
  // `max` widens the headroom; `connectionTimeoutMillis` makes pool starvation
  // surface as a fast, real error instead of the pg default (0 = wait forever),
  // which is what turned a transient blip into an indefinitely hanging Feeds load.
  max: Math.max(Number(process.env.DB_POOL_MAX || 20), 1),
  connectionTimeoutMillis: Math.max(Number(process.env.DB_POOL_CONNECTION_TIMEOUT_MS || 10000), 1000),
  idleTimeoutMillis: Math.max(Number(process.env.DB_POOL_IDLE_TIMEOUT_MS || 30000), 1000),
  options: `-c TimeZone=${String(process.env.SYSTEM_TIMEZONE || process.env.TZ || 'UTC').trim() || 'UTC'}`
});

const appLog = createServiceLogger('backend');

// pg emits 'error' on an idle pooled client when Postgres or the network drops
// the connection. With no listener attached, Node treats it as an unhandled
// 'error' event and crashes the whole backend — which resets every in-flight
// request (including a Feeds page load) before docker restarts the process.
// Log and let the pool discard the dead client; the next query acquires a fresh one.
pool.on('error', (err) => {
  appLog.warn('pg pool idle client error (connection discarded)', { error: err?.message || String(err) });
});

async function syncRuntimeTimezoneFromDb() {
  try {
    await adoptSystemTimezoneFromBootstrap(pool, { logger: appLog });
    const cfg = await loadSystemTimeConfig(pool, { force: true });
    if (!isTimezoneRuntimeReady(cfg) && !(cfg.timezone_restart_required && cfg.pending_system_timezone)) {
      appLog.warn('system timezone not ready', {
        setup_completed: cfg.initial_setup_completed,
        configuration_required: cfg.timezone_configuration_required
      });
      return null;
    }

    // After restart with a pending change: apply pending, verify PG session, then promote.
    if (cfg.timezone_restart_required && cfg.pending_system_timezone) {
      const pending = assertValidIanaTimezone(cfg.pending_system_timezone);
      process.env.TZ = pending;
      setSystemScheduleTimezoneOverride(pending);
      await applySessionTimezoneToPool(pool, pending);
      const { readPostgresSessionTimezone } = await import('./lib/systemTime.js');
      const pgTz = await readPostgresSessionTimezone(pool);
      const pgOk = pgTz && String(pgTz).toLowerCase() === pending.toLowerCase();
      if (pgOk) {
        const promoted = await promotePendingSystemTimezone(pool);
        appLog.info('pending system timezone promoted', { timezone: pending, status: promoted.status });
        return pending;
      }
      appLog.warn('pending timezone not promoted — postgres session mismatch; reverting process to active', {
        pending,
        active: cfg.active_system_timezone,
        postgres_session_timezone: pgTz
      });
      // Health failed: do not promote. Keep restart_required + pending. Revert runtime to active.
      if (cfg.active_system_timezone && isValidIanaTimezone(cfg.active_system_timezone)) {
        const active = assertValidIanaTimezone(cfg.active_system_timezone);
        process.env.TZ = active;
        setSystemScheduleTimezoneOverride(active);
        await applySessionTimezoneToPool(pool, active);
        return active;
      }
      return null;
    }

    const tz = assertValidIanaTimezone(cfg.active_system_timezone);
    process.env.TZ = tz;
    setSystemScheduleTimezoneOverride(tz);
    await applySessionTimezoneToPool(pool, tz);
    appLog.info('system timezone synchronized', { timezone: tz });
    return tz;
  } catch (err) {
    appLog.warn('system timezone sync skipped', { error: err?.message || String(err) });
    return null;
  }
}

loadThreatClassificationRegistry(pool).catch((err) => {
  console.warn('[threat-classifications] registry preload skipped:', err?.message || err);
});

const redisUrl = getRedisUrl();
const queueName = process.env.QUEUE_NAME || 'integration-imports';
const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const importQueue = new Queue(queueName, { connection: redis });
const iocSearchExportQueue = new Queue(EXPORT_QUEUE_NAME, { connection: redis });
const iocDeepSearchQueue = new Queue(DEEP_SEARCH_QUEUE_NAME, { connection: redis });
const iocBulkQueryQueue = new Queue(BULK_QUERY_QUEUE_NAME, { connection: redis });
const systemBackupQueue = new Queue(BACKUP_QUEUE_NAME, { connection: redis });
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
app.use(createSetupGate(pool));
app.use(apiAuthGate);
app.use(createAuthVersionGate(pool, {
  getTokenAuthVersion: getRequestTokenAuthVersion,
  getTokenSessionId: getRequestTokenSessionId
}));
app.use(csrfProtection);
app.use(createPasswordChangeGate(pool));
app.use(ingestCapabilityPolicy);
app.use(rbacHttpPolicy);

// Serialize API timestamps with system-timezone offsets (never bare local / offset-less).
app.use((req, res, next) => {
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    const tz = getCachedSystemTimezone() || process.env.SYSTEM_TIMEZONE || process.env.TZ || null;
    if (tz && body != null && typeof body === 'object') {
      try {
        return originalJson(convertPayloadTimestamps(body, tz));
      } catch {
        return originalJson(body);
      }
    }
    return originalJson(body);
  };
  next();
});

let geoCacheRefreshInProgress = false;
let geoCacheDebounceTimer = null;

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
  const timeHealth = await buildTimeHealth(pool).catch(() => null);
  const checks = { ...result.checks };
  if (timeHealth) checks.date_time = timeHealth.status;
  const ok = result.ok && (!timeHealth || timeHealth.status !== 'unhealthy');
  const payload = buildHealthPayload(ok ? 'ok' : 'error', checks);
  if (timeHealth) payload.date_time = timeHealth;
  if (!ok) {
    payload.error = result.error || timeHealth?.error || 'readiness failed';
    return res.status(503).json(payload);
  }
  return res.json(payload);
});

app.get('/health', async (_req, res) => {
  try {
    const result = await runReadinessChecks(pool, redis);
    const timeHealth = await buildTimeHealth(pool).catch(() => null);
    const checks = { ...result.checks };
    if (timeHealth) checks.date_time = timeHealth.status;
    const ok = result.ok && (!timeHealth || timeHealth.status !== 'unhealthy');
    if (ok) {
      return res.json({
        ok: true,
        service: 'backend',
        db: 'up',
        date_time: timeHealth,
        ...buildHealthPayload('ok', checks)
      });
    }
    return res.status(500).json({
      ok: false,
      service: 'backend',
      db: result.checks.postgres === 'ok' ? 'up' : 'down',
      date_time: timeHealth,
      ...buildHealthPayload('error', checks),
      error: result.error || timeHealth?.error
    });
  } catch {
    res.status(500).json({ ok: false, service: 'backend', db: 'down' });
  }
});

app.get('/api/system/time-health', async (_req, res) => {
  try {
    const timeHealth = await buildTimeHealth(pool);
    const statusCode = timeHealth.status === 'unhealthy' ? 503 : 200;
    return res.status(statusCode).json(timeHealth);
  } catch (err) {
    return res.status(500).json({ status: 'unhealthy', error: err?.message || 'time health failed' });
  }
});

const FEED_JOB_TYPE_BY_KEY = {
  'et-blockrules': 'hourly_import',
  'usom-trcert': 'usom_import',
  'urlhaus-abusech': 'urlhaus_import',
  'threatfox-abusech': 'threatfox_import',
  'malwarebazaar-abusech': 'malwarebazaar_import',
  'phishtank-opendnsrr': 'phishtank_import',
  'alienvault-otx': 'alienvault_otx_import'
};

function integrationsTimingLog(enabled, label, startMs) {
  if (!enabled) return;
  console.log(`[integrations] ${label}: ${Date.now() - startMs}ms`);
}

function wantsIntegrationsQueue(req) {
  const q = req.query || {};
  return Object.prototype.hasOwnProperty.call(q, 'queue_page')
    || Object.prototype.hasOwnProperty.call(q, 'queue_search')
    || Object.prototype.hasOwnProperty.call(q, 'queue_window')
    || Object.prototype.hasOwnProperty.call(q, 'queue_integration')
    || Object.prototype.hasOwnProperty.call(q, 'queue_state')
    || Object.prototype.hasOwnProperty.call(q, 'queue_from')
    || Object.prototype.hasOwnProperty.call(q, 'queue_to');
}

const QUEUE_ALLOWED_STATES = new Set(['queued', 'running', 'success', 'failed', 'skipped']);
const QUEUE_MAX_CUSTOM_RANGE_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Resolve queue time window filters for integration_queue_jobs listing.
 * @returns {{ ok: true, clause: string, params: any[], nextIndex: number, window: string, from: string|null, to: string|null }
 *   | { ok: false, status: number, message: string }}
 */
function resolveQueueWindowFilter(req, startParamIndex = 1) {
  const queueWindow = String(req.query?.queue_window || '24h').trim();
  const params = [];
  let idx = startParamIndex;

  if (queueWindow === 'custom') {
    const fromRaw = String(req.query?.queue_from || '').trim();
    const toRaw = String(req.query?.queue_to || '').trim();
    if (!fromRaw || !toRaw) {
      return { ok: false, status: 400, message: 'queue_from and queue_to are required when queue_window=custom' };
    }
    const fromMs = Date.parse(fromRaw);
    const toMs = Date.parse(toRaw);
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs)) {
      return { ok: false, status: 400, message: 'queue_from and queue_to must be valid ISO timestamps' };
    }
    if (toMs < fromMs) {
      return { ok: false, status: 400, message: 'queue_to must be greater than or equal to queue_from' };
    }
    if ((toMs - fromMs) > QUEUE_MAX_CUSTOM_RANGE_MS) {
      return { ok: false, status: 400, message: 'Custom queue window cannot exceed 30 days' };
    }
    params.push(new Date(fromMs).toISOString(), new Date(toMs).toISOString());
    const fromIdx = idx;
    const toIdx = idx + 1;
    idx += 2;
    return {
      ok: true,
      clause: `q.queued_at >= $${fromIdx}::timestamptz AND q.queued_at <= $${toIdx}::timestamptz`,
      countClause: `queued_at >= $${fromIdx}::timestamptz AND queued_at <= $${toIdx}::timestamptz`,
      params,
      nextIndex: idx,
      window: 'custom',
      from: new Date(fromMs).toISOString(),
      to: new Date(toMs).toISOString()
    };
  }

  let intervalSql = "NOW() - INTERVAL '24 hours'";
  let windowLabel = '24h';
  if (queueWindow === '7d') {
    intervalSql = "NOW() - INTERVAL '7 days'";
    windowLabel = '7d';
  } else if (queueWindow === '30d') {
    intervalSql = "NOW() - INTERVAL '30 days'";
    windowLabel = '30d';
  } else if (queueWindow === '1d') {
    intervalSql = "NOW() - INTERVAL '24 hours'";
    windowLabel = '1d';
  }

  return {
    ok: true,
    clause: `q.queued_at >= ${intervalSql}`,
    countClause: `queued_at >= ${intervalSql}`,
    params,
    nextIndex: idx,
    window: windowLabel,
    from: null,
    to: null
  };
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

function buildIntegrationHealthSummary(integrations, changes24h = null) {
  const feedRows = (integrations || []).filter((i) => i.key !== 'asn_enrichment');
  const activeFeeds = feedRows.filter((i) => i.active !== false);
  const healthyFeeds = feedRows.filter((i) => {
    if (i.active === false) return false;
    const health = String(i.health_state || '').toLowerCase();
    return health === 'success';
  });
  const needsAttentionFeeds = feedRows.filter((i) => {
    if (i.active === false) return false;
    const health = String(i.health_state || '').toLowerCase();
    return health === 'warning' || health === 'failed' || health === 'degraded';
  });
  const runningQueuedFeeds = feedRows.filter((i) => {
    const runtime = String(i.runtime_state || '').toLowerCase();
    const st = String(i.status || i.last_status || '').toLowerCase();
    return runtime === 'running' || runtime === 'queued' || st === 'running' || st === 'queued';
  });
  // Legacy fields retained for older clients.
  const failingFeeds = needsAttentionFeeds.filter((i) => {
    const health = String(i.health_state || '').toLowerCase();
    const st = String(i.status || i.last_status || '').toLowerCase();
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

  const summary = {
    total_feeds: feedRows.length,
    active_feeds: activeFeeds.length,
    enabled_feeds: activeFeeds.length,
    inactive_feeds: feedRows.length - activeFeeds.length,
    healthy_feeds: healthyFeeds.length,
    needs_attention_feeds: needsAttentionFeeds.length,
    running_queued_feeds: runningQueuedFeeds.length,
    failing_feeds: failingFeeds.length,
    successful_feeds_24h: successfulFeeds24h.length,
    last_run_inserted_total: lastRunInsertedTotal,
    last_run_new_total: lastRunInsertedTotal,
    last_run_processed_total: lastRunProcessedTotal
  };

  if (changes24h && changes24h.available) {
    summary.changes_24h = {
      available: true,
      new: metricInt(changes24h.new),
      updated: metricInt(changes24h.updated)
    };
  } else {
    summary.changes_24h = { available: false, new: null, updated: null };
  }

  return summary;
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
      health_state: feedActive ? (asnLastUpdatedAt ? 'success' : 'never') : 'disabled',
      run_health_state: feedActive ? (asnLastUpdatedAt ? 'success' : 'never') : 'disabled',
      runtime_state: null,
      last_run_at: asnLastUpdatedAt || null,
      last_started_at: asnLastUpdatedAt || null,
      last_finished_at: null,
      last_success_at: asnLastUpdatedAt || null,
      last_error: null,
      consecutive_failures: 0,
      last_run_metrics: lastRunMetrics,
      last_result: normalizeLastRunResult(null, {
        status: asnLastUpdatedAt ? 'success' : 'never',
        lastRunMetrics
      }),
      ...runMetrics,
      total_records: null
    };
  }

  const rawLastStatus = lr?.status || lq?.status || 'never';
  const runtimeState = resolveFeedRuntimeState(rawLastStatus);
  const healthStatus = pickHealthStatus(
    lr || lq || { status: 'never' },
    lastSuccess
  );
  // Prefer terminal status for display when in-flight; keep raw status on status field.
  const lastStatus = rawLastStatus;
  const lastError = (String(healthStatus) === 'failed' || String(healthStatus) === 'fail'
    || String(rawLastStatus) === 'failed' || String(rawLastStatus) === 'fail')
    ? (lr?.error_message || lq?.error_message || null)
    : null;
  const consecutive = consecutiveFailures.get(jobType) || 0;
  const metricsHints = buildFeedMetricsHints(lastRunMetrics, { runDetails: lr?.run_details || null });
  const healthState = resolveFeedHealthState(
    feedActive,
    healthStatus,
    consecutive,
    metricsHints,
    { runDetails: lr?.run_details || null }
  );
  const lastResult = normalizeLastRunResult(metricsRow, {
    status: lastStatus,
    jobType,
    errorMessage: lastError,
    startedAt: lr?.started_at || lq?.started_at || null,
    finishedAt: lr?.finished_at || lq?.finished_at || null,
    lastRunMetrics,
    runDetails: lr?.run_details || null
  });

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
    health_state: healthState,
    // Run-level operational health of the latest run, before any USOM full-reconciliation
    // overlay is applied by mergeUsomReconciliationFields. The Last Result column reconciles
    // against this so a separate reconciliation problem never rewrites a successful run.
    run_health_state: healthState,
    runtime_state: runtimeState,
    last_run_at: lr?.finished_at || lr?.started_at || lq?.finished_at || lq?.started_at || lq?.queued_at || null,
    last_started_at: lr?.started_at || lq?.started_at || lq?.queued_at || null,
    last_finished_at: lr?.finished_at || lq?.finished_at || null,
    last_success_at: lastSuccess?.finished_at || lastSuccess?.started_at || (
      ['success', 'skipped', 'skipped_unchanged'].includes(String(lastStatus).toLowerCase())
        ? (lr?.finished_at || lr?.started_at || null)
        : null
    ),
    last_error: lastError,
    consecutive_failures: consecutive,
    last_run_metrics: lastRunMetrics,
    last_run_details: lr?.run_details || null,
    last_result: lastResult,
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

function queryIntegrationsMetaWithTimeout(queryPromise, fallbackRows = []) {
  return settleWithTimeout(queryPromise, {
    timeoutMs: INTEGRATIONS_META_QUERY_TIMEOUT_MS,
    fallback: () => ({ rows: fallbackRows })
  });
}

app.get('/api/integrations', async (req, res) => {
  const handlerStart = Date.now();
  const timingEnabled = INTEGRATIONS_TIMING || req.query?.timing === '1';

  try {
    const queuePage = Math.max(Number(req.query?.queue_page || 1) || 1, 1);
    const requestedSize = Number(req.query?.queue_page_size || 25) || 25;
    const queuePageSize = Math.min(Math.max(requestedSize, 1), 100);
    const queueOffset = (queuePage - 1) * queuePageSize;
    const queueSearch = String(req.query?.queue_search || '').trim();
    const queueIntegration = String(req.query?.queue_integration || '').trim();
    const queueStateRaw = String(req.query?.queue_state || '').trim().toLowerCase();
    const queueState = QUEUE_ALLOWED_STATES.has(queueStateRaw) ? queueStateRaw : '';
    const loadQueue = wantsIntegrationsQueue(req);

    const queueWindowResolved = resolveQueueWindowFilter(req, 1);
    if (loadQueue && !queueWindowResolved.ok) {
      return res.status(queueWindowResolved.status).json({ message: queueWindowResolved.message });
    }
    const queueWindow = queueWindowResolved.ok ? queueWindowResolved.window : '24h';

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
        f.color,
        f.credentials,
        f.created_at
      FROM integration_feeds f
      WHERE ($1::boolean OR f.archived_at IS NULL)
        AND COALESCE(f.feed_kind, 'built_in') <> 'custom'
      ORDER BY f.archived_at NULLS FIRST, f.active DESC, f.created_at ASC, f.name ASC
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
    // `getRepeatableJobs()` is a Redis (BullMQ) call on the initial-load critical
    // path. It is only used to surface BullMQ's Next Run; when it is unavailable
    // we fall back to the schedule-derived next run below, so it is non-critical.
    // Bounding it with the same timeout as the meta queries keeps a Redis stall
    // from hanging the whole Feeds request (the ioredis client uses
    // maxRetriesPerRequest:null, so an unbounded call cannot fail fast). feedsQ
    // and expirationPoliciesQ stay unbounded here because they are the primary
    // data — a starved pool now fails fast via connectionTimeoutMillis rather
    // than returning fabricated feed rows.
    const [feedsRes, repeatableNextByKey, expirationPoliciesRes] = await Promise.all([
      pool.query(feedsQ, [includeArchived]),
      settleWithTimeout(
        importQueue.getRepeatableJobs().then((rows) => buildRepeatableNextRunMap(rows)),
        { timeoutMs: INTEGRATIONS_META_QUERY_TIMEOUT_MS, fallback: () => new Map() }
      ),
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
      // Never surface a stale/past BullMQ next as "Next Run" — fall back to the
      // schedule-derived future run. See resolveNextRunAt.
      const nextRunAt = isRunOnceSchedule(feed.schedule) ? null : resolveNextRunAt(bullNext, computedNext, now);
      const fullBullNext = feed.key === 'usom-trcert'
        ? repeatableNextByKey.get(`${feed.key}::${USOM_FULL_RECONCILIATION_MODE}`)
        : null;
      const fullComputedNext = feed.key === 'usom-trcert' && usomFullSchedule.enabled
        ? computeNextWeeklyRunAt(usomFullSchedule.cron, now, usomFullSchedule.timezone)
        : null;
      const nextFull = resolveNextRunAt(fullBullNext, fullComputedNext, now);
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
        AND status IN ('success', 'skipped_unchanged', 'skipped')
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

    const changes24hQ = `
      SELECT
        COALESCE(SUM(records_inserted), 0)::bigint AS new_count,
        COALESCE(SUM(records_updated), 0)::bigint AS updated_count
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
        AND status IN ('success', 'skipped_unchanged', 'skipped')
        AND finished_at >= NOW() - INTERVAL '24 hours'
    `;

    const latestRunStart = Date.now();
    const [latestRunsRes, lastSuccessRunsRes, recentFailuresRes, latestQueueRes, latestPurgeRes, asnRes, usomRunsByModeRes, usomSuccessRunsByModeRes, changes24hRes] = await Promise.all([
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
      feedKeys.includes('usom-trcert')
        ? queryIntegrationsMetaWithTimeout(pool.query(usomRunsByModeQ))
        : Promise.resolve({ rows: [] }),
      feedKeys.includes('usom-trcert')
        ? queryIntegrationsMetaWithTimeout(pool.query(usomSuccessRunsByModeQ))
        : Promise.resolve({ rows: [] }),
      jobTypes.length
        ? queryIntegrationsMetaWithTimeout(pool.query(changes24hQ, [jobTypes]), [{ new_count: null, updated_count: null }])
        : Promise.resolve({ rows: [{ new_count: null, updated_count: null }] })
    ]);
    integrationsTimingLog(timingEnabled, 'latest run query', latestRunStart);

    let mbCoverage = null;
    let mbCoverageUnavailable = false;
    if (feedKeys.includes(MALWAREBAZAAR_FEED_KEY)) {
      try {
        const mbCoverageRes = await Promise.race([
          pool.query(
            'SELECT * FROM malwarebazaar_coverage_state WHERE feed_key = $1',
            [MALWAREBAZAAR_FEED_KEY]
          ),
          new Promise((_, reject) => {
            setTimeout(
              () => reject(new Error('malwarebazaar coverage query timeout')),
              INTEGRATIONS_META_QUERY_TIMEOUT_MS
            );
          })
        ]);
        mbCoverage = mbCoverageRes.rows[0] || null;
      } catch {
        mbCoverageUnavailable = true;
      }
    }

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
    const changes24hRow = changes24hRes.rows[0] || {};
    const changes24h = (changes24hRow.new_count != null || changes24hRow.updated_count != null)
      ? {
          available: true,
          new: Number(changes24hRow.new_count || 0),
          updated: Number(changes24hRow.updated_count || 0)
        }
      : { available: false, new: null, updated: null };

    const integrations = feedsRes.rows.map((feed) => mergeMalwareBazaarCoverageFields(
      mergeUsomReconciliationFields(
        mergeIntegrationListRow(feed, latestRunByJobType, latestQueueByKey, lastSuccessByJobType, consecutiveFailures, asnLastUpdatedAt, expirationByKey, latestPurgeByKey),
        latestUsomByMode,
        lastSuccessfulUsomByMode,
        now
      ),
      mbCoverage,
      now,
      { unavailable: mbCoverageUnavailable }
    ));
    const healthSummary = buildIntegrationHealthSummary(integrations, changes24h);

    let queue = {
      counts: { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0 },
      jobs: []
    };

    if (loadQueue) {
    const queueStart = Date.now();
    try {
      const filterParams = [...(queueWindowResolved.params || [])];
      let paramIdx = queueWindowResolved.nextIndex;
      const whereParts = [queueWindowResolved.clause];

      if (queueIntegration) {
        filterParams.push(queueIntegration);
        whereParts.push(`q.integration_key = $${paramIdx}`);
        paramIdx += 1;
      }
      if (queueState) {
        filterParams.push(queueState);
        whereParts.push(`q.status = $${paramIdx}`);
        paramIdx += 1;
      }

      let searchWhere = '';
      if (queueSearch) {
        filterParams.push(`%${queueSearch}%`);
        searchWhere = `
          AND (
            q.job_id ILIKE $${paramIdx}
            OR q.integration_key ILIKE $${paramIdx}
            OR q.job_name ILIKE $${paramIdx}
            OR q.status ILIKE $${paramIdx}
            OR COALESCE(q.error_message, '') ILIKE $${paramIdx}
            OR COALESCE(q.result_summary, '') ILIKE $${paramIdx}
            OR COALESCE(q.result_code, '') ILIKE $${paramIdx}
            OR COALESCE(f.name, q.integration_key) ILIKE $${paramIdx}
          )
        `;
        paramIdx += 1;
      }

      const whereSql = whereParts.join(' AND ');

      // Status histogram: time + integration + state (not free-text search)
      const countParams = [...(queueWindowResolved.params || [])];
      let countIdx = queueWindowResolved.nextIndex;
      const countFilters = [queueWindowResolved.countClause];
      if (queueIntegration) {
        countParams.push(queueIntegration);
        countFilters.push(`integration_key = $${countIdx}`);
        countIdx += 1;
      }
      if (queueState) {
        countParams.push(queueState);
        countFilters.push(`status = $${countIdx}`);
      }
      const countSqlFinal = `
        SELECT status, COUNT(*)::int AS cnt
        FROM integration_queue_jobs
        WHERE ${countFilters.join(' AND ')}
        GROUP BY status
      `;

      const totalSql = `
        SELECT COUNT(*)::int AS total
        FROM integration_queue_jobs q
        LEFT JOIN integration_feeds f ON f.key = q.integration_key
        WHERE ${whereSql}
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
          q.queued_at,
          q.error_message AS failed_reason,
          q.failure_type,
          q.triggered_by,
          q.records_processed,
          q.records_inserted,
          q.records_updated,
          q.records_duplicate,
          q.records_unchanged,
          q.records_reactivated,
          q.records_removed,
          q.records_skipped,
          q.records_suppressed,
          q.records_failed,
          q.result_code,
          q.result_summary,
          q.result_details,
          q.run_mode,
          q.started_at,
          q.finished_at
        FROM integration_queue_jobs q
        LEFT JOIN integration_feeds f ON f.key = q.integration_key
        WHERE ${whereSql}
        ${searchWhere}
        ORDER BY q.queued_at DESC
        LIMIT $${paramIdx}
        OFFSET $${paramIdx + 1}
      `;

      const jobsParams = [...filterParams, queuePageSize, queueOffset];

      const [countRows, totalRows, jobsRows] = await Promise.all([
        pool.query(countSqlFinal, countParams),
        pool.query(totalSql, filterParams),
        pool.query(jobsSql, jobsParams)
      ]);

      const mapped = { waiting: 0, active: 0, delayed: 0, failed: 0, completed: 0, skipped: 0 };
      for (const r of countRows.rows) {
        if (r.status === 'queued') mapped.waiting += r.cnt;
        else if (r.status === 'running') mapped.active += r.cnt;
        else if (r.status === 'failed') mapped.failed += r.cnt;
        else if (r.status === 'success') mapped.completed += r.cnt;
        else if (r.status === 'skipped') mapped.skipped += r.cnt;
      }

      const total = Number(totalRows.rows[0]?.total || 0);
      queue = {
        counts: mapped,
        jobs: jobsRows.rows.map((row) => {
          const result = mapQueueJobResult(row);
          const display = withIntegrationJobDisplayName(row);
          return {
            ...display,
            result_code: result.result_code,
            result_summary: result.result_summary,
            result_details: result.result_details,
            result,
            run_mode: row.run_mode || null,
            triggered_by: row.triggered_by || null,
            failure_type: row.failure_type || null,
            records_inserted: row.records_inserted,
            records_updated: row.records_updated,
            records_unchanged: row.records_unchanged,
            records_reactivated: row.records_reactivated,
            records_removed: row.records_removed,
            records_skipped: row.records_skipped,
            records_suppressed: row.records_suppressed,
            records_failed: row.records_failed
          };
        }),
        pagination: {
          page: queuePage,
          page_size: queuePageSize,
          total,
          total_pages: Math.max(1, Math.ceil(total / queuePageSize))
        },
        filters: {
          search: queueSearch,
          window: queueWindow,
          integration: queueIntegration || null,
          state: queueState || null,
          from: queueWindowResolved.from || null,
          to: queueWindowResolved.to || null
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
      if (snapshot.bull_counts) {
        queue.counts = {
          ...queue.counts,
          waiting: Number(snapshot.bull_counts.waiting || 0),
          active: Number(snapshot.bull_counts.active || 0),
          delayed: Number(snapshot.bull_counts.delayed || 0)
        };
      }
    } catch (err) {
      console.warn('[integrations] queue health snapshot failed', err.message);
    }
    }

    integrationsTimingLog(timingEnabled, 'endpoint total', handlerStart);

    return res.json({
      integrations,
      health_summary: healthSummary,
      schedule_reference_timezone: getSystemScheduleTimezone(),
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
     DO UPDATE SET status='queued', triggered_by=$3, updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL,
       ${QUEUE_JOB_REQUEUE_RESET_SQL}`,
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
         DO UPDATE SET status='queued', triggered_by='manual-ui-all', updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL,
           ${QUEUE_JOB_REQUEUE_RESET_SQL}`,
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
       DO UPDATE SET status='queued', triggered_by='manual-ui-one', updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL,
         ${QUEUE_JOB_REQUEUE_RESET_SQL}`,
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
       DO UPDATE SET status='queued', triggered_by=$4, updated_at=NOW(), started_at=NULL, finished_at=NULL, error_message=NULL, failure_type=NULL,
         ${QUEUE_JOB_REQUEUE_RESET_SQL}`,
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

app.put('/api/integrations/:key/color', requireRole(ROLES.ADMIN), async (req, res) => {
  const { key } = req.params;
  const colorCheck = validateHexColor(req.body?.color);
  if (!colorCheck.ok) {
    return res.status(400).json({ message: colorCheck.error });
  }

  try {
    const prevQ = await pool.query(
      'SELECT key, integration_id, name, color FROM integration_feeds WHERE key = $1 LIMIT 1',
      [key]
    );
    if (!prevQ.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }
    const prev = prevQ.rows[0];

    const result = await pool.query(
      `UPDATE integration_feeds
       SET color = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, integration_id, name, color`,
      [key, colorCheck.value]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.INTEGRATION_COLOR_CHANGED,
      entityType: AUDIT_ENTITY.INTEGRATION,
      entityId: String(result.rows[0].integration_id || key),
      entityDisplay: result.rows[0].name,
      before: { color: prev.color },
      after: { color: result.rows[0].color },
      metadata: { feed_key: key }
    }).catch((e) => console.warn('[audit] color log failed', e?.message || e));

    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update badge color', detail: err.message });
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

app.put('/api/integrations/:key/credentials', requireRole(ROLES.ADMIN), async (req, res) => {
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

app.post('/api/integrations/:key/credentials/test', requireRole(ROLES.ADMIN), async (req, res) => {
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
      'SELECT id, public_id, username, password_hash, role, status, must_change_password, auth_version FROM users WHERE username = $1',
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
        const authVersion = Number(u.auth_version) || 1;
        const session = await createSession(pool, {
          userId: u.id,
          authVersion,
          userAgent: req.headers['user-agent'] || null
        });
        const token = signUserToken({
          userId: u.id,
          username: u.username,
          email: u.username,
          role: u.role,
          authVersion,
          sessionId: session.sessionId
        });
        appendAuthCookie(req, res, token);
        appendRefreshCookie(req, res, session.refreshToken);
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
            role: u.role,
            mustChangePassword: Boolean(u.must_change_password)
          }
        });
      }
    }
  } catch (err) {
    appLog.warn('login database lookup failed', { error: err?.message || String(err) });
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
  // JWT-03: logout invalidates all outstanding JWTs for this user (version bump).
  // JWT-06: also revoke the server-side session so the refresh token dies immediately.
  if (req.user?.id != null && Number.isFinite(Number(req.user.id)) && req.authVia !== 'ingest') {
    await bumpAuthVersion(pool, req.user.id).catch(() => {});
    await revokeAllForUser(pool, req.user.id, 'logout').catch(() => {});
  } else {
    // No valid access token (e.g. it already expired) but a refresh cookie may remain:
    // revoke that specific session by its refresh secret so logout is always effective.
    const raw = readRefreshCookie(req);
    if (raw) {
      const { parseRefreshToken } = await import('./lib/authSessions.js');
      const parsed = parseRefreshToken(raw);
      if (parsed?.sessionId) {
        await revokeSession(pool, parsed.sessionId, 'logout').catch(() => {});
      }
    }
  }
  await auditLogService.auditSuccess({
    req,
    action: AUDIT_ACTION.AUTH_LOGOUT,
    entityType: AUDIT_ENTITY.AUTH,
    entityDisplay: String(req.user?.username || req.user?.email || 'unknown'),
    severity: AUDIT_SEVERITY.INFO,
    metadata: { auth_via: req.authVia || 'web', sessions: 'all' }
  }).catch(() => {});
  clearAuthCookie(req, res);
  clearRefreshCookie(req, res);
  clearCsrfCookie(req, res);
  res.status(204).end();
});

// JWT-06: silent access-token renewal via rotating refresh token. Enforces idle +
// absolute limits and replay detection server-side. Does NOT extend the idle clock
// (refresh is not user activity), so background polling that merely triggers refresh
// cannot keep an idle session alive.
app.post('/api/auth/refresh', async (req, res) => {
  const raw = readRefreshCookie(req);
  if (!raw) return res.status(401).json({ message: 'Unauthorized', code: 'SESSION_INVALID' });

  let result;
  try {
    result = await rotateRefresh(pool, {
      rawRefresh: raw,
      userAgent: req.headers['user-agent'] || null
    });
  } catch (err) {
    appLog.warn('session refresh failed', { error: err?.message || String(err) });
    return res.status(500).json({ message: 'Session refresh failed' });
  }

  if (!result.ok) {
    clearAuthCookie(req, res);
    clearRefreshCookie(req, res);
    clearCsrfCookie(req, res);
    if (result.reason === 'reuse') {
      await auditLogService.auditFailure({
        req,
        action: AUDIT_ACTION.AUTH_SESSION_REFRESH_REUSE,
        entityType: AUDIT_ENTITY.AUTH,
        entityDisplay: 'session',
        severity: AUDIT_SEVERITY.CRITICAL,
        metadata: { reason: 'refresh_reuse' }
      }).catch(() => {});
    } else if (result.reason === 'idle' || result.reason === 'absolute') {
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.AUTH_SESSION_EXPIRED,
        entityType: AUDIT_ENTITY.AUTH,
        entityDisplay: 'session',
        severity: AUDIT_SEVERITY.INFO,
        metadata: { reason: result.reason }
      }).catch(() => {});
    }
    const code =
      result.reason === 'idle' ? 'SESSION_EXPIRED_IDLE'
      : result.reason === 'absolute' ? 'SESSION_EXPIRED_ABSOLUTE'
      : 'SESSION_INVALID';
    return res.status(401).json({ message: 'Session expired', code });
  }

  const { rows } = await pool.query(
    'SELECT id, public_id, username, role FROM users WHERE id = $1',
    [result.userId]
  );
  if (!rows.length) {
    clearAuthCookie(req, res);
    clearRefreshCookie(req, res);
    clearCsrfCookie(req, res);
    return res.status(401).json({ message: 'Unauthorized', code: 'SESSION_INVALID' });
  }
  const u = rows[0];
  const token = signUserToken({
    userId: u.id,
    username: u.username,
    email: u.username,
    role: u.role,
    authVersion: result.authVersion,
    sessionId: result.sessionId
  });
  appendAuthCookie(req, res, token);
  // On a grace-window hit a concurrent tab already rotated the shared cookie; leave it.
  if (result.refreshToken) {
    appendRefreshCookie(req, res, result.refreshToken);
  }
  return res.json({
    user: { email: u.username, username: u.username, id: u.public_id, role: u.role }
  });
});

// JWT-06: explicit genuine-activity heartbeat. The frontend calls this (throttled)
// ONLY in response to real user interaction — never from background polling. Runs after
// the auth-version/session gate, so it can only extend a session that is still valid.
app.post('/api/auth/activity', async (req, res) => {
  const sid = getRequestTokenSessionId(req);
  if (sid) {
    await touchActivity(pool, sid).catch(() => {});
  }
  return res.status(204).end();
});

registerAuthPasswordRoutes(app, pool, {
  bcrypt,
  signUserToken,
  appendAuthCookie,
  appendRefreshCookie,
  appendCsrfCookie,
  createSession,
  revokeAllForUser,
  pool,
  audit: auditLogService
});

app.get('/api/auth/me', async (req, res) => {
  let publicId = null;
  let mustChangePassword = false;
  let role = req.user?.role || ROLES.ADMIN;
  let username = req.user?.username || req.user?.email;

  if (req.user?.id != null) {
    try {
      const { rows } = await pool.query(
        'SELECT public_id, username, role, must_change_password FROM users WHERE id = $1',
        [Number(req.user.id)]
      );
      if (rows.length) {
        publicId = rows[0].public_id;
        mustChangePassword = Boolean(rows[0].must_change_password);
        role = rows[0].role || role;
        username = rows[0].username || username;
      }
    } catch {
      // fall through
    }
  }

  res.json({
    user: {
      email: username,
      username,
      id: publicId,
      role,
      mustChangePassword
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
registerSetupRoutes(app, pool, {
  audit: auditLogService,
  onTimezoneChanged: async (tz, meta = {}) => {
    clearSystemTimeCache();
    // Pending admin changes must NOT switch the running process off active.
    if (meta?.restartRequired || meta?.reason === 'admin_change_pending') {
      appLog.info('timezone change pending restart', {
        active: meta.active,
        pending: meta.pending
      });
      return;
    }
    if (!tz) return;
    process.env.TZ = tz;
    setSystemScheduleTimezoneOverride(tz);
    try {
      await applySessionTimezoneToPool(pool, tz);
    } catch (err) {
      appLog.warn('failed to apply session timezone after change', { error: err?.message || String(err) });
    }
    appLog.info('system timezone applied', { timezone: tz, reason: meta.reason || 'unknown' });
  }
});
registerRouteModule('users');
registerRouteModule('setup');
registerPublicFeedRoutes(app, pool);
registerRouteModule('public_feeds');
registerTaxii21Routes(app, pool);
registerRouteModule('taxii21');
registerApiDocsRoutes(app);
registerRouteModule('api_docs');
registerApiV1IocRoutes(app, pool, auditLogService);
registerRouteModule('api_v1_iocs');
registerPublishedFeedRoutes(app, pool, auditLogService);
registerRouteModule('published_feeds');
registerApiKeyRoutes(app, pool, auditLogService);
registerRouteModule('api_keys');
registerAuditLogRoutes(app, pool);
registerAuditRetentionRoutes(app, pool, { audit: auditLogService });
registerRouteModule('audit_retention');
registerIocExportRoutes(app, pool);
registerIocSearchExportRoutes(app, pool, { exportQueue: iocSearchExportQueue, auditLogService });
registerIocSavedSearchRoutes(app, pool, auditLogService);
registerRouteModule('ioc_saved_searches');
registerIocDeepSearchRoutes(app, pool, {
  deepSearchQueue: iocDeepSearchQueue,
  auditLogService,
  logger: appLog,
  // Deep Search result rows are shaped through the exact same enrichment path as the
  // interactive IOC List (byItemIds), so a browsed result is indistinguishable from a live
  // search row.
  mapPageItems: (p, pageItems) => mapIocListPageItems(p, pageItems, { statusFilter: 'all', hasSearch: true, byItemIds: true })
});
registerBackupRoutes(app, pool, { backupQueue: systemBackupQueue, auditLogService });
registerRouteModule('audit');

registerRdapEnrichmentRoutes(app, pool, auditLogService);
registerRouteModule('rdap_enrichment');
registerIpEnrichmentRoutes(app, pool, auditLogService);
registerAbuseIpdbEnrichmentRoutes(app, pool, auditLogService);
registerRouteModule('abuseipdb_enrichment');
registerSpamhausDropEnrichmentRoutes(app, pool, auditLogService, { importQueue });
registerEnrichmentUsageRoutes(app, pool);
registerRouteModule('enrichment_usage');
registerAnalystIntelligenceRoutes(app, pool, auditLogService);
registerRouteModule('analyst_intelligence');
registerRouteModule('ip_enrichment');
registerIocExpirationRoutes(app, pool, auditLogService);
registerRouteModule('ioc_expiration');
registerIocBulkTriageRoutes(app, pool, auditLogService);
registerIocBulkQueryTriageRoutes(app, pool, {
  bulkQueryQueue: iocBulkQueryQueue,
  audit: auditLogService
});
registerRouteModule('ioc_bulk_triage');
registerIocConfidenceRoutes(app, pool, auditLogService, {
  invalidateDetailsCache: invalidateIocDetailsCache
});
registerRouteModule('ioc_confidence');
// Flat name -> color catalog used by the frontend to paint source badges
// consistently across every screen. Merges feed names (integration_feeds,
// covers built-in + custom feeds) with manual IOC source names/display names.
// The same display name can legitimately exist in both integration_feeds and
// ioc_sources (e.g. a manual source whose display_name coincides with a feed
// name). To avoid a silent, scan-order-dependent winner we assign an explicit
// precedence (feed=0 wins over source=1) and a deterministic ORDER BY. The
// `type`/`key` metadata is additive; existing clients only read name+color.
app.get('/api/source-colors', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT name, color, source_type AS type, source_key AS key
       FROM (
         SELECT name, color, 'feed'::text AS source_type, key AS source_key, 0 AS priority
           FROM integration_feeds
           WHERE color IS NOT NULL
         UNION ALL
         SELECT name, color, 'source'::text AS source_type, id::text AS source_key, 1 AS priority
           FROM ioc_sources
           WHERE color IS NOT NULL AND archived_at IS NULL
         UNION ALL
         SELECT display_name AS name, color, 'source'::text AS source_type, id::text AS source_key, 2 AS priority
           FROM ioc_sources
           WHERE color IS NOT NULL AND archived_at IS NULL
             AND display_name IS NOT NULL AND display_name <> name
       ) t
       ORDER BY lower(name), priority, source_key`
    );
    const colors = rows
      .filter((r) => r.name && r.color)
      .map((r) => ({ name: r.name, color: r.color, type: r.type, key: r.key }));
    return res.json({ colors });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to load source colors', detail: err.message });
  }
});

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
  // AUTH-04: ingest synthetic role must not pass human-admin helper checks.
  if (isIngestAuth(req) || req.user?.principalType === 'machine_ingest') return false;
  return isHumanAdmin(req);
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

const TAG_TYPES = new Set(['threat', 'actor', 'technique', 'context']);

app.get('/api/tags', async (req, res) => {
  if (!isAdminUser(req) && !isAnalystUser(req)) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  try {
    const limit = parseTagListLimit(req.query?.limit);
    const search = normalizeTagSearch(req.query?.q);
    const excludeIds = parseExcludeTagIds(req.query?.exclude_ids);
    const params = [];
    const where = ['enabled = TRUE'];

    if (search) {
      params.push(`%${search}%`);
      where.push(`name ILIKE $${params.length}`);
    }
    if (excludeIds.length) {
      params.push(excludeIds);
      where.push(`NOT (id = ANY($${params.length}::int[]))`);
    }
    params.push(limit);

    const q = await pool.query(
      `SELECT id, name, type, enabled
       FROM tags
       WHERE ${where.join(' AND ')}
       ORDER BY type ASC, name ASC
       LIMIT $${params.length}`,
      params
    );
    return res.json(q.rows);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch tags', detail: err.message });
  }
});

app.get('/api/admin/tags', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  try {
    const result = await listAdminTags(pool, req.query || {});
    return res.json({
      items: result.items,
      pagination: result.pagination
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch tags', detail: err.message });
  }
});

app.post('/api/admin/tags', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const parsed = parseNormalizedTagName(req.body?.name);
  if (!parsed.ok) {
    if (parsed.error === 'too_long') return res.status(400).json({ message: 'Tag name is too long', code: 'TAG_TOO_LONG' });
    return res.status(400).json({ message: 'name is required', code: 'TAG_EMPTY' });
  }
  const category = String(req.body?.category || 'custom').trim().toLowerCase();
  if (!isValidCategory(category)) {
    return res.status(400).json({ message: `category must be one of: behavior, campaign, theme, targeting, source-context, review-state, vulnerability, custom` });
  }
  const enabled = req.body?.is_active !== false;
  try {
    const result = await ensureCatalogTag(pool, {
      name: parsed.name,
      createdOrigin: 'manual',
      category,
      description: req.body?.description || null,
      color: req.body?.color || null,
      enabled
    });
    const tag = toPublicTag(result.tag, {
      sources: result.tag.created_origin === 'manual' || !result.existing
        ? ['Manual']
        : undefined
    });
    if (!tag.sources) {
      tag.sources = result.tag.created_origin === 'manual' ? ['Manual'] : [];
    }

    if (result.existing) {
      if (!result.tag.enabled) {
        return res.status(409).json({
          message: 'A disabled tag with this name already exists. Enable it instead of creating a duplicate.',
          code: 'TAG_INACTIVE',
          tag
        });
      }
      return res.status(200).json({ tag, existing: true });
    }

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.TAG_CREATED,
      entityType: AUDIT_ENTITY.TAG,
      entityId: String(tag.id),
      entityDisplay: tag.name,
      after: { name: tag.name, category: tag.category, is_active: Boolean(tag.is_active) }
    });
    return res.status(201).json({ tag, existing: false });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ message: 'Tag already exists', code: 'TAG_DUPLICATE' });
    if (err.code === 'TAG_EMPTY' || err.code === 'TAG_TOO_LONG') {
      return res.status(400).json({ message: err.message, code: err.code });
    }
    return res.status(500).json({ message: 'Failed to create tag', detail: err.message });
  }
});

app.put('/api/admin/tags/:id', async (req, res) => {
  if (!isAdminUser(req)) return res.status(403).json({ message: 'Forbidden' });
  const id = parsePositiveInt(req.params?.id);
  if (!id) return res.status(400).json({ message: 'Invalid id' });
  const fields = [];
  const params = [id];
  // Rename is intentionally unsupported in this phase (feed re-ingest would recreate aliases).
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
    const q = await pool.query(
      `UPDATE tags SET ${fields.join(', ')} WHERE id = $1
       RETURNING id, name, slug, description, color, category, type, enabled, created_origin, created_at, updated_at`,
      params
    );
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
    return res.json({ tag: toPublicTag(r) });
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
    await pool.query('UPDATE tags SET enabled = FALSE, updated_at = NOW() WHERE id = $1 RETURNING id, name, enabled', [id]);
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

  const parsed = parseNormalizedTagName(req.body?.name);
  const type = String(req.body?.type || '').trim().toLowerCase();

  if (!parsed.ok) return res.status(400).json({ message: 'name is required' });
  if (!TAG_TYPES.has(type)) return res.status(400).json({ message: 'Invalid type' });

  try {
    const q = await pool.query(
      `INSERT INTO tags (name, type, slug, category, created_origin)
       VALUES ($1, $2::tag_type, $1, 'custom', 'manual')
       ON CONFLICT (name) DO NOTHING
       RETURNING id, name, type, enabled`,
      [parsed.name, type]
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
         t.type,
         t.enabled
       FROM ioc_items i
       LEFT JOIN ioc_tags it
         ON it.ioc_id = i.id
        AND it.ioc_observable_type = i.observable_type
        AND it.origin = 'manual'
       LEFT JOIN tags t ON t.id = it.tag_id AND t.enabled = TRUE
       WHERE i.id = $1
       ORDER BY t.type ASC NULLS LAST, t.name ASC NULLS LAST`,
      [iocId]
    );

    if (!q.rowCount) return res.status(404).json({ message: 'IOC not found' });

    return res.json(q.rows.filter((row) => row.id != null).map((row) => ({
      id: row.id,
      name: row.name,
      type: row.type,
      is_active: true
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

    const insertResult = await ensureIocTagAssignment(pool, {
      iocId,
      observableType: iocObservableType,
      tagId,
      origin: 'manual',
      createdBy: req.user?.id ?? null
    });

    if (insertResult.inserted) {
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
         AND origin = 'manual'
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

    return res.status(result.status).json(result.body);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create record', detail: err.message });
  }
});

registerIocDeleteRoute(app, pool, auditLogService, { invalidateDetailsCache: invalidateIocDetailsCache });
registerIocSourceRemovalRoute(app, pool, auditLogService, { invalidateDetailsCache: invalidateIocDetailsCache });

async function finalizeIocListPageItems(pool, pageItems, opts = {}) {
  const enriched = await enrichItemsWithActiveSourceCounts(pool, pageItems, opts);
  const [confMap, threatMetaMap, analystMap, feedClassMap, suppressMap] = await Promise.all([
    buildDisplayConfidenceForItems(pool, enriched, {
      includeInactiveMemberships: Boolean(opts.includeInactiveMemberships)
    }),
    enrichItemsWithThreatMetadata(pool, pageItems),
    enrichItemsWithAnalystIntelligenceCounts(pool, pageItems),
    batchLoadFeedClassifications(pool, pageItems),
    batchLoadThreatClassificationSuppressions(pool, pageItems)
  ]);
  return enriched.map((it) => {
    const c = confMap.get(`${Number(it.id)}|${String(it.observable_type)}`) || {};
    const merged = mergeThreatMetadataItem({ ...it, ...c }, threatMetaMap);
    const withFeed = mergeFeedClassificationsIntoItem(merged, feedClassMap, suppressMap);
    return mergeAnalystIntelligenceItem(withFeed, analystMap);
  });
}

async function mapIocListPageItems(pool, pageItems, { statusFilter, hasSearch, byItemIds = false } = {}) {
  const finalized = await finalizeIocListPageItems(pool, pageItems, {
    byItemIds,
    includeInactiveMemberships: hasSearch
  });
  const scoped = hasSearch ? finalized : applyActiveListScope(finalized, statusFilter);
  const withCanonicalTs = await attachCanonicalIocListTimestamps(pool, scoped);
  return decorateIocListItems(withCanonicalTs);
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
            // Browse: 1 oversample CTE window (+optional retry) + enrich fan-out inside resultMapping.
            'path=browse',
            `rows=${browseRows.length}`,
            `responseBytes=${t.responseBytes}`,
            `page=${currentPage}`,
            `pageSize=${limit}`
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
      const obsLimit = Math.min(Math.max(limit * 20, 200), 2000);
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
        let pageItems;
        if (isFileArtifactsReadEnabled()) {
          const { artifactByPublicId, primaryByArtifact } = await loadArtifactMapsForPublicIds(
            pool,
            rows.map((r) => r.public_id)
          );
          const canonical = canonicalizeRowsByIdentity(rows, artifactByPublicId, primaryByArtifact);
          pageItems = canonical.slice(0, limit).map((g) => ({
            id: g.id,
            public_id: g.public_id,
            observable: g.observable,
            observable_type: g.observable_type,
            ip: g.observable,
            status: g.status || 'active',
            created_at: g.created_at || g.imported_at,
            imported_at: g.imported_at || g.created_at,
            first_seen_at: g.first_seen_at,
            last_seen_at: g.imported_at || g.created_at || g.last_seen_at,
            source_count: g.source_count,
            source_names: g.source_names,
            confidence_set: g.confidence_set,
            category_set: g.category_set,
            artifact_id: g.artifact_id || null,
            asn: null,
            country_code: null,
            as_name: null
          }));
          const matchCount = canonical.length;
          const finalItems = await mapIocListPageItems(pool, pageItems, { statusFilter, hasSearch });
          const payload = {
            items: finalItems,
            pagination: buildIocListPagination({
              mode: 'search',
              matchCount,
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
              console.log('[perf][ioc-list]', [
                d('total', t.requestStart, t.responseSent),
                d('db', t.dbQueryStart, t.dbQueryEnd),
                `rows=${finalItems.length}`,
                `path=observables-canonical`
              ].filter(Boolean).join(' '));
            });
            res.setHeader('Content-Type', 'application/json');
            return res.send(payloadStr);
          }
          return res.json(payload);
        }

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
              created_at: r.created_at,
              imported_at: r.created_at,
              first_seen_at: r.created_at,
              last_seen_at: r.created_at,
              status: r.status || 'active',
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.imported_at) {
            g.imported_at = r.created_at;
            g.created_at = r.created_at;
            g.first_seen_at = r.created_at;
            g.last_seen_at = r.created_at;
            g.id = r.id;
            g.public_id = r.public_id;
          }
          if (r.status) g.status = r.status || g.status || 'active';
          if (r.source_name) g._sources.add(r.source_name);
          if (r.confidence) g._conf.add(r.confidence);
          if (r.category) g._cat.add(r.category);
        }

        pageItems = Array.from(grouped.values()).map((g) => ({
          id: g.id,
          public_id: g.public_id,
          observable: g.observable,
          observable_type: g.observable_type,
          ip: g.ip,
          status: g.status || 'active',
          created_at: g.created_at || g.imported_at,
          imported_at: g.imported_at || g.created_at,
          first_seen_at: g.first_seen_at,
          last_seen_at: g.imported_at || g.created_at || g.last_seen_at,
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
      const pageItems = await (async () => {
        if (rows.length === 0) return [];
        if (isFileArtifactsReadEnabled()) {
          const { artifactByPublicId, primaryByArtifact } = await loadArtifactMapsForPublicIds(
            pool,
            rows.map((r) => r.public_id)
          );
          const canonical = canonicalizeRowsByIdentity(rows, artifactByPublicId, primaryByArtifact);
          return canonical.slice(0, limit).map((g) => ({
            id: g.id,
            public_id: g.public_id,
            observable: g.observable,
            observable_type: g.observable_type,
            ip: g.observable,
            status: g.status || 'active',
            created_at: g.created_at || g.imported_at,
            imported_at: g.imported_at || g.created_at,
            first_seen_at: g.first_seen_at,
            last_seen_at: g.imported_at || g.created_at || g.last_seen_at,
            source_count: g.source_count,
            source_names: g.source_names,
            confidence_set: g.confidence_set,
            category_set: g.category_set,
            artifact_id: g.artifact_id || null,
            asn: null,
            country_code: null,
            as_name: null
          }));
        }
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
              created_at: r.created_at,
              imported_at: r.created_at,
              first_seen_at: r.created_at,
              last_seen_at: r.created_at,
              status: r.status || 'active',
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.imported_at) {
            g.imported_at = r.created_at;
            g.created_at = r.created_at;
            g.first_seen_at = r.created_at;
            g.last_seen_at = r.created_at;
            g.id = r.id;
            g.public_id = r.public_id;
          }
          if (r.status) g.status = r.status || g.status || 'active';
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
          created_at: g.created_at || g.imported_at,
          imported_at: g.imported_at || g.created_at,
          first_seen_at: g.first_seen_at,
          last_seen_at: g.imported_at || g.created_at || g.last_seen_at,
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
              created_at: r.created_at,
              imported_at: r.created_at,
              first_seen_at: r.created_at,
              last_seen_at: r.created_at,
              status: r.status || 'active',
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          // Platform import Timestamp = earliest created_at (stable across duplicate rows / re-imports).
          if (r.created_at < g.imported_at) {
            g.imported_at = r.created_at;
            g.created_at = r.created_at;
            g.first_seen_at = r.created_at;
            g.last_seen_at = r.created_at;
            g.id = r.id;
            g.public_id = r.public_id;
          }
          if (r.status) g.status = r.status || g.status || 'active';
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
          created_at: g.created_at || g.imported_at,
          imported_at: g.imported_at || g.created_at,
          first_seen_at: g.first_seen_at,
          last_seen_at: g.imported_at || g.created_at || g.last_seen_at,
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

    const groupedBody = buildGroupedCteBody();
    const base = `
      WITH combined AS (
        ${sourceSql}
      ), filtered AS (
        SELECT * FROM combined
        ${where}
      ), grouped AS (
        ${groupedBody}
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
      SELECT g.id, g.public_id, g.observable, g.observable_type, g.observable AS ip,
             g.platform_imported_at AS created_at,
             g.platform_imported_at AS imported_at,
             g.platform_imported_at AS first_seen_at,
             g.platform_imported_at AS last_seen_at,
             g.status,
             g.source_count,
             g.source_names, g.confidence_set, g.category_set, g.threat_classification, g.threat_actor_id,
             g.artifact_id,
             NULL::bigint AS asn, NULL::text AS country_code, NULL::text AS as_name,
             COUNT(*) OVER()::int AS total
      FROM scoped g
      ORDER BY g.platform_imported_at DESC, g.identity_key ASC
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
      SELECT id, public_id, observable, observable_type, ip,
             platform_imported_at AS created_at,
             platform_imported_at AS imported_at,
             platform_imported_at AS first_seen_at,
             platform_imported_at AS last_seen_at,
             status, source_count,
             source_names, confidence_set, category_set, threat_classification, threat_actor_id,
             artifact_id,
             asn, country_code, as_name, total
      FROM with_geo
      ORDER BY platform_imported_at DESC, identity_key ASC
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

// ---------------------------------------------------------------------------
// Advanced DSL search (structured query language; no free-text fallback).
// ---------------------------------------------------------------------------

function encodeSearchCursor(cursor) {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

function decodeSearchCursor(raw) {
  if (!raw) return null;
  try {
    const obj = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
    if (obj && typeof obj.t === 'string' && obj.id != null) {
      return { t: obj.t, id: String(obj.id), seen: Math.max(0, Number(obj.seen) || 0) };
    }
  } catch {
    /* fall through to invalid cursor */
  }
  return null;
}

function clampSearchPageSize(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return 25;
  return Math.min(Math.max(Math.trunc(n), 1), 100);
}

// Enqueue the current normalized query as a Deep Search and reply with the async contract
// (HTTP 202). Shared by the classifier path and the statement-timeout fallback so both
// produce an identical response. Never returns an error for a valid expensive query.
async function enqueueDeepSearchAndRespond(req, res, { parsed, rawQuery, reason, origin, startedAt }) {
  try {
    const { row, deduped } = await enqueueDeepSearch(pool, iocDeepSearchQueue, {
      originalQuery: String(rawQuery ?? ''),
      normalizedQuery: parsed.normalizedQuery,
      normalizedAst: parsed.ast,
      classificationReason: reason,
      origin,
      requestedById: Number.isFinite(Number(req.user?.id)) ? Number(req.user.id) : null,
      requestedByEmail: String(req.user?.email || req.user?.username || '').trim(),
      auditLogService,
      logger: appLog,
      req
    });
    return res.status(202).json({
      mode: 'deep_search',
      task_type: 'ioc_deep_search',
      deep_search_id: row.id,
      status: row.status,
      reason,
      origin,
      fallback: origin === 'timeout_fallback',
      deduped,
      normalized_query: parsed.normalizedQuery,
      conditions: parsed.conditions,
      query_duration_ms: Date.now() - startedAt
    });
  } catch (err) {
    if (err.status === 401) return res.status(401).json({ message: err.message });
    if (err.status === 429) return res.status(429).json({ message: err.message });
    return res.status(500).json({ message: 'Failed to start deep search' });
  }
}

async function handleIocSearch(req, res) {
  const startedAt = Date.now();
  // DSL query + cursor travel in the POST body: the query can be up to
  // IOC_SEARCH_MAX_QUERY_LENGTH (4000) chars, which would risk URL/proxy length limits
  // as a query string, and keeping it out of the URL avoids logging the raw DSL in
  // access logs.
  const body = req.body || {};
  const rawQuery = body.query ?? '';

  let parsed;
  try {
    parsed = parseSearchQuery(rawQuery);
  } catch (err) {
    if (isDslError(err)) {
      return res.status(400).json({ error: err.toJSON(), message: err.message });
    }
    return res.status(400).json({ message: 'Invalid search query', detail: err.message });
  }

  // Deterministic, AST-based classification: expensive/non-index-friendly queries are routed
  // to an asynchronous Deep Search instead of being run interactively and timing out. Only
  // the initial submit (no cursor) is classified — paging always continues on whichever path
  // produced the first page.
  const cursorIn = decodeSearchCursor(body.cursor);
  if (!cursorIn) {
    const classification = classifyQuery(parsed.ast);
    if (classification.mode === 'deep_search') {
      appLog.info('ioc search classified deep_search', {
        event: 'ioc_search.classified',
        mode: 'deep_search',
        reason: classification.reason,
        query_fingerprint: queryFingerprint(parsed.normalizedQuery)
      });
      return enqueueDeepSearchAndRespond(req, res, {
        parsed,
        rawQuery,
        reason: classification.reason,
        origin: 'classified',
        startedAt
      });
    }
    appLog.info('ioc search classified interactive', {
      event: 'ioc_search.classified',
      mode: 'interactive',
      query_fingerprint: queryFingerprint(parsed.normalizedQuery)
    });
  }

  const previewLimit = getPreviewLimit();
  const timeoutMs = getQueryTimeoutMs();
  const pageSize = clampSearchPageSize(body.page_size);
  const cursor = decodeSearchCursor(body.cursor);
  const seen = cursor ? cursor.seen : 0;
  const remaining = Math.max(previewLimit - seen, 0);

  if (remaining <= 0) {
    return res.json({
      normalized_query: parsed.normalizedQuery,
      conditions: parsed.conditions,
      items: [],
      preview_limit: previewLimit,
      has_more: false,
      next_cursor: null,
      exact_count: null,
      count_display: `${previewLimit.toLocaleString('en-US')}+`,
      query_duration_ms: Date.now() - startedAt,
      warnings: ['Preview capped at the maximum number of records. Export all matching IOCs to retrieve the full result set.']
    });
  }

  const built = buildWhereClause(parsed.ast);
  const whereSql = built.sql;
  const params = [...built.params];
  const dslParamCount = params.length;

  const effectivePageSize = Math.min(pageSize, remaining);
  const fetchLimit = effectivePageSize + 1;

  let keysetClause = '';
  let cursorParamStart = null;
  if (cursor) {
    params.push(cursor.t);
    params.push(cursor.id);
    cursorParamStart = dslParamCount + 1;
    keysetClause = ` AND (i.created_at, i.id) < ($${cursorParamStart}::timestamptz, $${cursorParamStart + 1}::bigint)`;
  }
  params.push(fetchLimit);
  const limitIdx = params.length;

  const faRead = isFileArtifactsReadEnabled();
  const pageSql = buildSearchPageSql({
    fileArtifactsReadEnabled: faRead,
    whereSql,
    keysetClause,
    cursorParamStart,
    limitParamIdx: limitIdx
  });

  // Probe (first page only) to derive an exact count for small result sets or the
  // "N+" indicator for large ones, without a full COUNT. Bounded by previewLimit+1.
  const probeLimit = previewLimit + 1;
  const probeSql = buildSearchProbeSql({
    fileArtifactsReadEnabled: faRead,
    whereSql,
    probeLimit
  });
  const probeParams = built.params;

  const safeTimeout = Math.max(100, Math.min(Math.trunc(timeoutMs), 120000));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL statement_timeout = ${safeTimeout}`);
    // Parallel hash / gather needs extra DSM segments; the db container ships with
    // default 64MiB /dev/shm which OOMs on ~500k-row FA aggregates and surfaces as
    // a non-timeout 500 ("Search failed"). Serialize this transaction only — do not
    // raise container shm as the fix.
    await client.query('SET LOCAL max_parallel_workers_per_gather = 0');

    let exactCount = null;
    let countDisplay = null;
    if (!cursor) {
      const probe = await client.query(probeSql, probeParams);
      if (probe.rowCount > previewLimit) {
        exactCount = null;
        countDisplay = `${previewLimit.toLocaleString('en-US')}+`;
      } else {
        exactCount = probe.rowCount;
        countDisplay = probe.rowCount.toLocaleString('en-US');
      }
    }

    const pageRes = await client.query(pageSql, params);
    await client.query('COMMIT');

    const hasMoreRows = pageRes.rows.length > effectivePageSize;
    const pageRows = pageRes.rows.slice(0, effectivePageSize);
    const newSeen = seen + pageRows.length;
    const capReached = newSeen >= previewLimit;
    const hasMore = hasMoreRows && !capReached;

    const pageItems = pageRows.map((row) => ({
      id: row.id,
      public_id: row.public_id,
      observable: row.observable,
      observable_type: row.observable_type,
      ip: row.observable,
      status: row.status || 'active',
      created_at: row.created_at,
      imported_at: row.created_at,
      first_seen_at: row.first_seen_at || row.created_at,
      last_seen_at: row.created_at,
      artifact_id: row.artifact_id || null,
      source_count: 0,
      source_names: [],
      confidence_set: [],
      category_set: []
    }));

    const items = await mapIocListPageItems(pool, pageItems, {
      statusFilter: 'all',
      hasSearch: true,
      byItemIds: true
    });

    const lastRow = pageRows[pageRows.length - 1];
    const nextCursor = hasMore && lastRow
      ? encodeSearchCursor({
          t: new Date(lastRow.created_at).toISOString(),
          id: String(lastRow.id),
          seen: newSeen
        })
      : null;

    const warnings = [];
    if (capReached && hasMoreRows) {
      warnings.push('More results exist beyond the preview limit. Export all matching IOCs to retrieve the full result set.');
    }

    return res.json({
      normalized_query: parsed.normalizedQuery,
      conditions: parsed.conditions,
      items,
      preview_limit: previewLimit,
      has_more: hasMore,
      next_cursor: nextCursor,
      exact_count: exactCount,
      count_display: countDisplay,
      query_duration_ms: Date.now() - startedAt,
      warnings
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    // Only the real statement-timeout / query-cancel condition (SQLSTATE 57014) is converted
    // to a Deep Search. Every other DB error still fails normally so we never mask a genuine
    // fault as "just slow". The interactive path already classified this query as cheap, so
    // this is the classifier under-calling — continue the exact same normalized query as a
    // background Deep Search instead of returning the old red timeout error. Per-user
    // fingerprint de-dup guarantees at most one job even if paging retriggers the timeout
    // (no recursive retry loop).
    if (err && err.code === '57014') {
      appLog.warn('ioc search interactive statement timeout; continuing as deep_search', {
        event: 'ioc_search.timeout_fallback',
        reason: TIMEOUT_FALLBACK_REASON,
        query_fingerprint: queryFingerprint(parsed.normalizedQuery),
        query_duration_ms: Date.now() - startedAt
      });
      return enqueueDeepSearchAndRespond(req, res, {
        parsed,
        rawQuery,
        reason: TIMEOUT_FALLBACK_REASON,
        origin: 'timeout_fallback',
        startedAt
      });
    }
    return res.status(500).json({ message: 'Search failed', detail: err.message });
  } finally {
    client.release();
  }
}

app.post('/api/iocs/search', handleIocSearch);

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
    let publicId = rows[0]?.public_id || null;

    // When File Artifact read is on, prefer canonical IOC for alias hashes.
    if (publicId && isFileArtifactsReadEnabled()) {
      try {
        const fa = await buildFileArtifactDetailBlock(pool, publicId);
        const canonical = fa?.canonical_ioc_public_id ? String(fa.canonical_ioc_public_id).trim() : '';
        if (
          fa?.is_legacy_alias
          && canonical
          && canonical !== publicId
          && fa?.primary_hash?.hash_type
        ) {
          const reqType = String(observableType || rows[0]?.observable_type || '').toLowerCase();
          const pri = String(fa.primary_hash.hash_type).toLowerCase();
          const rank = (t) => (t === 'sha256' ? 0 : t === 'sha1' ? 1 : t === 'md5' ? 2 : 9);
          if ((reqType === 'md5' || reqType === 'sha1') && rank(pri) < rank(reqType)) {
            publicId = canonical;
          }
        }
      } catch {
        /* keep resolved public_id */
      }
    }

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

  const cached = iocDetailsCache.get(requestedPublicId);
  if (cached && cached.expiresAt > Date.now()) {
    console.log(`[perf][ioc-details] public_id=${requestedPublicId} cache=hit total_ms=${Date.now() - startedAt} pg_ms=0`);
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
        i.manual_override_reason,
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
      console.log(`[perf][ioc-details] public_id=${requestedPublicId} cache=miss total_ms=${Date.now() - startedAt} pg_ms=${pgMs} rows=0 matches=0`);
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
    try {
      const feedTagNames = (feedIntelligence?.tags || []).map((t) => t?.normalized || t?.tag).filter(Boolean);
      const disabledNames = await loadDisabledTagNameSet(pool, feedTagNames);
      feedIntelligence = filterFeedIntelligenceByDisabledTags(feedIntelligence, disabledNames);
    } catch (err) {
      console.warn('[ioc-details] disabled catalog tag filter skipped:', err.message);
    }

    const threatMetadataFields = await buildThreatMetadataFields(pool, lifecycleRow, {
      feedClassifications: rawFeedIntelligence?.classifications || []
    });

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
      // expiration_reason describes WHY an IOC expired; it is meaningless while active.
      // Suppress it for active IOCs so a manual source's lifecycle sentinel
      // (manual_never_expire / manual_custom_expire) never leaks as an "expiration reason".
      expiration_reason: String(lifecycleRow.status || 'active').toLowerCase() === 'expired'
        ? (lifecycleRow.expiration_reason || null)
        : null,
      reactivated_by_match_at: lifecycleRow.reactivated_by_match_at || null,
      ...threatMetadataFields,
      // Analyst-facing "Manual Override": TRUE only for an explicit lifecycle override
      // (Expire IOC now / reactivate / custom expiry / bulk expire). A manual *source*
      // carries manual_status_override for its own expiry bookkeeping but is NOT an override.
      manual_status_override: isExplicitIocLifecycleOverride(lifecycleRow),
      manual_status: lifecycleRow.manual_status || null,
      // Platform insert = earliest ioc_items.created_at (immutable). API alias: imported_at.
      ...(() => {
        const platform = resolveDetailPlatformImportTimestamp(rows);
        return {
          created_at: platform.created_at,
          imported_at: platform.imported_at
        };
      })(),
      first_seen_at: globalFirstSeenAt,
      // Analyst "last changed in source" aggregate (legacy field name kept for clients).
      last_seen_at: globalLastSeenAt,
      // Presence confirmation across feeds — null when no last_seen_in_feed (no silent fallback).
      last_confirmed_at: resolveDetailLastConfirmedAt(membershipSummary.membershipRows),
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
      `SELECT id, active, scope, source_name, reason, created_by, created_at, updated_at, expires_at,
              ioc_value, ioc_type
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
    let activeSuppression = suppressionQ.rowCount ? suppressionQ.rows[0] : null;
    let artifactSuppressionHits = [];

    const fileArtifact = await buildFileArtifactDetailBlock(pool, requestedPublicId);
    if (fileArtifact?.known_hashes?.length) {
      // Enrich file_information with artifact known hashes (additive)
      const fi = summary.file_information || {};
      for (const h of fileArtifact.known_hashes) {
        if (h.hash_type === 'md5' && !fi.md5) fi.md5 = h.value;
        if (h.hash_type === 'sha1' && !fi.sha1) fi.sha1 = h.value;
        if (h.hash_type === 'sha256' && !fi.sha256) fi.sha256 = h.value;
      }
      summary.file_information = fi;

      // Aggregate suppressions across linked exact hashes (do not rewrite rows)
      const vals = fileArtifact.known_hashes.map((h) => h.value);
      const types = fileArtifact.known_hashes.map((h) => h.hash_type);
      const aggSup = await pool.query(
        `SELECT id, active, scope, source_name, reason, created_by, created_at, updated_at, expires_at,
                ioc_value, ioc_type
         FROM ioc_suppressions
         WHERE active = TRUE
           AND deleted_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW())
           AND lower(ioc_value) = ANY($1::text[])
           AND lower(ioc_type) = ANY($2::text[])`,
        [vals.map((v) => String(v).toLowerCase()), types.map((t) => String(t).toLowerCase())]
      );
      artifactSuppressionHits = aggSup.rows;
      if (!activeSuppression && artifactSuppressionHits.length) {
        activeSuppression = artifactSuppressionHits[0];
      }
    }

    // Augment confidence detail with highest_active_source_confidence so the UI
    // can show provenance separately from the effective value when analyst override is active.
    const enrichedConfidenceDetail = confidenceDetail
      ? { ...confidenceDetail, highest_active_source_confidence: highestActiveSourceConfidence }
      : null;

    const payload = {
      summary,
      confidence: enrichedConfidenceDetail,
      // Legacy Source Evidence projection removed; use active_sources / feed_memberships.
      sources: [],
      historical_ioc_rows: rows.filter((r) => String(r.status || 'active') !== 'active'),
      active_sources: membershipSummary.activeSources,
      historical_sources: membershipSummary.historicalSources,
      feed_memberships: membershipSummary.membershipRows,
      matches: [],
      incidents,
      impact,
      analyst_intelligence_summary: analystIntelligenceSummary,
      suppression: activeSuppression
        ? {
            ...activeSuppression,
            active: true,
            artifact_suppressions: artifactSuppressionHits.length ? artifactSuppressionHits : undefined
          }
        : { active: false },
      file_artifact: fileArtifact || null
    };

    iocDetailsCache.set(requestedPublicId, { expiresAt: Date.now() + IOC_DETAILS_CACHE_TTL_MS, payload });
    console.log(`[perf][ioc-details] public_id=${requestedPublicId} cache=miss total_ms=${Date.now() - startedAt} pg_ms=${pgMs} rows=${rows.length} incidents=${incidents.length}`);

    return res.json(payload);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch IOC details', detail: err.message });
  }
});

/** File artifact detail by artifact UUID (feature-flagged). */
app.get('/api/file-artifacts/:artifactId', async (req, res) => {
  try {
    if (!isFileArtifactsReadEnabled()) {
      return res.status(404).json({ message: 'File artifacts read path is disabled' });
    }
    const artifactId = String(req.params.artifactId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(artifactId)) {
      return res.status(400).json({ message: 'Invalid artifact id' });
    }
    const detail = await loadArtifactDetail(pool, artifactId);
    if (!detail) return res.status(404).json({ message: 'File artifact not found' });
    return res.json(detail);
  } catch (err) {
    if (err?.code === '42P01') {
      return res.status(404).json({ message: 'File artifacts schema not migrated' });
    }
    return res.status(500).json({ message: 'Failed to fetch file artifact', detail: err.message });
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


async function ensureDefaultAdmin() {
  try {
    await ensureDefaultAdminBootstrap(pool, { logger: appLog });
  } catch (err) {
    appLog.warn('default admin bootstrap skipped', { error: err?.message || String(err) });
  }

  // Reconcile the protected system administrator flag on every startup. This NEVER creates an
  // account with the well-known default password on an existing install. A missing system admin
  // is not swallowed as success:
  //   - if another active admin exists, we log a high-priority actionable error and continue;
  //   - if the invariant cannot be met (no active admin at all) or reconcile errors out, we abort
  //     startup so the problem is loud and the operator must act.
  try {
    const result = await ensureSystemAdminAccount(pool, { logger: appLog });
    if (result?.status === 'missing_manual_required') {
      appLog.error(
        '[SECURITY] Protected system administrator account (admin@talonhound.local) is MISSING and was NOT auto-created. ' +
          SYSTEM_ADMIN_MANUAL_INSTRUCTION +
          ' Backend is continuing only because other active administrators exist.',
        { active_admins: result.activeAdminCount, reason: result.reason }
      );
    }
  } catch (err) {
    appLog.error(
      '[SECURITY] Could not establish the protected system administrator account; aborting startup. ' +
        SYSTEM_ADMIN_MANUAL_INSTRUCTION,
      { error: err?.message || String(err) }
    );
    // Fail loudly rather than run without a protected system admin and no safe fallback.
    process.exit(1);
  }
}

// Poll resolution for Published Feed due checks (default 60s). Due filtering is cheap;
// expensive generation only runs for feeds that pass isPublishedFeedDue.
const PUBLISHED_FEED_TICK_MS = resolvePublishedFeedTickMs();
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
    file: {
      md5: attr.md5 || null,
      sha1: attr.sha1 || null,
      sha256: attr.sha256 || null,
      names: Array.isArray(attr.names) ? attr.names.slice(0, 10) : [],
      type_description: attr.type_description || null
    }
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
  // Usage telemetry timing (hoisted so the catch block can read them).
  let vtStartedAt = 0;
  let vtExternalAttempted = false;

  try {
    // Central disable guard: no external call for a disabled provider.
    if (!(await guardProviderEnabled(pool, VT_PROVIDER, res))) return;

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

    // Usage telemetry: VT refresh always performs a real outbound provider call
    // (there is no cache short-circuit here). Time it for provider-latency metrics.
    vtStartedAt = Date.now();

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), providerCfg.timeout_ms || VT_TIMEOUT_MS);
    let vtRes;
    try {
      vtExternalAttempted = true;
      vtRes = await fetch(`https://www.virustotal.com/api/v3${endpoint}`, { headers: { 'x-apikey': vtKey }, signal: ctrl.signal });
    } finally { clearTimeout(t); }

    if (vtRes.status === 429) {
      recordEnrichmentUsage(pool, { provider: VT_PROVIDER, iocType, outcome: 'failure', external: true, rateLimited: true, responseTimeMs: Date.now() - vtStartedAt });
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
      // A 404 is a completed lookup ("no report yet"), not a failure.
      recordEnrichmentUsage(pool, { provider: VT_PROVIDER, iocType, outcome: 'success', external: true, responseTimeMs: Date.now() - vtStartedAt });
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
      recordEnrichmentUsage(pool, { provider: VT_PROVIDER, iocType, outcome: 'failure', external: true, responseTimeMs: Date.now() - vtStartedAt });
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
      recordEnrichmentUsage(pool, { provider: VT_PROVIDER, iocType, outcome: 'failure', external: true, responseTimeMs: Date.now() - vtStartedAt });
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

    // Dual-write: attach VT exact hash set to file artifact when enabled
    try {
      const { dualWriteFileArtifactForObservable, extractExactHashesFromVtRaw, isFileArtifactsDualWriteEnabled } = await import('./lib/fileArtifacts/index.js');
      if (isFileArtifactsDualWriteEnabled() && extractExactHashesFromVtRaw(raw).length >= 1) {
        const noteParts = [];
        const attr = raw?.data?.attributes || {};
        if (attr.md5) noteParts.push(`md5=${String(attr.md5).toLowerCase()}`);
        if (attr.sha1) noteParts.push(`sha1=${String(attr.sha1).toLowerCase()}`);
        if (attr.sha256) noteParts.push(`sha256=${String(attr.sha256).toLowerCase()}`);
        await dualWriteFileArtifactForObservable(pool, {
          observable: item.ioc_value,
          observableType: iocType === 'hash'
            ? (attr.sha256 ? 'sha256' : (attr.sha1 ? 'sha1' : 'md5'))
            : iocType,
          sourceName: 'VirusTotal',
          note: noteParts.join(' | '),
          attachNoteSiblings: true,
          providerMapping: true,
          observationType: 'enrichment_derived',
          relationMethod: 'enrichment_result'
        });
      }
    } catch {
      // never fail VT enrichment on artifact dual-write
    }

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

    recordEnrichmentUsage(pool, { provider: VT_PROVIDER, iocType, outcome: 'success', external: true, responseTimeMs: Date.now() - vtStartedAt });
    return res.json({ status: 'success', provider: VT_PROVIDER, is_error: false, summary, fetched_at: fetchedAt.toISOString(), expires_at: expiresAt.toISOString() });
  } catch (err) {
    // Telemetry: only count a provider consumption when the outbound call was actually
    // attempted (timeouts/network errors); pre-fetch failures are not provider calls.
    if (vtExternalAttempted) {
      recordEnrichmentUsage(pool, { provider: VT_PROVIDER, iocType, outcome: 'failure', external: true, responseTimeMs: Date.now() - vtStartedAt });
    }
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

async function loadEnrichmentProviderSummaries() {
  const [cfg, ipinfo, abuseipdb, sdCfg, sdState] = await Promise.all([
    getThreatIntelProviderConfig(VT_PROVIDER),
    getIpinfoLiteConfig(pool),
    getAbuseIpdbConfig(pool),
    getSpamhausDropConfig(pool),
    getSpamhausDropSyncState(pool)
  ]);
  const lastSpamhausSuccess = sdState.map((s) => s.last_success_at).filter(Boolean)
    .reduce((a, b) => (a && new Date(a) > new Date(b) ? a : b), null);

  return attachProviderHealth(pool, [
      {
        provider: VT_PROVIDER,
        name: 'VirusTotal',
        enabled: cfg.enabled,
        configured: cfg.configured,
        masked_key: maskApiKey(cfg.apiKey),
        source: cfg.source,
        ttl_hours: cfg.ttl_hours,
        timeout_ms: cfg.timeout_ms,
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
        last_test_at: abuseipdb.last_test_at,
        last_success_at: abuseipdb.last_success_at,
        last_error_at: abuseipdb.last_error_at,
        last_error_message: abuseipdb.last_error_message
      },
      getRdapProviderAdminSummary(),
      {
        provider: 'spamhaus_drop',
        name: 'Spamhaus DROP',
        enabled: sdCfg.enabled,
        configured: true,
        sync_interval_hours: sdCfg.sync_interval_hours,
        timeout_ms: sdCfg.timeout_ms,
        last_success_at: lastSpamhausSuccess,
        sync_state: sdState
      }
    ]);
}

app.get('/api/admin/enrichment-providers', async (_req, res) => {
  try {
    return res.json({ providers: await loadEnrichmentProviderSummaries() });
  } catch { return res.status(500).json({ message: 'Failed to load enrichment providers' }); }
});

async function loadSystemFeedHealth() {
  const feedsRes = await pool.query(`
    SELECT key, name, active, schedule_cron
    FROM integration_feeds
    WHERE archived_at IS NULL
      AND COALESCE(feed_kind, 'built_in') <> 'custom'
    ORDER BY name
  `);
  const feeds = feedsRes.rows || [];
  const jobTypes = [...new Set(feeds.map((feed) => feedJobType(feed.key)))];
  if (!jobTypes.length) return [];

  const [latestRes, successRes, recentRes] = await Promise.all([
    pool.query(`
      SELECT DISTINCT ON (job_type)
        job_type, status, started_at, finished_at, error_message, run_details
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
      ORDER BY job_type, started_at DESC
    `, [jobTypes]),
    pool.query(`
      SELECT DISTINCT ON (job_type)
        job_type, status, started_at, finished_at
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
        AND status IN ('success','skipped','skipped_unchanged')
      ORDER BY job_type, started_at DESC
    `, [jobTypes]),
    pool.query(`
      SELECT job_type, status, started_at
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
      ORDER BY job_type, started_at DESC
      LIMIT 300
    `, [jobTypes])
  ]);
  const latestByJob = new Map(latestRes.rows.map((row) => [row.job_type, row]));
  const successByJob = new Map(successRes.rows.map((row) => [row.job_type, row]));

  return feeds.map((feed) => {
    const jobType = feedJobType(feed.key);
    const latest = latestByJob.get(jobType) || null;
    const lastSuccess = successByJob.get(jobType) || null;
    const consecutiveFailures = computeConsecutiveFailures(recentRes.rows, jobType);
    const healthStatus = pickHealthStatus(latest, lastSuccess);
    const state = resolveFeedHealthState(
      feed.active !== false,
      healthStatus,
      consecutiveFailures,
      [],
      { runDetails: latest?.run_details || null }
    );
    const status = feed.active === false
      ? 'unknown'
      : state === 'success'
        ? 'healthy'
        : state === 'failed'
          ? 'unhealthy'
          : state === 'warning' || state === 'degraded'
            ? 'degraded'
            : 'unknown';
    return {
      key: feed.key,
      name: feed.name,
      enabled: feed.active !== false,
      status,
      reason: feed.active === false ? 'disabled' : state === 'never' ? 'never_run' : `last_result_${state}`,
      runtime_state: resolveFeedRuntimeState(latest?.status),
      last_success_at: lastSuccess?.finished_at || lastSuccess?.started_at || null,
      last_failure_at: latest?.status === 'failed' ? (latest.finished_at || latest.started_at) : null,
      last_error: latest?.status === 'failed' ? latest.error_message || null : null,
      consecutive_failures: consecutiveFailures,
      include_in_overall: feed.active !== false
    };
  });
}

async function loadBullWorkerHealth(queue, key, name) {
  try {
    const workers = await queue.getWorkers();
    const count = Array.isArray(workers) ? workers.length : 0;
    return {
      key,
      name,
      status: count > 0 ? 'healthy' : 'unknown',
      reason: count > 0 ? 'worker_registered' : 'no_registered_worker',
      worker_count: count
    };
  } catch {
    return { key, name, status: 'unknown', reason: 'worker_lookup_failed', worker_count: null };
  }
}

app.get('/api/system/health', async (_req, res) => {
  const checkedAt = new Date().toISOString();
  const readiness = await runReadinessChecks(pool, redis);
  const timeHealth = await buildTimeHealth(pool).catch(() => null);
  const core = [
    { key: 'backend', name: 'Backend API', status: 'healthy', required: true },
    {
      key: 'postgres',
      name: 'PostgreSQL',
      status: readiness.checks.postgres === 'ok' ? 'healthy' : readiness.checks.postgres === 'error' ? 'unhealthy' : 'unknown',
      required: true
    },
    {
      key: 'redis',
      name: 'Redis',
      status: readiness.checks.redis === 'ok' ? 'healthy' : readiness.checks.redis === 'error' ? 'unhealthy' : 'unknown',
      required: true
    },
    {
      key: 'date_time',
      name: 'Date & time',
      status: timeHealth ? normalizeComponentStatus(timeHealth.status) : 'unknown',
      reason: timeHealth?.reason || timeHealth?.error || null,
      required: true
    }
  ];

  const [providerResult, feedResult, workerResult, queueResult] = await Promise.all([
    loadEnrichmentProviderSummaries().catch(() => null),
    readiness.checks.postgres === 'ok' ? loadSystemFeedHealth().catch(() => null) : Promise.resolve(null),
    Promise.all([
      loadBullWorkerHealth(importQueue, 'integration_worker', 'Integration worker'),
      loadBullWorkerHealth(iocSearchExportQueue, 'ioc_search_export_worker', 'IOC search export worker'),
      loadBullWorkerHealth(iocDeepSearchQueue, 'ioc_deep_search_worker', 'IOC deep search worker'),
      loadBullWorkerHealth(iocBulkQueryQueue, 'ioc_bulk_query_worker', 'IOC bulk query worker'),
      loadBullWorkerHealth(systemBackupQueue, 'backup_worker', 'Backup worker')
    ]),
    readiness.ok
      ? loadIntegrationQueueHealthSnapshot(pool, importQueue).catch(() => null)
      : Promise.resolve(null)
  ]);

  const providers = providerResult
    ? providerResult.map((provider) => ({
        key: provider.provider,
        name: provider.name,
        enabled: provider.enabled !== false,
        configured: provider.configured !== false,
        status: provider.health.status,
        reason: provider.health.reason,
        evidence: provider.health.evidence || null,
        last_success_at: provider.health.last_success_at,
        last_failure_at: provider.health.last_failure_at,
        last_checked_at: provider.health.last_checked_at,
        last_enrichment_at: provider.last_enrichment_at || null,
        include_in_overall: provider.enabled !== false
      }))
    : [{ key: 'providers', name: 'Enrichment providers', status: 'unknown', reason: 'evidence_unavailable' }];
  const feeds = feedResult || [{ key: 'feeds', name: 'Threat feeds', status: 'unknown', reason: 'evidence_unavailable' }];
  const workers = [
    ...workerResult,
    { key: 'integration_scheduler', name: 'Integration scheduler', status: 'unknown', reason: 'heartbeat_unavailable' },
    { key: 'ioc_expiration_worker', name: 'IOC expiration worker', status: 'unknown', reason: 'heartbeat_unavailable' }
  ];
  const queues = queueResult
    ? [{
        key: 'integration_queue',
        name: 'Integration queue',
        status: normalizeComponentStatus(queueResult.health?.queue_health),
        reason: queueResult.health?.warnings?.[0] || null,
        waiting: queueResult.health?.bullmq_waiting ?? null,
        active: queueResult.health?.bullmq_active ?? null,
        stalled: queueResult.health?.bullmq_stalled ?? null,
        worker_count: queueResult.worker_count
      }]
    : [{ key: 'integration_queue', name: 'Integration queue', status: 'unknown', reason: 'snapshot_unavailable' }];
  const overall = resolveOverallSystemHealth({ core, workers, feeds, providers, queues });

  return res.json({
    checked_at: checkedAt,
    overall,
    summary: {
      core: summarizeHealth(core),
      workers: summarizeHealth(workers),
      feeds: summarizeHealth(feeds.filter((feed) => feed.enabled !== false)),
      providers: summarizeHealth(providers.filter((provider) => provider.enabled !== false)),
      queues: summarizeHealth(queues)
    },
    sections: { core, workers, feeds, providers, queues }
  });
});

app.put('/api/admin/enrichment-providers/virustotal', requireRole(ROLES.ADMIN), async (req, res) => {
  try {
    const enabled = req.body?.enabled !== false;
    const ttl = Math.max(1, Number(req.body?.ttl_hours || 24));
    const timeout = Math.max(3000, Number(req.body?.timeout_ms || 12000));
    const apiKey = typeof req.body?.api_key === 'string' ? req.body.api_key.trim() : undefined;
    const previous = await getThreatIntelProviderConfig(VT_PROVIDER);
    await pool.query(`INSERT INTO threat_intel_provider_configs(provider,enabled,ttl_hours,timeout_ms,api_key,updated_at)
      VALUES ($1,$2,$3,$4,$5,NOW())
      ON CONFLICT(provider) DO UPDATE SET enabled=$2, ttl_hours=$3, timeout_ms=$4, api_key=COALESCE(NULLIF($5,''), threat_intel_provider_configs.api_key), updated_at=NOW()`,
      [VT_PROVIDER, enabled, ttl, timeout, apiKey]);
    await auditProviderConfigUpdate(auditLogService, req, {
      provider: VT_PROVIDER,
      displayName: 'VirusTotal',
      previousEnabled: previous.enabled,
      newEnabled: enabled,
      after: { ttl_hours: ttl, timeout_ms: timeout, api_key_updated: Boolean(apiKey) }
    });
    return res.json({ ok: true });
  } catch { return res.status(500).json({ message: 'Failed to update provider config' }); }
});

app.post('/api/admin/enrichment-providers/virustotal/remove-key', requireRole(ROLES.ADMIN), async (req, res) => {
  try { await pool.query(`UPDATE threat_intel_provider_configs SET api_key=NULL, updated_at=NOW() WHERE provider=$1`, [VT_PROVIDER]); return res.json({ ok: true }); }
  catch { return res.status(500).json({ message: 'Failed to remove key' }); }
});

// Manual "Test Connection" — routes through the canonical provider health probe
// so manual and scheduled checks share one implementation and one health store.
// A successful test updates canonical health to Healthy immediately.
app.post('/api/admin/enrichment-providers/virustotal/test', requireRole(ROLES.ADMIN), async (req, res) => {
  const cfg = await getThreatIntelProviderConfig(VT_PROVIDER).catch(() => ({ configured: false }));
  if (!cfg.configured) return res.status(400).json({ message: 'VirusTotal API key is not configured' });
  const result = await runProviderHealthProbe(pool, VT_PROVIDER, { source: 'manual' });
  if (result.ok) return res.json({ ok: true, message: 'Connection successful' });
  if (result.category === 'rate_limit') return res.status(429).json({ message: 'VirusTotal rate limit reached. Try again later.' });
  if (result.category === 'auth') return res.status(400).json({ message: 'Invalid VirusTotal API key' });
  if (result.category === 'timeout') return res.status(504).json({ message: 'VirusTotal test timeout' });
  return res.status(502).json({ message: 'VirusTotal test failed' });
});

// RDAP / WHOIS "Test Connection". RDAP needs no API key, so an enabled RDAP is
// always testable. The probe performs a real, UNCACHED RDAP lookup of a
// standards-reserved domain through the production RDAP client (bootstrap + DNS
// + TLS + HTTP + redirect + parse), and updates canonical health on success.
app.post('/api/admin/enrichment-providers/rdap/test', requireRole(ROLES.ADMIN), async (req, res) => {
  const result = await runProviderHealthProbe(pool, 'rdap', { source: 'manual' });
  if (result.skipped && result.reason === 'disabled') {
    return res.status(409).json({ message: 'RDAP provider is disabled' });
  }
  if (result.ok) {
    return res.json({ ok: true, message: 'Connection successful', registrar: result.detail?.registrar || null });
  }
  if (result.category === 'rate_limit') return res.status(429).json({ message: 'RDAP rate limit reached. Try again later.' });
  if (result.category === 'timeout') return res.status(504).json({ message: 'RDAP test timeout' });
  return res.status(502).json({ message: 'RDAP connection test failed' });
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
  try {
    const { config: sessionCfg, warnings } = validateSessionConfig();
    console.log(
      `[session] bounded sessions: access_ttl=${sessionCfg.accessTtlSeconds}s idle=${Math.round(sessionCfg.idleMs / 60000)}m absolute=${Math.round(sessionCfg.absoluteMs / 3600000)}h`
    );
    for (const w of warnings) appLog.warn('session config warning', { warning: w });
  } catch (err) {
    appLog.error('invalid session configuration', { error: err?.message || String(err) });
    process.exit(1);
  }
  logRegisteredRouteModules();
  await syncRuntimeTimezoneFromDb();
  if (IOC_LIST_TIMING) {
    console.log('[ioc/list] IOC_LIST_TIMING=1: timing logs enabled (searchStringParse, dbQuery, responseSent, etc.). Use ?timing=1 per request if env not set.');
  }
  await ensureDefaultAdmin();
  runIocListStatsRefreshTick().catch(() => {});
  setInterval(() => {
    runIocListStatsRefreshTick().catch(() => {});
  }, IOC_LIST_STATS_REFRESH_MS);
  // Startup reconciliation: reclaim abandoned Published Feed ".part" temp files left by a
  // crash/restart mid-generation (only touches stale temps, never published artifacts).
  import('./lib/publishedFeedArtifact/store.js')
    .then(({ reconcileStaleParts, getPublishedFeedArtifactConfig }) =>
      reconcileStaleParts(getPublishedFeedArtifactConfig()))
    .catch(() => {});
  import('./lib/publishedFeedChunkGeneration.js')
    .then(({ cleanupPublishedFeedChunkGenerations }) =>
      cleanupPublishedFeedChunkGenerations(pool))
    .catch(() => {});
  regenerateAllEnabledFeeds(pool).catch(() => {});
  setInterval(() => {
    if (publishedFeedTickInProgress) return;
    publishedFeedTickInProgress = true;
    regenerateAllEnabledFeeds(pool)
      .catch((err) => console.error('[published-feeds] tick failed', err?.message || err))
      .then(() => import('./lib/publishedFeedChunkGeneration.js'))
      .then(({ cleanupPublishedFeedChunkGenerations }) =>
        cleanupPublishedFeedChunkGenerations(pool))
      .then(() => cleanupPublishedFeedLegacyArtifacts(pool))
      .catch((err) => console.error('[published-feeds] cleanup failed', err?.message || err))
      .finally(() => {
        publishedFeedTickInProgress = false;
      });
  }, PUBLISHED_FEED_TICK_MS);
});
