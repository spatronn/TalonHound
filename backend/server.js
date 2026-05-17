import './lib/ensure-db-password.js';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import IORedis from 'ioredis';
import { Queue } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { query as clickhouseQuery, ensureSyslogTable, pingClickhouse } from './lib/clickhouse.js';
import {
  signUserToken,
  apiAuthGate,
  csrfProtection,
  appendAuthCookie,
  clearAuthCookie,
  appendCsrfCookie,
  clearCsrfCookie
} from './lib/auth.js';
import { rbacHttpPolicy, ROLES } from './lib/rbac.js';
import { registerUserManagementRoutes } from './routes/users.js';
import { registerPublishedFeedRoutes } from './routes/publishedFeeds.js';
import { registerPublicFeedRoutes } from './routes/publicFeeds.js';
import { regenerateAllEnabledFeeds } from './lib/feedPublisherService.js';
import { calculateIncidentRisk, calculateInstitutionRisk } from './lib/riskEngine.js';
import { IOC_MATCH_EVENT_STATS_SELECT } from './lib/incidentEventAggSql.js';
import { createLlmRiskAdvisor } from './risk/llmRiskAdvisor.js';
import { enrichIncidentContextWithRelatedIocs, summarizeRelatedIocSignals } from './risk/incidentAiInsightContext.js';

const { Pool } = pg;

const app = express();
const port = process.env.PORT || 3000;
const demoEmail = process.env.DEMO_EMAIL || 'demo@demo.local';
const demoPassword = process.env.DEMO_PASSWORD || 'Password1!';
const LOG_STORAGE = (process.env.LOG_STORAGE || 'postgres').toLowerCase();
const USE_CLICKHOUSE = LOG_STORAGE === 'clickhouse';

// Single shared pool: no new Client() per request; connections are reused (recommended for latency).
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const redisUrl = getRedisUrl();
const queueName = process.env.QUEUE_NAME || 'integration-imports';
const signalQueueName = process.env.SIGNAL_QUEUE_NAME || 'signal-events';
const llmRiskQueueName = process.env.LLM_RISK_QUEUE_NAME || 'llm-risk-jobs';
const redis = new IORedis(redisUrl, { maxRetriesPerRequest: null });
const importQueue = new Queue(queueName, { connection: redis });
const signalQueue = new Queue(signalQueueName, { connection: redis });
const llmRiskQueue = new Queue(llmRiskQueueName, { connection: redis });
const llmRiskAdvisor = createLlmRiskAdvisor({ redis, queue: llmRiskQueue, db: pool });

// Geo cache refresh tuning (local/kısıtlı ortam için düşürülebilir)

/** IOC list timing: IOC_LIST_TIMING=1 or query ?timing=1 to log searchStringParse, dbConnectionAcquired, dbQuery, countQuery, resultMapping, jsonSerialization, responseSent (ms). */
const IOC_LIST_TIMING = process.env.IOC_LIST_TIMING === '1' || process.env.IOC_LIST_TIMING === 'true';
/** Integrations list timing: INTEGRATIONS_TIMING=1 logs base feed, latest run, queue, and total handler durations (ms). */
const INTEGRATIONS_TIMING = process.env.INTEGRATIONS_TIMING === '1' || process.env.INTEGRATIONS_TIMING === 'true';
const INTEGRATIONS_META_QUERY_TIMEOUT_MS = Math.max(Number(process.env.INTEGRATIONS_META_QUERY_TIMEOUT_MS || 5000), 1000);
/** Hash-only (sha256:/md5:/sha1: no asn/country) uses single SELECT + JS group by default. Set IOC_LIST_USE_CTE_FOR_HASH=1 to force the full CTE path. */
const IOC_LIST_USE_CTE_FOR_HASH = process.env.IOC_LIST_USE_CTE_FOR_HASH === '1' || process.env.IOC_LIST_USE_CTE_FOR_HASH === 'true';

// In-memory cache for IOC stats/summary (non-real-time aggregations, feed-aware via last_update + TTL).
const IOC_STATS_TTL_MS = 60 * 60 * 1000; // 1 hour
let iocStatsCache = {
  key: null,
  data: null,
  createdAt: 0,
  lastUpdate: null
};

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
  const n = String(v ?? '0').replace(/[^0-9]/g, '');
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

function escapeChString(v) {
  return String(v ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

/** Squid / explicit HTTP proxy evidence in a raw syslog line (shared list + detail context). */
function rawLooksLikeSquidOrHttpProxy(raw) {
  return /\bsquid[_\s-]?proxy\b|\bTCP_(?:TUNNEL|MISS|HIT|DENIED|REFRESH|MEM_HIT|CLIENT_REFRESH)\/[0-9-]{3}|\bCONNECT\s+[^\s]+:[0-9]+|\bHIER_DIRECT\//i.test(String(raw || ''));
}

/**
 * Prefer ClickHouse syslog_logs bulk match when incident_related_logs snapshot is missing
 * proxy-shaped evidence (common when source_type/parser metadata is stale).
 */
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

async function withRawSyslogEvent(row) {
  if (!USE_CLICKHOUSE) return row;

  try {
    const parserSource = String(row?.parser_source || '').trim().toLowerCase();
    if (parserSource === 'microsoft_dns_debug') return row;

    const matched = String(row?.matched_ioc || '').trim();
    if (!matched) return row;

    const ts = row?.event_time ? new Date(row.event_time) : null;
    const tsStart = ts ? new Date(ts.getTime() - 10 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ') : null;
    const tsEnd = ts ? new Date(ts.getTime() + 10 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ') : null;

    const baseWhereParts = [];
    if (tsStart && tsEnd) baseWhereParts.push(`ts BETWEEN toDateTime('${tsStart}') AND toDateTime('${tsEnd}')`);

    const rowSource = String(row?.source || '').trim();
    const rowHost = String(row?.host_name || '').trim();
    const rowParser = String(row?.parser_source || '').trim();
    const rowDestIp = String(row?.destination_ip || '').trim();

    const escapedMatched = escapeChString(matched);
    const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(matched);
    const iocClause = isIp
      ? `(ioc_ip = '${escapedMatched}' OR parsed_ip = '${escapedMatched}' OR position(COALESCE(raw, message), '${escapedMatched}') > 0)`
      : `(
          ioc_query = '${escapedMatched}'
          OR lower(ioc_query) = lower('${escapedMatched}')
          OR lower(parsed_query) = lower('${escapedMatched}')
          OR positionCaseInsensitiveUTF8(COALESCE(raw, message), '${escapedMatched}') > 0
        )`;

    const strictParts = [...baseWhereParts];
    if (rowSource) strictParts.push(`source = '${escapeChString(rowSource)}'`);
    if (rowHost) strictParts.push(`host = '${escapeChString(rowHost)}'`);
    if (rowParser) strictParts.push(`parser_source = '${escapeChString(rowParser)}'`);
    if (rowDestIp) strictParts.push(`(parsed_ip = '${escapeChString(rowDestIp)}' OR ioc_ip = '${escapeChString(rowDestIp)}')`);
    strictParts.push(iocClause);

    const mediumParts = [...baseWhereParts];
    if (rowSource) mediumParts.push(`source = '${escapeChString(rowSource)}'`);
    if (rowParser) mediumParts.push(`parser_source = '${escapeChString(rowParser)}'`);
    mediumParts.push(iocClause);

    const relaxedParts = [...baseWhereParts, iocClause];

    // If event_time is delayed/skewed against ClickHouse ts, try without time window.
    const noTimeStrictParts = [];
    if (rowSource) noTimeStrictParts.push(`source = '${escapeChString(rowSource)}'`);
    if (rowHost) noTimeStrictParts.push(`host = '${escapeChString(rowHost)}'`);
    if (rowParser) noTimeStrictParts.push(`parser_source = '${escapeChString(rowParser)}'`);
    if (rowDestIp) noTimeStrictParts.push(`(parsed_ip = '${escapeChString(rowDestIp)}' OR ioc_ip = '${escapeChString(rowDestIp)}')`);
    noTimeStrictParts.push(iocClause);

    const noTimeRelaxedParts = [iocClause];

    const candidates = [strictParts, mediumParts, relaxedParts, noTimeStrictParts, noTimeRelaxedParts];

    for (const parts of candidates) {
      const whereSql = parts.length ? `WHERE ${parts.join(' AND ')}` : '';
      const rows = await clickhouseQuery(`
        SELECT COALESCE(NULLIF(raw, ''), NULLIF(message, '')) AS raw_event
        FROM syslog_logs
        ${whereSql}
        ORDER BY ts DESC
        LIMIT 1
      `);

      const raw = rows?.[0]?.raw_event;
      if (raw && String(raw).trim()) {
        return { ...row, matched_syslog_event: String(raw) };
      }
    }

    return row;
  } catch {
    return row;
  }
}

async function bulkRawSyslogEvidence(rows = []) {
  if (!USE_CLICKHOUSE || !Array.isArray(rows) || rows.length === 0) return new Map();
  const items = rows.filter((r) => String(r?.matched_ioc || '').trim());
  if (!items.length) return new Map();

  const iocs = Array.from(new Set(items.map((r) => String(r.matched_ioc).trim().toLowerCase()))).slice(0, 100);
  const times = items.map((r) => new Date(r?.event_time || r?.created_at || Date.now()).getTime()).filter((v) => Number.isFinite(v));
  if (!iocs.length || !times.length) return new Map();

  const fromIso = new Date(Math.min(...times) - (10 * 60 * 1000)).toISOString().slice(0, 19).replace('T', ' ');
  const toIso = new Date(Math.max(...times) + (10 * 60 * 1000)).toISOString().slice(0, 19).replace('T', ' ');
  // Page-scoped IOCs only (caller passes current page rows); max 100 distinct observables.
  const iocClause = iocs.map((ioc) => `positionCaseInsensitiveUTF8(COALESCE(raw, message), '${escapeChString(ioc)}') > 0`).join(' OR ');
  if (!String(iocClause || '').trim()) return new Map();

  const RELAX_PAD_MS = 14 * 24 * 60 * 60 * 1000;
  const relaxFromIso = new Date(Math.min(...times) - RELAX_PAD_MS).toISOString().slice(0, 19).replace('T', ' ');
  const relaxToIso = new Date(Math.max(...times) + RELAX_PAD_MS).toISOString().slice(0, 19).replace('T', ' ');
  const chSettings = { max_execution_time: 12 };

  let timedRows = [];
  let relaxRows = [];
  try {
    timedRows = await clickhouseQuery(
      `
      SELECT ts, host, source, parser_source, source_type, COALESCE(raw, message) AS raw_message
      FROM syslog_logs
      WHERE ts BETWEEN toDateTime('${fromIso}') AND toDateTime('${toIso}')
        AND (${iocClause})
      ORDER BY ts DESC
      LIMIT 5000
    `,
      { logTag: 'bulk_raw_syslog_timed', settings: chSettings }
    );
  } catch (e) {
    console.warn('[bulkRawSyslogEvidence] timed syslog_logs query failed', e?.message || e);
  }
  try {
    relaxRows = await clickhouseQuery(
      `
      SELECT ts, host, source, parser_source, source_type, COALESCE(raw, message) AS raw_message
      FROM syslog_logs
      WHERE ts BETWEEN toDateTime('${relaxFromIso}') AND toDateTime('${relaxToIso}')
        AND (${iocClause})
      ORDER BY ts DESC
      LIMIT 5000
    `,
      { logTag: 'bulk_raw_syslog_relax', settings: chSettings }
    );
  } catch (e) {
    console.warn('[bulkRawSyslogEvidence] relaxed-window syslog_logs query failed; using timed pool only', e?.message || e);
  }

  const seen = new Set();
  const pool = [];
  for (const c of [...(timedRows || []), ...(relaxRows || [])]) {
    const raw = String(c?.raw_message || '');
    const k = `${c?.ts}\0${raw.slice(0, 280)}`;
    if (seen.has(k)) continue;
    seen.add(k);
    pool.push(c);
  }

  const WINDOW_MS = 10 * 60 * 1000;
  const byEventId = new Map();
  for (const r of items) {
    const ioc = String(r?.matched_ioc || '').toLowerCase();
    const t = new Date(r?.event_time || r?.created_at || Date.now()).getTime();
    const rowHost = String(r?.host_name || '').trim();
    const rowSource = String(r?.source || '').trim();
    const scored = [];
    for (const c of pool) {
      const raw = String(c?.raw_message || '');
      const rawL = raw.toLowerCase();
      if (!rawL.includes(ioc)) continue;
      const ct = new Date(c?.ts || 0).getTime();
      const dt = Number.isFinite(ct) ? Math.abs(ct - t) : Infinity;
      const squid = rawLooksLikeSquidOrHttpProxy(raw);
      const hostMatch = !rowHost || String(c?.host || '').trim() === rowHost;
      const inWin = dt <= WINDOW_MS;
      const sourceMatch = !rowSource || String(c?.source || '').trim() === rowSource;
      scored.push({ c, dt, squid, hostMatch, inWin, sourceMatch, ct });
    }
    if (!scored.length) continue;
    scored.sort((a, b) => {
      if (a.squid !== b.squid) return a.squid ? -1 : 1;
      if (a.inWin !== b.inWin) return a.inWin ? -1 : 1;
      if (a.hostMatch !== b.hostMatch) return a.hostMatch ? -1 : 1;
      if (a.sourceMatch !== b.sourceMatch) return a.sourceMatch ? -1 : 1;
      if (a.dt !== b.dt) return a.dt - b.dt;
      return (b.ct || 0) - (a.ct || 0);
    });
    const hit = scored[0]?.c;
    if (hit) byEventId.set(Number(r.id), hit);
  }
  return byEventId;
}

function buildFileInformation(rows, observable, observableType) {
  const type = String(observableType || '').toLowerCase();
  const fileTypes = new Set(['md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh']);
  const looksLikeFileIoc = fileTypes.has(type);

  let md5 = null;
  let sha1 = null;
  let sha256 = null;
  let ssdeep = null;
  let imphash = null;
  let tlsh = null;
  let fileName = null;
  let fileType = null;
  let mime = null;
  let reporter = null;
  let vtpercent = null;

  for (const row of rows) {
    const kv = parseNoteKeyValues(row.note);
    md5 = md5 || kv.md5 || null;
    sha1 = sha1 || kv.sha1 || null;
    sha256 = sha256 || kv.sha256 || null;
    ssdeep = ssdeep || kv.ssdeep || null;
    imphash = imphash || kv.imphash || null;
    tlsh = tlsh || kv.tlsh || null;
    fileName = fileName || kv.file_name || null;
    fileType = fileType || kv.file_type || null;
    mime = mime || kv.mime || null;
    reporter = reporter || kv.reporter || null;
    vtpercent = vtpercent || kv.vtpercent || null;
  }

  if (type === 'sha256' && !sha256) sha256 = observable;
  if (type === 'sha1' && !sha1) sha1 = observable;
  if (type === 'md5' && !md5) md5 = observable;
  if (type === 'ssdeep' && !ssdeep) ssdeep = observable;

  const hasData = Boolean(
    md5 || sha1 || sha256 || ssdeep || imphash || tlsh || fileName || fileType || mime || reporter || vtpercent
  );

  if (!hasData && !looksLikeFileIoc) return null;

  return {
    md5,
    sha1,
    sha256,
    ssdeep,
    imphash,
    tlsh,
    file_name: fileName,
    file_type: fileType,
    mime,
    reporter,
    vtpercent
  };
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

/** Yeni IOC eklendiğinde tek tek ağır refresh yerine debounce: kısa süre içinde tek seferde hafif limit ile çalışır. */
function scheduleGeoCacheRefreshAfterAdd() {
  // Threat map removed: geo cache refresh disabled.
}

// schema migrations are handled by migrate.js

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'backend', db: 'up' });
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

  const clickhouse = { ok: false };
  if (USE_CLICKHOUSE) {
    try {
      const [verRows, rowRows, sizeRows, retroStateRows] = await Promise.all([
        clickhouseQuery('SELECT version() AS version'),
        clickhouseQuery('SELECT count() AS rows FROM syslog_logs'),
        clickhouseQuery("SELECT sum(bytes_on_disk) AS bytes FROM system.parts WHERE active = 1 AND database = currentDatabase() AND table = 'syslog_logs'"),
        clickhouseQuery(`
          SELECT
            toString(last_processed_ts) AS cursor_ts,
            toUInt64(toUnixTimestamp64Milli(last_processed_ts)) AS cursor_ts_ms,
            toString(toUInt64(last_processed_row_hash)) AS cursor_hash,
            toString(updated_at) AS state_updated_at,
            toUInt64(toUnixTimestamp64Milli(updated_at)) AS state_updated_at_ms,
            toInt32(last_run_duration_ms) AS last_run_duration_ms,
            toUInt8(chunk_active) AS chunk_active,
            toString(chunk_end_ts) AS chunk_end_ts,
            toString(chunk_end_row_hash) AS chunk_end_row_hash,
            toUInt32(chunk_ioc_count) AS chunk_ioc_count,
            toUInt64(chunk_rows_processed) AS chunk_rows_processed
          FROM ioc_retro_state
          WHERE worker_name = 'ioc-retro-v1'
          ORDER BY updated_at DESC
          LIMIT 2
        `)
      ]);

      const latestState = retroStateRows?.[0] || null;
      const prevState = retroStateRows?.[1] || null;
      let retroRows = [{ pending: 0, cursor_ts: null, cursor_hash: null }];
      let lastRetroScannedIoc = null;

      if (latestState?.cursor_ts && latestState?.cursor_hash) {
        retroRows = await clickhouseQuery(`
          SELECT
            count() AS pending,
            min(updated_at) AS pending_min_ts,
            max(updated_at) AS pending_max_ts,
            '${String(latestState.cursor_ts)}' AS cursor_ts,
            '${String(latestState.cursor_hash)}' AS cursor_hash
          FROM ioc_lookup
          WHERE (updated_at > toDateTime64('${safeTs(String(latestState.cursor_ts))}', 3))
             OR (updated_at = toDateTime64('${safeTs(String(latestState.cursor_ts))}', 3)
                 AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${safeHash(String(latestState.cursor_hash))}'))
        `);
      }

      if (latestState?.cursor_ts && latestState?.cursor_hash && prevState?.cursor_ts && prevState?.cursor_hash) {
        const lastScannedRows = await clickhouseQuery(`
          SELECT count() AS scanned
          FROM ioc_lookup
          WHERE (
            updated_at > toDateTime64('${safeTs(String(prevState.cursor_ts))}', 3)
            OR (
              updated_at = toDateTime64('${safeTs(String(prevState.cursor_ts))}', 3)
              AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${safeHash(String(prevState.cursor_hash))}')
            )
          )
          AND (
            updated_at < toDateTime64('${safeTs(String(latestState.cursor_ts))}', 3)
            OR (
              updated_at = toDateTime64('${safeTs(String(latestState.cursor_ts))}', 3)
              AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) <= toUInt64('${safeHash(String(latestState.cursor_hash))}')
            )
          )
        `);
        lastRetroScannedIoc = Number(lastScannedRows?.[0]?.scanned || 0);
      }

      const sizeBytes = Number(sizeRows?.[0]?.bytes || 0);
      clickhouse.ok = true;
      clickhouse.version = verRows?.[0]?.version || null;
      clickhouse.rows = Number(rowRows?.[0]?.rows || 0);
      clickhouse.size_bytes = sizeBytes;
      clickhouse.size_mb = Number((sizeBytes / (1024 * 1024)).toFixed(2));
      clickhouse.table = 'syslog_logs';
      const rawPendingIoc = Number(retroRows?.[0]?.pending || 0);
      const activeChunkIoc = Number(latestState?.chunk_ioc_count || 0);
      const chunkActive = Number(latestState?.chunk_active || 0) === 1;
      // When a chunk is active, those IOC rows are already being processed by retro worker.
      // Exclude them from pending to avoid a misleading "stuck" value on /system.
      clickhouse.retro_pending_ioc = chunkActive
        ? Math.max(0, rawPendingIoc - activeChunkIoc)
        : rawPendingIoc;
      clickhouse.retro_cursor_ts = retroRows?.[0]?.cursor_ts || latestState?.cursor_ts || null;
      clickhouse.retro_cursor_ts_iso = isoFromEpochMs(latestState?.cursor_ts_ms);
      clickhouse.retro_cursor_hash = retroRows?.[0]?.cursor_hash || latestState?.cursor_hash || null;
      clickhouse.retro_last_run_at = latestState?.state_updated_at || null;
      clickhouse.retro_last_run_at_iso = isoFromEpochMs(latestState?.state_updated_at_ms);
      clickhouse.retro_last_duration_ms = Number(latestState?.last_run_duration_ms || 0);
      clickhouse.retro_last_scanned_ioc = lastRetroScannedIoc;
      clickhouse.retro_pending_min_ts = retroRows?.[0]?.pending_min_ts || null;
      clickhouse.retro_pending_max_ts = retroRows?.[0]?.pending_max_ts || null;
      clickhouse.retro_chunk_active = Number(latestState?.chunk_active || 0);
      clickhouse.retro_chunk_end_ts = latestState?.chunk_end_ts || null;
      clickhouse.retro_chunk_end_row_hash = latestState?.chunk_end_row_hash || null;
      clickhouse.retro_chunk_ioc_count = Number(latestState?.chunk_ioc_count || 0);
      clickhouse.retro_chunk_rows_processed = Number(latestState?.chunk_rows_processed || 0);
    } catch (err) {
      clickhouse.error = err.message;
    }
  } else {
    clickhouse.note = 'LOG_STORAGE is not clickhouse';
  }
  payload.clickhouse = clickhouse;

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
    const [integrationCounts, signalCounts] = await Promise.all([
      importQueue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed'),
      signalQueue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed')
    ]);
    queues.integration_imports = integrationCounts;
    queues.signal_events = signalCounts;
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
    const signals24hPromise = USE_CLICKHOUSE
      ? clickhouseQuery(`
          SELECT count() AS count
          FROM syslog_logs
          WHERE ts >= now() - INTERVAL 24 HOUR
        `)
      : pool.query("SELECT COUNT(*)::bigint AS count FROM signal_events WHERE created_at >= NOW() - INTERVAL '24 hours'");

    const [signals24hRes, iocTotalRes, iocTodayRes] = await Promise.all([
      signals24hPromise,
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

    const signalCount = USE_CLICKHOUSE
      ? Number(signals24hRes?.[0]?.count || 0)
      : Number(signals24hRes.rows?.[0]?.count || 0);

    telemetry = {
      signal_events_24h: signalCount,
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

app.get('/api/analytics/data-sources', async (_req, res) => {
  try {
    if (USE_CLICKHOUSE) {
      const rows = await clickhouseQuery(`
        SELECT
          source AS key,
          concat('Syslog ', source) AS name,
          'syslog' AS platform,
          'active' AS status,
          '' AS source_ip,
          'syslog' AS protocol,
          count() AS event_count,
          max(ts) AS last_seen_at
        FROM syslog_logs
        WHERE ts > now() - INTERVAL 30 DAY
        GROUP BY source
        ORDER BY last_seen_at DESC
      `);
      return res.json({ total: rows.length, sources: rows });
    }

    const q = await pool.query(
      `SELECT key, name, platform, status, source_ip, protocol, event_count, last_seen_at
       FROM signal_sources
       ORDER BY last_seen_at DESC NULLS LAST, key ASC`
    );
    return res.json({ total: q.rowCount, sources: q.rows });
  } catch (err) {
    console.error('[analytics-data-sources] failed', err);
    return res.status(500).json({ total: 0, sources: [] });
  }
});

app.get('/api/analytics/raw-events', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query?.limit || 10), 1), 100);

    if (USE_CLICKHOUSE) {
      const rows = await clickhouseQuery(`
        SELECT
          cityHash64(raw) AS id,
          source AS source_key,
          '' AS source_ip,
          ts AS event_time,
          ts AS received_at,
          host AS host_name,
          program AS process_name,
          '' AS destination_ip,
          0 AS destination_port,
          'syslog' AS protocol,
          ts AS created_at,
          message AS raw_event,
          raw
        FROM syslog_logs
        ORDER BY ts DESC
        LIMIT ${limit}
      `);
      return res.json({ total: rows.length, items: rows });
    }

    const q = await pool.query(
      `SELECT id, source_key, source_ip, event_time, received_at, host_name, process_name, destination_ip, destination_port, protocol, created_at, raw_event, raw
       FROM signal_events
       ORDER BY COALESCE(received_at, created_at) DESC
       LIMIT $1`,
      [limit]
    );

    return res.json({ total: q.rowCount, items: q.rows });
  } catch (err) {
    console.error('[analytics-raw-events] failed', err);
    return res.status(500).json({ total: 0, items: [] });
  }
});

app.get('/api/analytics/ioc-matches', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query?.limit || 10), 1), 100);
    const hasHours = req.query?.hours !== undefined && req.query?.hours !== null && String(req.query.hours).trim() !== '';
    const hours = hasHours ? Math.min(Math.max(Number(req.query.hours), 1), 87600) : null;

    const q = hasHours
      ? await pool.query(
          `WITH recent AS (
             SELECT
               m.id,
               m.signal_event_id,
               m.event_time,
               m.matched_ioc,
               m.source_name,
               m.created_at,
               COALESCE(
                 NULLIF(CONCAT_WS(' | ',
                   NULLIF(m.source, ''),
                   NULLIF(m.host_name, ''),
                   NULLIF(m.process_name, ''),
                   CASE
                     WHEN m.destination_ip IS NOT NULL AND m.destination_ip <> '' THEN m.destination_ip || COALESCE(':' || m.destination_port::text, '')
                     ELSE NULL
                   END,
                   NULLIF(m.protocol, '')
                 ), ''),
                 '-'
               ) AS matched_syslog_event,
               m.detection_type,
               m.match_source,
               m.verdict,
               m.reviewed_at,
               m.reviewed_by,
               m.note,
               m.assigned_to,
               m.assigned_at,
               COALESCE(
                 m.detection_type,
                 CASE
                   WHEN COALESCE(NULLIF(m.match_context->>'processing_path', ''), 'realtime') = 'retro'
                     OR COALESCE((m.match_context->>'retroactive')::boolean, false)
                   THEN 'retroactive'
                   ELSE 'realtime'
                 END
               ) AS detection_mode
             FROM ioc_match_events m
             WHERE m.created_at >= NOW() - ($2::text || ' hours')::interval
             ORDER BY m.created_at DESC, m.id DESC
             LIMIT $1
           ), source_agg AS (
             SELECT
               i.observable AS observable_norm,
               COUNT(DISTINCT i.source_name)::int AS source_count,
               ARRAY_AGG(DISTINCT i.source_name ORDER BY i.source_name) AS source_names
             FROM ioc_items i
             WHERE i.observable IN (SELECT DISTINCT lower(r.matched_ioc) FROM recent r)
             GROUP BY i.observable
           )
           SELECT
             r.*,
             COALESCE(sa.source_count, 0) AS source_count,
             COALESCE(sa.source_names, ARRAY[]::text[]) AS source_names
           FROM recent r
           LEFT JOIN source_agg sa ON sa.observable_norm = lower(r.matched_ioc)
           ORDER BY r.created_at DESC, r.id DESC`,
          [limit, hours]
        )
      : await pool.query(
          `WITH recent AS (
             SELECT
               m.id,
               m.signal_event_id,
               m.event_time,
               m.matched_ioc,
               m.source_name,
               m.created_at,
               COALESCE(
                 NULLIF(CONCAT_WS(' | ',
                   NULLIF(m.source, ''),
                   NULLIF(m.host_name, ''),
                   NULLIF(m.process_name, ''),
                   CASE
                     WHEN m.destination_ip IS NOT NULL AND m.destination_ip <> '' THEN m.destination_ip || COALESCE(':' || m.destination_port::text, '')
                     ELSE NULL
                   END,
                   NULLIF(m.protocol, '')
                 ), ''),
                 '-'
               ) AS matched_syslog_event,
               m.detection_type,
               m.match_source,
               m.verdict,
               m.reviewed_at,
               m.reviewed_by,
               m.note,
               m.assigned_to,
               m.assigned_at,
               COALESCE(
                 m.detection_type,
                 CASE
                   WHEN COALESCE(NULLIF(m.match_context->>'processing_path', ''), 'realtime') = 'retro'
                     OR COALESCE((m.match_context->>'retroactive')::boolean, false)
                   THEN 'retroactive'
                   ELSE 'realtime'
                 END
               ) AS detection_mode
             FROM ioc_match_events m
             ORDER BY m.created_at DESC, m.id DESC
             LIMIT $1
           ), source_agg AS (
             SELECT
               i.observable AS observable_norm,
               COUNT(DISTINCT i.source_name)::int AS source_count,
               ARRAY_AGG(DISTINCT i.source_name ORDER BY i.source_name) AS source_names
             FROM ioc_items i
             WHERE i.observable IN (SELECT DISTINCT lower(r.matched_ioc) FROM recent r)
             GROUP BY i.observable
           )
           SELECT
             r.*,
             COALESCE(sa.source_count, 0) AS source_count,
             COALESCE(sa.source_names, ARRAY[]::text[]) AS source_names
           FROM recent r
           LEFT JOIN source_agg sa ON sa.observable_norm = lower(r.matched_ioc)
           ORDER BY r.created_at DESC, r.id DESC`,
          [limit]
        );

    const items = USE_CLICKHOUSE
      ? await Promise.all((q.rows || []).map((row) => withRawSyslogEvent(row)))
      : q.rows;

    return res.json({ total: q.rowCount, items });
  } catch (err) {
    console.error('[analytics-ioc-matches] failed', err);
    return res.status(500).json({ total: 0, items: [] });
  }
});

app.get('/api/ioc/match-events', async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query?.limit || 20), 1), 100);
    const qStr = String(req.query?.q || '').trim();
    const fromStr = String(req.query?.from || '').trim();
    const toStr = String(req.query?.to || '').trim();
    const verdictStr = String(req.query?.verdict || '').trim();
    const detectionStr = String(req.query?.detection || '').trim();
    const activityIdStr = String(req.query?.activity_id || req.query?.activityId || '').trim();

    const where = [];
    const params = [];

    if (qStr) {
      params.push(`%${qStr}%`);
      const idx = params.length;
      where.push(`(
        m.id::text ILIKE $${idx}
        OR COALESCE(m.matched_ioc, '') ILIKE $${idx}
        OR COALESCE(m.source_name, '') ILIKE $${idx}
        OR COALESCE(m.host_name, '') ILIKE $${idx}
        OR COALESCE(m.process_name, '') ILIKE $${idx}
        OR COALESCE(m.destination_ip, '') ILIKE $${idx}
        OR COALESCE(m.protocol, '') ILIKE $${idx}
      )`);
    }

    if (activityIdStr) {
      params.push(activityIdStr);
      where.push(`m.activity_id = $${params.length}::uuid`);
    }

    if (verdictStr) {
      const verdictVals = verdictStr
        .split(',')
        .map((v) => String(v || '').trim().toLowerCase())
        .filter(Boolean)
        .filter((v) => ['unreviewed', 'in_progress', 'fp', 'tp'].includes(v));
      const parts = [];
      for (const v of verdictVals) {
        if (v === 'unreviewed') {
          parts.push("(m.verdict IS NULL OR m.verdict = '')");
        } else {
          params.push(v);
          parts.push(`m.verdict = $${params.length}`);
        }
      }
      if (parts.length) where.push(`(${parts.join(' OR ')})`);
    }

    if (detectionStr) {
      const detVals = detectionStr
        .split(',')
        .map((v) => String(v || '').trim().toLowerCase())
        .filter(Boolean)
        .filter((v) => ['realtime', 'retroactive'].includes(v));
      if (detVals.length) {
        const idxs = [];
        for (const v of detVals) {
          params.push(v);
          idxs.push(`$${params.length}`);
        }
        where.push(`COALESCE(m.detection_type, CASE WHEN COALESCE(NULLIF(m.match_context->>'processing_path',''),'realtime')='retro' OR COALESCE((m.match_context->>'retroactive')::boolean, false) THEN 'retroactive' ELSE 'realtime' END) IN (${idxs.join(',')})`);
      }
    }

    if (fromStr) {
      const fromDate = new Date(fromStr);
      if (!Number.isNaN(fromDate.getTime())) {
        params.push(fromDate.toISOString());
        where.push(`m.created_at >= $${params.length}::timestamptz`);
      }
    }

    let fromIsoForGuard = null;
    let toIsoForGuard = null;

    if (fromStr) {
      const fromDate = new Date(fromStr);
      if (!Number.isNaN(fromDate.getTime())) fromIsoForGuard = fromDate.toISOString();
    }

    if (toStr) {
      const toDate = new Date(toStr);
      if (!Number.isNaN(toDate.getTime())) toIsoForGuard = toDate.toISOString();
    }

    if (fromIsoForGuard && toIsoForGuard && fromIsoForGuard > toIsoForGuard) {
      return res.status(400).json({ message: 'Invalid date range: from must be <= to' });
    }

    if (toStr) {
      const toDate = new Date(toStr);
      if (!Number.isNaN(toDate.getTime())) {
        params.push(toDate.toISOString());
        where.push(`m.created_at <= $${params.length}::timestamptz`);
      }
    }

    params.push(limit);
    const limitIdx = params.length;

    const sql = `
      WITH recent AS (
        SELECT
          m.id,
          m.signal_event_id,
          m.event_time,
          m.host_name,
          m.process_name,
          m.destination_ip,
          m.destination_port,
          m.protocol,
          m.matched_ioc,
          m.source_name,
          m.confidence,
          m.ioc_type,
          m.ioc_item_id,
          m.parser_source,
          m.source,
          m.match_context,
          m.dedup_key,
          m.bucket_start,
          m.first_seen_at,
          m.last_seen_at,
          m.hit_count,
          m.created_at,
          COALESCE(m.last_seen_at, m.event_time, m.created_at) AS detected_at,
          m.detection_type,
          m.match_source,
          m.activity_id,
          m.verdict,
          m.reviewed_at,
          m.reviewed_by,
          m.note,
          m.assigned_to,
          m.assigned_at,
          COALESCE(
            NULLIF(CONCAT_WS(' | ',
              NULLIF(m.source, ''),
                  NULLIF(m.host_name, ''),
              NULLIF(m.process_name, ''),
              CASE
                WHEN m.destination_ip IS NOT NULL AND m.destination_ip <> '' THEN m.destination_ip || COALESCE(':' || m.destination_port::text, '')
                ELSE NULL
              END,
              NULLIF(m.protocol, '')
            ), ''),
            '-'
          ) AS matched_syslog_event,
          COALESCE(
            m.detection_type,
            CASE
              WHEN COALESCE(NULLIF(m.match_context->>'processing_path', ''), 'realtime') = 'retro'
                OR COALESCE((m.match_context->>'retroactive')::boolean, false)
              THEN 'retroactive'
              ELSE 'realtime'
            END
          ) AS detection_mode
        FROM ioc_match_events m
        ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
        ORDER BY m.created_at DESC, m.id DESC
        LIMIT $${limitIdx}
      ), source_agg AS (
        SELECT
          i.observable AS observable_norm,
          COUNT(DISTINCT i.source_name)::int AS source_count,
          ARRAY_AGG(DISTINCT i.source_name ORDER BY i.source_name) AS source_names
        FROM ioc_items i
        WHERE i.observable IN (SELECT DISTINCT lower(r.matched_ioc) FROM recent r)
        GROUP BY i.observable
      )
      SELECT
        r.*,
        COALESCE(sa.source_count, 0) AS source_count,
        COALESCE(sa.source_names, ARRAY[]::text[]) AS source_names
      FROM recent r
      LEFT JOIN source_agg sa ON sa.observable_norm = lower(r.matched_ioc)
      ORDER BY r.created_at DESC, r.id DESC
    `;

    const q = await pool.query(sql, params);

    // ClickHouse raw-event enrichment is expensive for list views and is not
    // needed by the Detection Events table. Keep it opt-in for faster response.
    const includeRaw = String(req.query?.include_raw || req.query?.includeRaw || '').toLowerCase();
    const shouldIncludeRaw = includeRaw === '1' || includeRaw === 'true' || includeRaw === 'yes';

    const items = (USE_CLICKHOUSE && shouldIncludeRaw)
      ? await Promise.all((q.rows || []).map((row) => withRawSyslogEvent(row)))
      : q.rows;

    return res.json({ total: items.length, items });
  } catch (err) {
    console.error('[ioc-match-events] failed', err);
    return res.status(500).json({ total: 0, items: [] });
  }
});

app.get('/api/ioc/match-events/:id', async (req, res) => {
  try {
    const id = Number(req.params?.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    const q = await pool.query(
      `WITH one AS (
         SELECT
           m.*,
           COALESCE(
             NULLIF(CONCAT_WS(' | ',
               NULLIF(m.source, ''),
                   NULLIF(m.host_name, ''),
               NULLIF(m.process_name, ''),
               CASE
                 WHEN m.destination_ip IS NOT NULL AND m.destination_ip <> '' THEN m.destination_ip || COALESCE(':' || m.destination_port::text, '')
                 ELSE NULL
               END,
               NULLIF(m.protocol, '')
             ), ''),
             '-'
           ) AS matched_syslog_event,
           COALESCE(
             m.detection_type,
             CASE
               WHEN COALESCE(NULLIF(m.match_context->>'processing_path', ''), 'realtime') = 'retro'
                 OR COALESCE((m.match_context->>'retroactive')::boolean, false)
               THEN 'retroactive'
               ELSE 'realtime'
             END
           ) AS detection_mode
         FROM ioc_match_events m
         WHERE m.id = $1
         LIMIT 1
       ), source_agg AS (
         SELECT
           i.observable AS observable_norm,
           COUNT(DISTINCT i.source_name)::int AS source_count,
           ARRAY_AGG(DISTINCT i.source_name ORDER BY i.source_name) AS source_names
         FROM ioc_items i
         WHERE i.observable IN (SELECT DISTINCT lower(o.matched_ioc) FROM one o)
         GROUP BY i.observable
       )
       SELECT
         o.*,
         COALESCE(sa.source_count, 0) AS source_count,
         COALESCE(sa.source_names, ARRAY[]::text[]) AS source_names
       FROM one o
       LEFT JOIN source_agg sa ON sa.observable_norm = lower(o.matched_ioc)
       LIMIT 1`,
      [id]
    );

    if (!q.rowCount) {
      return res.status(404).json({ message: 'IOC match event not found' });
    }

    const pgRow = q.rows[0];
    let evidenceSource = 'match_context_fallback';
    let itemRaw = pgRow;

    if (pgRow?.raw_log_snapshot && String(pgRow.raw_log_snapshot).trim()) {
      evidenceSource = 'pg_snapshot';
      itemRaw = { ...pgRow, matched_syslog_event: String(pgRow.raw_log_snapshot) };
    } else if (USE_CLICKHOUSE) {
      const enriched = await withRawSyslogEvent(pgRow);
      if (String(enriched?.matched_syslog_event || '').trim() && String(enriched?.matched_syslog_event || '').trim() !== String(pgRow?.matched_syslog_event || '').trim()) {
        evidenceSource = 'clickhouse_enrich';
      }
      itemRaw = enriched;
    }

    if (!String(itemRaw?.matched_syslog_event || '').trim() || String(itemRaw?.matched_syslog_event || '').trim() === '-') {
      evidenceSource = pgRow?.match_context ? 'match_context_fallback' : 'unavailable';
    }

    const item = {
      ...itemRaw,
      raw_log_snapshot: pgRow?.raw_log_snapshot || null,
      normalized_event_json: pgRow?.normalized_event_json || null,
      source_type: pgRow?.source_type || null,
      v2_context: classifyEventContext(itemRaw)
    };
    console.info(`[ioc-match-event-detail] id=${id} evidence_source=${evidenceSource}`);
    return res.json({ item });
  } catch (err) {
    console.error('[ioc-match-event-detail] failed', err);
    return res.status(500).json({ message: 'Failed to fetch IOC match event detail' });
  }
});


app.patch('/api/ioc/match-events/:id/verdict', async (req, res) => {
  try {
    const id = Number(req.params?.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ message: 'Invalid id' });
    }

    const rawVerdict = req.body?.verdict;
    const rawNote = req.body?.note;
    const verdict = rawVerdict == null || String(rawVerdict).trim() === ''
      ? null
      : String(rawVerdict).trim().toLowerCase();

    if (verdict !== null && !['fp', 'tp', 'suspicious', 'in_progress'].includes(verdict)) {
      return res.status(400).json({ message: 'Invalid verdict. Use fp, tp, suspicious, in_progress or null.' });
    }

    const note = rawNote == null || String(rawNote).trim() === ''
      ? null
      : String(rawNote).trim().slice(0, 4000);

    const reviewedBy = String(req.user?.username || req.user?.email || '').trim() || null;
    const assignTo = String(req.body?.assigned_to || '').trim() || reviewedBy;

    const q = await pool.query(
      `UPDATE ioc_match_events
       SET verdict = $2::text,
           reviewed_at = CASE WHEN $2::text IS NULL THEN NULL ELSE NOW() END,
           reviewed_by = CASE WHEN $2::text IS NULL THEN NULL ELSE $3::text END,
           note = $4,
           assigned_to = CASE
             WHEN $2::text = 'in_progress' THEN $5::text
             WHEN $2::text IS NULL THEN NULL
             ELSE assigned_to
           END,
           assigned_at = CASE
             WHEN $2::text = 'in_progress' THEN NOW()
             WHEN $2::text IS NULL THEN NULL
             ELSE assigned_at
           END
       WHERE id = $1
       RETURNING *`,
      [id, verdict, reviewedBy, note, assignTo]
    );

    if (!q.rowCount) {
      return res.status(404).json({ message: 'IOC match event not found' });
    }

    return res.json({ item: q.rows[0] });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update verdict', detail: err.message });
  }
});

function resolveIncidentSelector(raw) {
  const s = String(raw || '').trim();
  if (!s) return { ok: false };
  if (/^\d+$/.test(s)) return { ok: true, by: 'incident_id', value: Number(s) };
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s)) return { ok: true, by: 'id', value: s };
  return { ok: false };
}

async function findIncidentRow(selectorRaw) {
  const sel = resolveIncidentSelector(selectorRaw);
  if (!sel.ok) return null;
  if (sel.by === 'incident_id') {
    const q = await pool.query(`SELECT id, incident_id FROM ioc_activity WHERE incident_id = $1 LIMIT 1`, [sel.value]);
    return q.rows?.[0] || null;
  }
  const q = await pool.query(`SELECT id, incident_id FROM ioc_activity WHERE id = $1::uuid LIMIT 1`, [sel.value]);
  return q.rows?.[0] || null;
}

app.get('/api/incidents', async (req, res) => {
  try {
    const page = Math.max(Number(req.query?.page || 1), 1);
    const pageSize = Math.min(Math.max(Number(req.query?.page_size || req.query?.pageSize || 20), 1), 100);
    const q = String(req.query?.q || req.query?.search || '').trim();
    const status = String(req.query?.status || '').trim().toLowerCase();
    const verdictStr = String(req.query?.verdict || '').trim();
    const assigneeStr = String(req.query?.assignee || '').trim();
    const fromStr = String(req.query?.from || '').trim();
    const toStr = String(req.query?.to || '').trim();

    const where = [];
    const params = [];

    if (q) {
      const searchPredicates = [];

      params.push(`%${q}%`);
      const textParamIdx = params.length;
      searchPredicates.push(`a.ioc_value ILIKE $${textParamIdx}`);
      searchPredicates.push(`a.ioc_type ILIKE $${textParamIdx}`);

      const normalizedIncidentId = q.startsWith('#') ? q.slice(1) : q;
      if (/^\d+$/.test(normalizedIncidentId)) {
        params.push(Number(normalizedIncidentId));
        searchPredicates.push(`a.incident_id = $${params.length}`);
      }

      where.push(`(${searchPredicates.join(' OR ')})`);
    }

    if (status && ['open', 'closed'].includes(status)) {
      params.push(status);
      where.push(`a.status = $${params.length}`);
    }

    if (verdictStr) {
      const allowed = new Set(['TP', 'FP', 'Suspicious', 'Unreviewed', 'In Progress']);
      const vals = verdictStr.split(',').map((v) => String(v || '').trim()).filter((v) => allowed.has(v));
      if (vals.length) {
        const holders = [];
        for (const v of vals) {
          params.push(v);
          holders.push(`$${params.length}`);
        }
        where.push(`a.verdict IN (${holders.join(',')})`);
      }
    }

    if (assigneeStr) {
      const norm = assigneeStr.toLowerCase();
      if (norm === 'unassigned') {
        where.push(`(a.assigned_to IS NULL OR a.assigned_to = '')`);
      } else {
        params.push(assigneeStr);
        where.push(`a.assigned_to = $${params.length}`);
      }
    }

    if (fromStr) {
      const from = new Date(fromStr);
      if (!Number.isNaN(from.getTime())) {
        params.push(from.toISOString());
        where.push(`a.created_at >= $${params.length}::timestamptz`);
      }
    }

    if (toStr) {
      const to = new Date(toStr);
      if (!Number.isNaN(to.getTime())) {
        params.push(to.toISOString());
        where.push(`a.created_at <= $${params.length}::timestamptz`);
      }
    }

    where.push(`EXISTS (SELECT 1 FROM ioc_match_events m WHERE m.activity_id = a.id)`);
    const whereSql = `WHERE ${where.join(' AND ')}`;

    const countQ = await pool.query(`SELECT COUNT(*)::bigint AS total FROM ioc_activity a ${whereSql}`, params);
    const total = Number(countQ.rows?.[0]?.total || 0);

    const offset = (page - 1) * pageSize;
    params.push(pageSize);
    params.push(offset);

    const rowsQ = await pool.query(
      `SELECT
        a.*,
        COALESCE(ev.asset_count, 0) AS asset_count,
        COALESCE(ev.event_count, 0) AS event_count,
        COALESCE(ev.accepted_connections, 0) AS accepted_connections,
        COALESCE(ev.blocked_connections, 0) AS blocked_connections,
        ev.dominant_source_type,
        ev.dominant_parser_source,
        ev.detection_type,
        ev.has_endpoint_evidence,
        ev.has_proxy_evidence,
        ev.has_dns_evidence,
        ev.has_firewall_evidence,
        ev.confidence
       FROM ioc_activity a
       LEFT JOIN LATERAL (
         SELECT
           ${IOC_MATCH_EVENT_STATS_SELECT}
         FROM ioc_match_events m
         WHERE m.activity_id = a.id
       ) ev ON true
       ${whereSql}
       ORDER BY a.incident_id DESC, a.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const items = (rowsQ.rows || []).map((row) => {
      const risk = calculateIncidentRisk(row);
      return {
        ...row,
        ...risk
      };
    });

    return res.json({
      items,
      pagination: {
        page,
        page_size: pageSize,
        total,
        total_pages: Math.max(1, Math.ceil(total / pageSize))
      }
    });
  } catch (err) {
    console.error('[incidents-list] failed', err);
    return res.status(500).json({ items: [], pagination: { page: 1, page_size: 20, total: 0, total_pages: 1 } });
  }
});

async function loadIncidentWithStats(activityId) {
  const q = await pool.query(
    `SELECT
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
     LEFT JOIN LATERAL (
       SELECT
         ${IOC_MATCH_EVENT_STATS_SELECT}
       FROM ioc_match_events m
       WHERE m.activity_id = a.id
     ) ev ON true
     WHERE a.id = $1::uuid
     LIMIT 1`,
    [activityId]
  );

  return q;
}

function llmNormSourceType(ev = {}) {
  const st = String(ev?.source_type || '').toLowerCase();
  if (st) return st;
  const p = String(ev?.parser_source || '').toLowerCase();
  if (/(proxy|url|http|webproxy|swg|squid)/.test(p)) return 'proxy';
  if (/(^|\s)dns(\s|$)|resolver|query|bind_dns/.test(p)) return 'dns';
  if (/(firewall|traffic|forti|palo|pan-os|checkpoint|netflow)/.test(p)) return 'firewall';
  return 'generic';
}

async function buildIncidentAiInsightContext(activityId) {
  const q = await loadIncidentWithStats(activityId);
  if (!q.rowCount) return null;
  const context = await enrichIncidentContextWithRelatedIocs(q.rows[0], { pool });

  const evQ = await pool.query(
    `SELECT event_time, created_at, source_type, parser_source, match_context, normalized_event_json, matched_ioc, host_name, raw_log_snapshot
     FROM ioc_match_events
     WHERE activity_id = $1::uuid
     ORDER BY COALESCE(last_seen_at, event_time, created_at) DESC
     LIMIT 20`,
    [context.id]
  );
  const rows = evQ.rows || [];
  const sourceTypes = {};
  for (const r of rows) {
    const st = llmNormSourceType(r);
    sourceTypes[st] = (sourceTypes[st] || 0) + 1;
  }
  context.event_summary = { ...(context.event_summary || {}), source_types: sourceTypes };
  context.playbook_coverage = {
    ...(context.playbook_coverage || {}),
    dns_evidence: Number(sourceTypes.dns || 0) > 0,
    proxy_evidence: Number(sourceTypes.proxy || 0) > 0
  };
  context.sample_events = rows.slice(0, 5).map((r) => ({
    detected_at: r.event_time || r.created_at || null,
    source_type: llmNormSourceType(r),
    matched_ioc: r.matched_ioc,
    raw_sample: String(r.raw_log_snapshot || '').slice(0, 500),
    method: r?.normalized_event_json?.method || r?.match_context?.method || null,
    status: r?.normalized_event_json?.status || r?.match_context?.status || null
  }));

  return context;
}

app.get('/api/incidents/:id', async (req, res) => {
  try {
    const idRaw = String(req.params?.id || '').trim();
    if (!idRaw) return res.status(400).json({ message: 'Invalid id' });

    const incident = await findIncidentRow(idRaw);
    if (!incident?.id) return res.status(404).json({ message: 'Incident not found' });

    const context = await buildIncidentAiInsightContext(incident.id);
    if (!context) return res.status(404).json({ message: 'Incident not found' });
    if (Number(context?.event_count || 0) <= 0) {
      return res.status(404).json({ message: 'Incident not found (no linked events)' });
    }

    const risk = calculateIncidentRisk(context);
    const incidentVersion = llmRiskAdvisor.computeVersion(context);
    const cachedLlmRisk = await llmRiskAdvisor.getCached({
      incidentId: context?.id,
      version: incidentVersion,
      baseRisk: risk.risk_score,
      incident: context
    });

    let llmRisk = cachedLlmRisk;
    if (!llmRisk) {
      llmRisk = {
        risk_before_llm: Number(risk.risk_score || 0),
        llm_risk_adjustment: null,
        llm_risk_confidence: null,
        llm_risk_reason: null,
        llm_last_updated_at: null,
        llm_version: incidentVersion,
        final_risk_score: Number(risk.risk_score || 0)
      };
      await llmRiskAdvisor.enqueueEvaluation({
        incidentId: context?.id,
        version: incidentVersion,
        reason: 'incident_detail_cache_miss'
      });
    }

    let related_log_count = null;
    try {
      const relQ = await pool.query(
        `SELECT COUNT(*)::bigint AS c
         FROM ioc_match_event_related_logs
         WHERE activity_id = $1::uuid`,
        [context.id]
      );
      const pgCount = Number(relQ.rows?.[0]?.c);
      if (Number.isFinite(pgCount) && pgCount > 0) {
        related_log_count = pgCount;
      } else {
        const iocValue = String(context?.ioc_value || '').trim().toLowerCase();
        const firstSeen = context?.first_seen ? new Date(context.first_seen) : null;
        const lastSeen = context?.last_seen ? new Date(context.last_seen) : null;
        const hasWindow = firstSeen && lastSeen && !Number.isNaN(firstSeen.getTime()) && !Number.isNaN(lastSeen.getTime());
        if (iocValue && hasWindow) {
          const fromIso = new Date(firstSeen.getTime() - (5 * 60 * 1000)).toISOString().slice(0, 19).replace('T', ' ');
          const toIso = new Date(lastSeen.getTime() + (5 * 60 * 1000)).toISOString().slice(0, 19).replace('T', ' ');
          const escaped = escapeChString(iocValue);
          const q = await clickhouseQuery(`
            SELECT count() AS c
            FROM syslog_observables
            WHERE lower(observable) = '${escaped}'
              AND ts >= toDateTime('${fromIso}')
              AND ts <= toDateTime('${toIso}')
          `);
          const chCount = Number(q?.[0]?.c);
          if (Number.isFinite(chCount) && chCount > 0) related_log_count = chCount;
        }
      }
    } catch (e) {
      console.warn('[incident-detail] related_log_count unavailable', e?.message || e);
      related_log_count = null;
    }

    const item = {
      ...context,
      detection_event_count: Number(context?.event_count || 0),
      related_log_count,
      incident_version: incidentVersion,
      ...risk,
      ...llmRisk,
      risk_score: llmRisk.final_risk_score
    };

    return res.json({ item });
  } catch (err) {
    console.error('[incident-detail] failed', err);
    return res.status(500).json({ message: 'Failed to fetch incident' });
  }
});

app.post('/api/incidents/:id/ai-analyze', async (req, res) => {
  try {
    const idRaw = String(req.params?.id || '').trim();
    if (!idRaw) return res.status(400).json({ message: 'Invalid id' });

    const incident = await findIncidentRow(idRaw);
    if (!incident?.id) return res.status(404).json({ message: 'Incident not found' });

    const context = await buildIncidentAiInsightContext(incident.id);
    if (!context) return res.status(404).json({ message: 'Incident not found' });
    if (Number(context?.event_count || 0) <= 0) {
      return res.status(404).json({ message: 'Incident not found (no linked events)' });
    }

    const risk = calculateIncidentRisk(context);
    const incidentVersion = llmRiskAdvisor.computeVersion(context);
    const llmRisk = await llmRiskAdvisor.evaluateAndCache({
      incident: context,
      baseRisk: risk.risk_score,
      version: incidentVersion,
      force: true,
      timeoutMsOverride: llmRiskAdvisor.manualTimeoutMs
    });

    if (String(llmRisk?.llm_risk_reason || '').toLowerCase() === 'timeout') {
      await llmRiskAdvisor.enqueueEvaluation({
        incidentId: context?.id,
        version: incidentVersion,
        reason: 'manual_timeout_retry_background'
      });
      return res.status(202).json({ status: 'processing' });
    }

    const relatedSignals = summarizeRelatedIocSignals(context?.related_iocs);
    console.log('[incident-ai-analyze][debug]', {
      incident_id: context?.incident_id || null,
      context_path: 'manual_update',
      ...relatedSignals,
      hasAcceptedOrSuccessfulTraffic: llmRisk?.hasAcceptedOrSuccessfulTraffic ?? null,
      hasStrongMaliciousContext: llmRisk?.hasStrongMaliciousContext ?? null,
      raw_model_adjustment: llmRisk?.raw_model_adjustment ?? null,
      final_adjustment: llmRisk?.llm_risk_adjustment ?? null,
      normalization_reason: llmRisk?.normalization_reason ?? null
    });

    const item = {
      ...context,
      incident_version: incidentVersion,
      ...risk,
      ...llmRisk,
      risk_score: llmRisk.final_risk_score
    };

    return res.json({ item });
  } catch (err) {
    console.error('[incident-ai-analyze] failed', err);
    return res.status(500).json({ message: 'AI analysis failed' });
  }
});

function classifyEventContext(ev = {}) {
  const mc = ev?.match_context || {};
  const nej = ev?.normalized_event_json || {};
  const raw = String(ev?.matched_syslog_event || ev?.raw_log_snapshot || '');
  const kv = {};
  raw.replace(/(\w+)=([^\s]+)/g, (_, k, v) => { kv[String(k).toLowerCase()] = String(v); return ''; });
  const ioc = String(ev?.matched_ioc || '').toLowerCase();
  const iocType = String(ev?.ioc_type || '').toLowerCase();
  const explicitType = String(mc.type || mc.log_type || mc.parser_type || kv.type || '').toLowerCase();
  const sourceType = String(ev?.source_type || nej?.source_type || '').toLowerCase();
  const parserSource = String(ev?.parser_source || nej?.parser_source || '').toLowerCase();

  const merged = {
    ...kv,
    ...Object.fromEntries(Object.entries(mc || {}).map(([k, v]) => [String(k).toLowerCase(), v])),
    ...Object.fromEntries(Object.entries(nej || {}).map(([k, v]) => [String(k).toLowerCase(), v]))
  };
  const hasProxyFields = Boolean(merged.url || merged.method || merged.status);
  const hasDnsFields = Boolean(merged.query || merged.query_type || merged.response_ip);
  const hasFwFields = Boolean(merged.srcip || merged.dstip || merged.dstport || merged.service);

  const squidSig = rawLooksLikeSquidOrHttpProxy(raw);
  const proxyMethodMatch = raw.match(/\b(CONNECT|GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b/i);
  const proxyHostMatch = raw.match(/\bCONNECT\s+([^\s:]+):\d+/i)
    || raw.match(/\bhttps?:\/\/([^\s\/]+)\//i);

  const bindDnsSig = /\bbind_dns:\b/i.test(raw)
    || /\bqueries:\s*info:\s*client\b/i.test(raw)
    || /\bquery:\s*\S+\s+IN\s+[A-Z]+\b/i.test(raw);
  const bindClientMatch = raw.match(/\bclient\s+[^\s]*\s*(\d{1,3}(?:\.\d{1,3}){3})#\d+/i);
  const bindQueryMatch = raw.match(/\bquery:\s*([^\s]+)\s+IN\s+([A-Z]+)/i);
  const bindResolverMatch = raw.match(/\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)\s*$/);

  let event_family = 'generic';
  let classification_confidence = 0.4;
  if (squidSig || /(proxy|squid|web|http)/.test(parserSource) || sourceType === 'proxy' || explicitType === 'proxy') { event_family = 'proxy'; classification_confidence = 0.97; }
  else if (bindDnsSig || /(dns|bind|resolver|microsoft_dns)/.test(parserSource) || sourceType === 'dns' || explicitType === 'dns') { event_family = 'dns'; classification_confidence = 0.9; }
  else if (/(firewall|forti|palo|pan-os|checkpoint|traffic)/.test(parserSource) || sourceType === 'firewall' || explicitType === 'firewall') { event_family = 'firewall'; classification_confidence = 0.9; }
  else if (hasProxyFields) { event_family = 'proxy'; classification_confidence = 0.85; }
  else if (hasDnsFields) { event_family = 'dns'; classification_confidence = 0.85; }
  else if (hasFwFields) { event_family = 'firewall'; classification_confidence = 0.75; }

  const control_point = event_family === 'dns' ? 'dns_resolver' : event_family;

  let matched_field = String(merged.matched_field || '').toLowerCase();
  const rawUrl = String(merged.url || '');
  let urlHost = '';
  try { if (rawUrl) urlHost = new URL(rawUrl).hostname.toLowerCase(); } catch {}

  if (!matched_field) {
    if (event_family === 'dns' && bindDnsSig) {
      if (bindQueryMatch?.[1]) merged.query = bindQueryMatch[1].toLowerCase();
      if (bindQueryMatch?.[2]) merged.query_type = bindQueryMatch[2].toUpperCase();
      if (bindClientMatch?.[1]) merged.client_ip = bindClientMatch[1];
      if (bindResolverMatch?.[1]) merged.resolver_ip = bindResolverMatch[1];
      matched_field = iocType === 'domain' ? 'query' : 'raw';
    }
    if (!matched_field && event_family === 'dns' && iocType === 'domain' && String(merged.query || '').toLowerCase() === ioc) matched_field = 'query';
    else if (event_family === 'dns' && iocType === 'ip' && String(merged.response_ip || '').toLowerCase() === ioc) matched_field = 'response_ip';
    else if (event_family === 'proxy' && (iocType === 'domain' || iocType === 'url')) {
      if (proxyHostMatch?.[1]) {
        const h = String(proxyHostMatch[1] || '').toLowerCase();
        if (iocType === 'domain' && (h === ioc || h.endsWith(`.${ioc}`))) matched_field = proxyMethodMatch?.[1]?.toUpperCase() === 'CONNECT' ? 'connect_host' : 'request_host';
      }
      if (!matched_field && iocType === 'domain' && urlHost && (urlHost === ioc || urlHost.endsWith(`.${ioc}`))) matched_field = 'url_host';
      else if (!matched_field && iocType === 'url' && rawUrl.toLowerCase().includes(ioc)) matched_field = 'url';
    } else if (event_family === 'firewall' && iocType === 'ip') {
      if (String(merged.dstip || '').toLowerCase() === ioc) matched_field = 'dstip';
      else if (String(merged.srcip || '').toLowerCase() === ioc) matched_field = 'srcip';
    }
  }

  if (!matched_field) matched_field = (event_family === 'proxy' ? 'url' : event_family === 'dns' ? 'query' : 'raw');
  if (iocType === 'domain' && ['srcip', 'dstip', 'client_ip'].includes(matched_field)) matched_field = event_family === 'proxy' ? 'url_host' : 'raw';

  const action = String(merged.action || merged.decision || '').toLowerCase();
  const statusCode = Number(merged.status);
  const blockSig = /(block|deny|drop|reject|quarantine|sinkhole|policy_block|block_page)/.test(`${action} ${merged.block_reason || ''} ${merged.response_page || ''}`.toLowerCase());
  const allowSig = /(allow|accept|permit|pass|delivered|success)/.test(action);

  let outcome = 'unknown';
  let outcome_confidence = 0.5;
  if (blockSig) { outcome = 'blocked'; outcome_confidence = 0.85; }
  else if (allowSig) { outcome = 'allowed'; outcome_confidence = 0.8; }
  else if (event_family === 'proxy' && Number.isFinite(statusCode) && statusCode >= 200 && statusCode < 400) {
    outcome = 'allowed_or_successful'; outcome_confidence = 0.7;
  } else if (event_family === 'dns') { outcome = 'observed'; outcome_confidence = 0.7; }

  let direction = String(mc.direction || mc.flow || '').toLowerCase();
  if (!direction) direction = event_family === 'proxy' ? 'outbound' : event_family === 'dns' ? 'resolution' : 'unknown';

  let scenario_type = 'unknown_ioc_match';
  if (event_family === 'dns' && matched_field === 'response_ip' && iocType === 'ip') scenario_type = 'dns_response_ip_ioc_observed';
  else if (event_family === 'dns') scenario_type = 'dns_query_to_ioc_domain';
  else if (event_family === 'proxy' && iocType === 'domain') scenario_type = (proxyMethodMatch?.[1] || '').toUpperCase() === 'CONNECT' ? 'proxy_connect_to_ioc_domain' : 'proxy_request_to_ioc_domain';
  else if (event_family === 'proxy' && iocType === 'url') scenario_type = 'proxy_request_to_ioc_url';
  else if (event_family === 'firewall' && iocType === 'ip' && direction === 'outbound') scenario_type = 'malicious_ip_outbound';
  else if (event_family === 'firewall' && iocType === 'ip' && direction === 'inbound') scenario_type = 'malicious_ip_inbound';

  const context_explanation = (event_family === 'proxy' && iocType === 'domain' && (matched_field === 'url_host' || matched_field === 'request_host' || matched_field === 'connect_host'))
    ? `Proxy ${((proxyMethodMatch?.[1] || '').toUpperCase() || 'request')} to IOC domain observed via squid/web proxy evidence.`
    : (event_family === 'dns' && bindClientMatch?.[1])
      ? `DNS query for the matched IOC domain was observed from client ${bindClientMatch[1]}.`
      : scenario_type === 'dns_response_ip_ioc_observed'
        ? 'IP IOC observed in DNS response_ip; no direct connection evidence.'
        : `${scenario_type} via ${event_family} with outcome=${outcome}`;

  return {
    event_family,
    control_point,
    matched_field,
    scenario_type,
    direction,
    outcome,
    classification_confidence,
    outcome_confidence,
    context_explanation,
    observed_host: merged.client_ip || null,
    resolver_ip: merged.resolver_ip || null,
    source_type: event_family === 'dns' ? 'dns' : null
  };
}

function classifyControlPoint(row) {
  const t = String(row?.ioc_type || '').toLowerCase();
  const note = String(row?.note || '').toLowerCase();
  if (t === 'domain') return 'dns';
  if (t === 'url') return 'proxy';
  if (t === 'ip' || t === 'ip6') return 'firewall';
  if (/(waf|xss|sqli|attack)/.test(note)) return 'waf';
  if (/(mail|smtp|phish)/.test(note)) return 'mail_gateway';
  return 'generic';
}

function classifyScenario(row, controlPoint) {
  const t = String(row?.ioc_type || '').toLowerCase();
  if (t === 'url' && controlPoint === 'proxy') return 'malicious_url_access';
  if (t === 'domain' && controlPoint === 'dns') return 'malicious_domain_dns_query';
  if ((t === 'ip' || t === 'ip6') && Number(row?.outbound_events || 0) > 0) return 'malicious_ip_outbound';
  if ((t === 'ip' || t === 'ip6') && Number(row?.inbound_events || 0) > 0) return 'malicious_ip_inbound';
  if (controlPoint === 'waf') return 'web_attack_payload';
  if (controlPoint === 'mail_gateway') return 'mail_threat_observed';
  return 'unknown_ioc_match';
}

function calculateThreatMetricsV2(incidents = []) {
  const rows = Array.isArray(incidents) ? incidents : [];
  const uniqueIocs = new Set(rows.map((r) => `${r.ioc_type}:${r.ioc_value}`));
  const uniqueIocTypes = new Set(rows.map((r) => String(r.ioc_type || '').toLowerCase()).filter(Boolean));
  const uniqueHosts = rows.reduce((acc, r) => acc + Math.max(Number(r.asset_count || 0), 0), 0);
  const totalHits = rows.reduce((acc, r) => acc + Math.max(Number(r.total_hits || 0), 0), 0);
  const uniqueSources = new Set(rows.map((r) => String(r.source_name || 'unknown')));

  const allowedCount = rows.reduce((a, r) => a + Math.max(Number(r.accepted_connections || 0), 0), 0);
  const blockedCount = rows.reduce((a, r) => a + Math.max(Number(r.blocked_connections || 0), 0), 0);
  const unknownCount = Math.max(totalHits - allowedCount - blockedCount, 0);
  const totalOutcome = Math.max(allowedCount + blockedCount + unknownCount, 1);

  const persistencePoints = Math.min(rows.filter((r) => {
    const f = new Date(r.first_seen || 0).getTime();
    const l = new Date(r.last_seen || 0).getTime();
    return Number.isFinite(f) && Number.isFinite(l) && (l - f) >= 12 * 3600000;
  }).length * 1.5, 10);

  const exposurePoints = Math.min(uniqueIocs.size * 2, 20)
    + Math.min(uniqueIocTypes.size * 5, 15)
    + Math.min(uniqueSources.size * 4, 12)
    + Math.min(uniqueHosts * 2, 20)
    + Math.min(Math.log10(totalHits + 1) * 5, 20)
    + persistencePoints;
  const threatExposureScore = Math.min(100, Number(exposurePoints.toFixed(2)));

  const activitySeverities = rows.map((r) => {
    const cp = classifyControlPoint(r);
    const scenario = classifyScenario(r, cp);
    const allowed = Number(r.accepted_connections || 0) > 0;
    const blocked = Number(r.blocked_connections || 0) > 0 && !allowed;
    let sev = 5;
    if (scenario === 'malicious_url_access') sev = allowed ? 35 : blocked ? 15 : 8;
    else if (scenario === 'malicious_domain_dns_query') sev = allowed ? 10 : blocked ? 5 : 6;
    else if (scenario === 'malicious_ip_outbound') sev = allowed ? 60 : blocked ? 20 : 10;
    else if (scenario === 'malicious_ip_inbound') sev = allowed ? 45 : blocked ? 10 : 8;
    else if (scenario === 'web_attack_payload') sev = allowed ? 55 : 20;
    else if (scenario === 'mail_threat_observed') sev = allowed ? 50 : 15;
    return { row: r, cp, scenario, sev, outcome: allowed ? 'allowed' : blocked ? 'blocked' : 'unknown' };
  }).sort((a, b) => b.sev - a.sev);

  const maxSev = activitySeverities[0]?.sev || 0;
  const otherSum = activitySeverities.slice(1).reduce((a, x) => a + x.sev, 0);
  const threatActivityScore = Math.min(100, Number((maxSev + Math.min(15, 0.15 * otherSum)).toFixed(2)));

  const spreadScore = Math.min(20, rows.filter((r) => Number(r.asset_count || 0) >= 2).length * 2);
  let institutionRiskEstimate = 0.60 * threatActivityScore + 0.25 * threatExposureScore + 0.15 * spreadScore;

  const hasTp = rows.some((r) => String(r.verdict || '').toLowerCase() === 'tp');
  const hasAllowed = allowedCount > 0;
  const allBlockedOnly = blockedCount > 0 && allowedCount === 0;
  const genericUnknownCount = activitySeverities.filter((x) => x.scenario === 'unknown_ioc_match').length;
  if (!hasTp && !hasAllowed) institutionRiskEstimate = Math.min(institutionRiskEstimate, 30);
  if (genericUnknownCount === rows.length) institutionRiskEstimate = Math.min(institutionRiskEstimate, 15);
  if (allBlockedOnly) institutionRiskEstimate = Math.min(institutionRiskEstimate, 25);

  const byCp = {};
  for (const k of ['dns', 'proxy', 'firewall', 'waf', 'mail_gateway', 'generic', 'unknown']) {
    byCp[k] = { allowed_count: 0, blocked_count: 0, unknown_count: 0, total: 0 };
  }
  for (const a of activitySeverities) {
    const bucket = byCp[a.cp] ? a.cp : 'unknown';
    byCp[bucket].total += 1;
    if (a.outcome === 'allowed') byCp[bucket].allowed_count += 1;
    else if (a.outcome === 'blocked') byCp[bucket].blocked_count += 1;
    else byCp[bucket].unknown_count += 1;
  }

  return {
    score_model_version: 'v2',
    threat_exposure_score: threatExposureScore,
    threat_activity_score: threatActivityScore,
    institution_risk_estimate: Number(institutionRiskEstimate.toFixed(2)),
    control_outcome: {
      allowed_count: allowedCount,
      blocked_count: blockedCount,
      unknown_count: unknownCount,
      allowed_ratio: Number((allowedCount / totalOutcome).toFixed(4)),
      blocked_ratio: Number((blockedCount / totalOutcome).toFixed(4))
    },
    activity_by_control_point: byCp,
    score_debug: {
      observed_ioc_count: uniqueIocs.size,
      incident_count: rows.length,
      strong_evidence_count: activitySeverities.filter((x) => x.outcome === 'allowed' || String(x.row?.verdict || '').toLowerCase() === 'tp').length,
      generic_unknown_count: genericUnknownCount,
      caps_applied: [
        !hasTp && !hasAllowed ? 'cap_no_tp_no_allowed_30' : null,
        genericUnknownCount === rows.length ? 'cap_generic_only_15' : null,
        allBlockedOnly ? 'cap_blocked_only_25' : null
      ].filter(Boolean),
      notes: ['v2 is parallel metric; existing institution_risk_score remains unchanged'],
      top_incident_v2: activitySeverities.slice(0, 20).map((x) => ({
        incident_id: x.row.incident_id,
        ioc: x.row.ioc_value,
        ioc_type: x.row.ioc_type,
        event_family: x.cp,
        scenario_type: x.scenario,
        outcome: x.outcome,
        classification_confidence: x.cp === 'generic' ? 0.4 : 0.75,
        outcome_confidence: x.outcome === 'unknown' ? 0.5 : 0.8,
        unique_hosts: Number(x.row.asset_count || 0),
        total_hits: Number(x.row.total_hits || 0),
        verdict: x.row.verdict,
        source_category: x.row.source_name || 'unknown',
        source_confidence: x.row.confidence || 'unknown',
        exposure_points: Number(Math.min(Math.log10(Number(x.row.total_hits || 0) + 1) * 5, 20).toFixed(2)),
        activity_severity: x.sev,
        risk_cap_applied: null,
        explanation: `${x.scenario} via ${x.cp} with outcome=${x.outcome}`
      }))
    }
  };
}

async function computeInstitutionRiskOverview() {
  const [q, totalQ] = await Promise.all([
    pool.query(
      `SELECT
         a.id,
         a.incident_id,
         a.ioc_value,
         a.ioc_type,
         a.total_hits,
         a.status,
         a.verdict,
         a.last_seen,
         a.updated_at,
         a.note,
         COALESCE(ev.event_count, 0) AS event_count,
         COALESCE(ev.asset_count, 0) AS asset_count,
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
       LEFT JOIN LATERAL (
         SELECT
           ${IOC_MATCH_EVENT_STATS_SELECT}
         FROM ioc_match_events m
         WHERE m.activity_id = a.id
       ) ev ON true
       WHERE EXISTS (SELECT 1 FROM ioc_match_events m WHERE m.activity_id = a.id)
       ORDER BY a.last_seen DESC`
    ),
    pool.query(
      `SELECT COUNT(*)::int AS total_active_incidents
       FROM ioc_activity a
       WHERE EXISTS (SELECT 1 FROM ioc_match_events m WHERE m.activity_id = a.id)`
    )
  ]);

  const scoredIncidentsBase = (q.rows || []).map((row) => {
    const risk = calculateIncidentRisk(row);
    return { ...row, ...risk };
  });

  const scoredIncidents = await Promise.all(scoredIncidentsBase.map(async (row) => {
    const version = llmRiskAdvisor.computeVersion(row);
    const cached = await llmRiskAdvisor.getCached({
      incidentId: row.id,
      version,
      baseRisk: row.risk_score,
      incident: row
    });

    if (!cached) {
      return {
        ...row,
        risk_before_llm: null,
        llm_risk_adjustment: null,
        llm_risk_confidence: null,
        llm_risk_reason: null,
        llm_last_updated_at: null,
        llm_version: version,
        final_risk_score: null
      };
    }

    return {
      ...row,
      ...cached,
      risk_score: cached.final_risk_score
    };
  }));

  const overview = calculateInstitutionRisk(scoredIncidents);

  const incidentById = new Map(scoredIncidents.map((row) => [String(row.id), row]));
  const topWithLlm = [];
  for (const it of (overview.top_contributing_incidents || [])) {
    const full = incidentById.get(String(it.id || ''));
    if (!full) {
      topWithLlm.push(it);
      continue;
    }

    const version = llmRiskAdvisor.computeVersion(full);
    const cached = await llmRiskAdvisor.getCached({
      incidentId: full.id,
      version,
      baseRisk: it.risk_score,
      incident: full
    });

    topWithLlm.push({
      ...it,
      risk_before_llm: cached?.risk_before_llm ?? null,
      llm_risk_adjustment: cached?.llm_risk_adjustment ?? null,
      llm_risk_confidence: cached?.llm_risk_confidence ?? null,
      llm_risk_reason: cached?.llm_risk_reason ?? null,
      llm_last_updated_at: cached?.llm_last_updated_at ?? null,
      llm_version: cached?.llm_version ?? version,
      final_risk_score: cached?.final_risk_score ?? null,
      risk_score: cached?.final_risk_score ?? it.risk_score
    });
  }

  const llmRows = topWithLlm.filter((x) => Number.isFinite(Number(x?.llm_risk_adjustment)));
  const llmAdjustmentAggregate = llmRows.length
    ? {
      enabled: true,
      total_adjustment: Number(llmRows.reduce((acc, x) => acc + Number(x.llm_risk_adjustment || 0), 0).toFixed(2)),
      avg_confidence: Number((llmRows.reduce((acc, x) => acc + Number(x.llm_risk_confidence || 0), 0) / llmRows.length).toFixed(3)),
      incident_count: llmRows.length
    }
    : null;

  const totalActiveIncidents = Number(totalQ.rows?.[0]?.total_active_incidents || 0);

  return {
    ...overview,
    top_contributing_incidents: topWithLlm,
    llm_adjustment_aggregate: llmAdjustmentAggregate,
    total_active_incidents: totalActiveIncidents,
    data_truncated: false,
    breakdown: {
      ...(overview.breakdown || {}),
      top_contributing_incidents: topWithLlm,
      llm_adjustment_aggregate: llmAdjustmentAggregate
    }
  };
}

app.get('/api/risk/overview', async (_req, res) => {
  try {
    const overview = await computeInstitutionRiskOverview();
    return res.json(overview);
  } catch (err) {
    console.error('[risk-overview] failed', err);
    return res.status(500).json({
      institution_risk_score: 0,
      active_incident_count: 0,
      total_active_incidents: 0,
      data_truncated: false,
      top_contributing_incidents: [],
      breakdown: { error: 'Failed to compute institution risk overview' }
    });
  }
});

app.get('/api/risk/trend', async (req, res) => {
  try {
    const range = String(req.query?.range || '24h').trim().toLowerCase();
    const allowedRanges = new Set(['24h', '7d', '30d']);
    const selectedRange = allowedRanges.has(range) ? range : '24h';

    const cfg = {
      '24h': {
        sinceSql: "NOW() - INTERVAL '24 hours'",
        query: `SELECT ts, institution_risk::float8 AS risk_score
                FROM risk_snapshots
                WHERE ts >= NOW() - INTERVAL '24 hours'
                ORDER BY ts ASC
                LIMIT 400`
      },
      '7d': {
        sinceSql: "NOW() - INTERVAL '7 days'",
        query: `SELECT
                  date_trunc('hour', ts) AS ts,
                  AVG(institution_risk)::float8 AS risk_score
                FROM risk_snapshots
                WHERE ts >= NOW() - INTERVAL '7 days'
                GROUP BY 1
                ORDER BY 1 ASC`
      },
      '30d': {
        sinceSql: "NOW() - INTERVAL '30 days'",
        query: `SELECT
                  date_trunc('day', ts) AS ts,
                  AVG(institution_risk)::float8 AS risk_score
                FROM risk_snapshots
                WHERE ts >= NOW() - INTERVAL '30 days'
                GROUP BY 1
                ORDER BY 1 ASC`
      }
    };

    const selected = cfg[selectedRange];

    const [overview, trendQ, statsQ] = await Promise.all([
      computeInstitutionRiskOverview(),
      pool.query(selected.query),
      pool.query(
        `SELECT
           COALESCE(MIN(institution_risk), 0)::float8 AS min,
           COALESCE(MAX(institution_risk), 0)::float8 AS max,
           COALESCE(AVG(institution_risk), 0)::float8 AS avg
         FROM risk_snapshots
         WHERE ts >= ${selected.sinceSql}`
      )
    ]);

    const history = (trendQ.rows || []).map((r) => ({
      ts: r.ts,
      risk_score: Number(r.risk_score || 0)
    }));

    const current = Number(overview.institution_risk_score || 0);
    const previous = history.length >= 2 ? Number(history[history.length - 2]?.risk_score || current) : current;
    const delta = Number((current - previous).toFixed(2));
    const trend = delta > 5 ? 'increasing' : delta < -5 ? 'decreasing' : 'stable';

    return res.json({
      range: selectedRange,
      current: Number(current.toFixed(2)),
      previous: Number(previous.toFixed(2)),
      delta,
      trend,
      stats: {
        min: Number(Number(statsQ.rows?.[0]?.min || 0).toFixed(2)),
        max: Number(Number(statsQ.rows?.[0]?.max || 0).toFixed(2)),
        avg: Number(Number(statsQ.rows?.[0]?.avg || 0).toFixed(2))
      },
      history,
      overview
    });
  } catch (err) {
    console.error('[risk-trend] failed', err);
    return res.status(500).json({
      range: '24h',
      current: 0,
      previous: 0,
      delta: 0,
      trend: 'stable',
      stats: { min: 0, max: 0, avg: 0 },
      history: []
    });
  }
});

function normalizeEvidenceRecord(r) {
  const parserSource = String(r?.parser_source || '').toLowerCase();
  const rawLog = String(r?.raw_message_sample || '').trim();
  if (!rawLog || rawLog === '-') return null;

  const srcTypeRaw = String(r?.source_type || '').toLowerCase();
  const lowerRaw = rawLog.toLowerCase();
  const dnsHint = /\bdns\b|\bquery\b|\bqname\b|\brrtype\b/.test(lowerRaw) || /dns/.test(parserSource);
  const proxyHint = /squid|access\.log|\bconnect\b|\bhttp\/1\./.test(lowerRaw) || /proxy|squid|web/.test(parserSource);
  const fwHint = /fortigate|\bsrcip=|\bdstip=|\baction=/.test(lowerRaw) || /fortigate|firewall|traffic/.test(parserSource);

  let source_type = 'generic';
  if (proxyHint) source_type = 'proxy';
  else if (dnsHint) source_type = 'dns';
  else if (fwHint) source_type = 'firewall';
  else if (srcTypeRaw) source_type = srcTypeRaw;

  let observed_host = String(r?.observed_host || '').trim();
  if (!observed_host || observed_host === '-') {
    const srcIpMatch = rawLog.match(/\bsrcip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
    const squidIpMatch = rawLog.match(/\b(?:TCP_[A-Z]+|CONNECT|GET|POST|HEAD|PUT|DELETE|OPTIONS)\b.*?\s([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s/i)
      || rawLog.match(/\bclient(?:ip)?[=:]([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i)
      || rawLog.match(/\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+TCP_/i);
    const dnsClientMatch = rawLog.match(/\bclient(?:\s+|=|:)?([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);

    if (source_type === 'firewall' && srcIpMatch) observed_host = srcIpMatch[1];
    else if (source_type === 'proxy' && squidIpMatch) observed_host = squidIpMatch[1];
    else if (source_type === 'dns' && dnsClientMatch) observed_host = dnsClientMatch[1];
  }

  return {
    ...r,
    source_type,
    observed_host: observed_host || null,
    detection_event_id: (Number(r?.match_event_id || 0) > 0 ? Number(r.match_event_id) : null)
  };
}

app.get('/api/incidents/:id/related-logs', async (req, res) => {
  try {
    const idRaw = String(req.params?.id || '').trim();
    if (!idRaw) return res.status(400).json({ message: 'Invalid id' });
    const incident = await findIncidentRow(idRaw);
    if (!incident?.id) return res.status(404).json({ message: 'Incident not found' });

    const page = Math.max(Number(req.query?.page || 1), 1);
    const pageSize = Math.min(Math.max(Number(req.query?.pageSize || 50), 1), 200);
    const offset = (page - 1) * pageSize;
    const sort = String(req.query?.sort || 'asc').toLowerCase() === 'desc' ? 'DESC' : 'ASC';

    const activityId = String(incident.id);
    const rows = await clickhouseQuery(`
      SELECT
        activity_id,
        any(incident_id) AS incident_id,
        any(match_event_id) AS match_event_id,
        evidence_hash,
        min(log_ts) AS log_ts,
        any(matched_ioc) AS matched_ioc,
        any(observable_type) AS observable_type,
        any(log_host) AS log_host,
        any(observed_host) AS observed_host,
        any(parser_source) AS parser_source,
        any(source_type) AS source_type,
        any(raw_message_sample) AS raw_message_sample,
        any(raw_message_hash) AS raw_message_hash
      FROM security_evidence.incident_related_logs
      WHERE activity_id = toUUID('${escapeChString(activityId)}')
      GROUP BY activity_id, evidence_hash
      ORDER BY log_ts ${sort}
    `);

    let normalized = (rows || []).map(normalizeEvidenceRecord).filter(Boolean).map((r) => ({
      ...r,
      evidence_origin: 'clickhouse_related_logs',
      fallback: false
    }));

    if (normalized.length === 0) {
      const pgQ = await pool.query(
        `SELECT
           id AS match_event_id,
           activity_id,
           event_time AS log_ts,
           matched_ioc,
           ioc_type AS observable_type,
           host_name AS log_host,
           source_type,
           parser_source,
           COALESCE(raw_log_snapshot, '') AS raw_log_snapshot,
           normalized_event_json
         FROM ioc_match_events
         WHERE activity_id = $1::uuid
         ORDER BY COALESCE(last_seen_at, event_time, created_at) ${sort}, id ${sort}`,
        [activityId]
      );

      normalized = (pgQ.rows || []).map((r) => {
        const raw = String(r?.raw_log_snapshot || '').trim();
        const normJson = r?.normalized_event_json ? JSON.stringify(r.normalized_event_json) : '';
        const evidenceText = raw || normJson;
        if (!evidenceText) return null;
        return normalizeEvidenceRecord({
          ...r,
          raw_message_sample: evidenceText
        });
      }).filter(Boolean).map((r) => ({
        ...r,
        evidence_origin: 'pg_detection_event_snapshot',
        fallback: true
      }));
    }

    const total = normalized.length;
    const paged = normalized.slice(offset, offset + pageSize);

    return res.json({ items: paged, page, pageSize, total });
  } catch (err) {
    console.error('[incident-related-logs] failed', err);
    return res.status(500).json({ items: [], page: 1, pageSize: 50, total: 0, error: 'unavailable' });
  }
});

app.get('/api/incidents/:id/related-logs/export.csv', async (req, res) => {
  try {
    const idRaw = String(req.params?.id || '').trim();
    if (!idRaw) return res.status(400).send('Invalid id');
    const incident = await findIncidentRow(idRaw);
    if (!incident?.id) return res.status(404).send('Incident not found');
    const maxRows = Math.max(Number(process.env.RELATED_LOG_EXPORT_MAX_ROWS || 10000), 1000);
    const activityId = String(incident.id);
    const rows = await clickhouseQuery(`
      SELECT any(incident_id) AS incident_id, activity_id, any(match_event_id) AS match_event_id,
             evidence_hash, min(log_ts) AS log_ts, toNullable(NULL) AS ingest_time, any(observed_host) AS observed_host, any(log_host) AS log_host,
             any(matched_ioc) AS matched_ioc, any(observable_type) AS observable_type, any(parser_source) AS parser_source,
             any(source_type) AS source_type, any(raw_message_sample) AS raw_message_sample, any(raw_message_hash) AS raw_message_hash
      FROM security_evidence.incident_related_logs
      WHERE activity_id = toUUID('${escapeChString(activityId)}')
      GROUP BY activity_id, evidence_hash
      ORDER BY log_ts ASC
      LIMIT ${maxRows}
    `);
    const normalized = (rows || []).map(normalizeEvidenceRecord).filter(Boolean);
    const esc = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`;
    const header = ['time','ingest_time','observed_host','matched_ioc','observable_type','source_type','parser_source','source_host','detection_event_id','evidence_hash','raw_log'];
    const lines = [header.join(',')];
    for (const r of normalized) lines.push([
      r.log_ts, r.ingest_time, r.observed_host, r.matched_ioc, r.observable_type, r.source_type, r.parser_source, r.log_host,
      (Number(r.match_event_id || 0) > 0 ? r.match_event_id : ''), r.evidence_hash, r.raw_message_sample
    ].map(esc).join(','));
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="incident-${incident.incident_id}-related-logs.csv"`);
    return res.send(lines.join('\n'));
  } catch (err) {
    console.error('[incident-related-logs-export] failed', err);
    return res.status(500).send('Export failed');
  }
});

app.get('/api/incidents/:id/events', async (req, res) => {
  const t0 = Date.now();
  const perf = { dbMs: 0, enrichMs: 0, countMs: 0, rows: 0, db: 'postgres', chUsed: false };
  try {
    const idRaw = String(req.params?.id || '').trim();
    if (!idRaw) return res.status(400).json({ message: 'Invalid id' });

    const incident = await findIncidentRow(idRaw);
    if (!incident?.id) return res.status(404).json({ message: 'Incident not found' });

    const limit = Math.min(Math.max(Number(req.query?.limit || 50), 1), 500);
    const offset = Math.max(Number(req.query?.offset || 0), 0);
    const debugContext = ['1', 'true', 'yes'].includes(String(req.query?.debugContext || req.query?.debug_context || '').toLowerCase());
    // context_debug is attached per-event only when debugContext is truthy; default JSON contract unchanged.

    const dbStart = Date.now();
    const q = await pool.query(
      `WITH recent AS (
         SELECT
           m.id,
           m.event_time,
           m.matched_ioc,
           m.ioc_type,
           m.source_name,
           m.source,
           m.host_name,
           m.source_type,
           m.parser_source,
           m.raw_log_snapshot,
           m.normalized_event_json,
           m.detection_type,
           m.activity_id,
           m.verdict,
           m.assigned_to,
           m.created_at,
           m.match_context,
           COALESCE(m.last_seen_at, m.event_time, m.created_at) AS detected_at,
           COALESCE(
             NULLIF(CONCAT_WS(' | ',
               NULLIF(m.source, ''),
               NULLIF(m.host_name, ''),
               NULLIF(m.process_name, ''),
               CASE
                 WHEN m.destination_ip IS NOT NULL AND m.destination_ip <> '' THEN m.destination_ip || COALESCE(':' || m.destination_port::text, '')
                 ELSE NULL
               END,
               NULLIF(m.protocol, '')
             ), ''),
             '-'
           ) AS matched_syslog_event,
           COALESCE(
             m.detection_type,
             CASE
               WHEN COALESCE(NULLIF(m.match_context->>'processing_path', ''), 'realtime') = 'retro'
                 OR COALESCE((m.match_context->>'retroactive')::boolean, false)
               THEN 'retroactive'
               ELSE 'realtime'
             END
           ) AS detection_mode
         FROM ioc_match_events m
         WHERE m.activity_id = $1::uuid
         ORDER BY COALESCE(m.last_seen_at, m.event_time, m.created_at) DESC, m.id DESC
         LIMIT $2 OFFSET $3
       ), source_agg AS (
         SELECT
           i.observable AS observable_norm,
           COUNT(DISTINCT i.source_name)::int AS source_count,
           ARRAY_AGG(DISTINCT i.source_name ORDER BY i.source_name) AS source_names
         FROM ioc_items i
         WHERE i.observable IN (SELECT DISTINCT lower(r.matched_ioc) FROM recent r)
         GROUP BY i.observable
       )
       SELECT
         r.*,
         COALESCE(sa.source_count, 0) AS source_count,
         COALESCE(sa.source_names, ARRAY[]::text[]) AS source_names
       FROM recent r
       LEFT JOIN source_agg sa ON sa.observable_norm = lower(r.matched_ioc)
       ORDER BY r.detected_at DESC, r.id DESC`,
      [incident.id, limit, offset]
    );
    perf.dbMs = Date.now() - dbStart;

    const countStart = Date.now();
    const totalQ = await pool.query(
      `SELECT COUNT(*)::bigint AS total
       FROM ioc_match_events
       WHERE activity_id = $1::uuid`,
      [incident.id]
    );

    perf.countMs = Date.now() - countStart;

    // Important: keep list endpoint lean (no per-row raw log lookup / no N+1).
    const enrichStart = Date.now();
    const baseItems = (q.rows || []);

    async function mapWithConcurrency(arr, limit, mapper) {
      const out = new Array(arr.length);
      let idx = 0;
      async function worker() {
        while (idx < arr.length) {
          const i = idx++;
          try { out[i] = await mapper(arr[i], i); } catch { out[i] = arr[i]; }
        }
      }
      const workers = Array.from({ length: Math.max(1, Math.min(limit, arr.length)) }, () => worker());
      await Promise.all(workers);
      return out;
    }

    const enrichedRows = await mapWithConcurrency(baseItems, 8, async (r) => {
      try {
        if (r?.raw_log_snapshot && String(r.raw_log_snapshot).trim()) {
          return { ...r, matched_syslog_event: String(r.raw_log_snapshot) };
        }
        const enriched = await Promise.race([
          withRawSyslogEvent(r),
          new Promise((resolve) => setTimeout(() => resolve(r), 1500))
        ]);
        return enriched || r;
      } catch {
        return r;
      }
    });

    perf.rows = enrichedRows.length;
    const items = enrichedRows.map((r) => {
      const enrichedForContext = {
        ...r,
        parser_source: r?.parser_source || null,
        source_type: r?.source_type || null,
        raw_log_snapshot: r?.raw_log_snapshot || null,
        matched_syslog_event: r?.matched_syslog_event || r?.raw_log_snapshot || r?.matched_syslog_event || '-'
      };
      const v2 = classifyEventContext(enrichedForContext);
      const st = String(enrichedForContext?.source_type || '').toLowerCase();
      const inferredFamily = String(v2?.event_family || '').toLowerCase();
      let family = (inferredFamily && inferredFamily !== 'generic') ? inferredFamily : (st || inferredFamily || 'generic');
      const iocType = String(r?.ioc_type || '').toLowerCase();
      const iocVal = String(r?.matched_ioc || '').toLowerCase();
      const looksLikeUrl = iocType === 'url' || iocVal.startsWith('http://') || iocVal.startsWith('https://');
      if (looksLikeUrl) family = 'proxy';
      const context_label = family === 'proxy' ? 'Proxy'
        : family === 'dns' ? 'DNS'
          : family === 'firewall' ? 'Firewall'
            : family === 'waf' ? 'WAF'
              : family === 'endpoint' ? 'Endpoint'
                : 'Generic';
      const out = {
        ...r,
        parser_source: enrichedForContext?.parser_source || r?.parser_source || null,
        source_type: enrichedForContext?.source_type || r?.source_type || null,
        raw_log_snapshot: enrichedForContext?.raw_log_snapshot || r?.raw_log_snapshot || null,
        context_label,
        inferred_context: family || 'generic',
        event_family: family || 'generic',
        control_point: v2?.control_point || (family === 'dns' ? 'dns_resolver' : family || 'generic'),
        scenario: v2?.scenario_type || null,
        matched_field: v2?.matched_field || null,
        v2_context: v2
      };
      if (debugContext) {
        const lane = String(ev?.evidence_lane || '');
        let selectedRawSource = 'none';
        if (lane === 'bulk_squid_over_related') selectedRawSource = 'bulk_squid_over_related_logs';
        else if (lane === 'incident_related_logs') selectedRawSource = 'incident_related_logs';
        else if (lane === 'syslog_logs_bulk') selectedRawSource = 'syslog_logs_bulk';
        else if (snapRaw) selectedRawSource = 'pg_raw_log_snapshot';
        else if (pgSummary && pgSummary !== '-') selectedRawSource = 'pg_matched_syslog_summary';
        out.context_debug = {
          event_id: r.id,
          source_type_before: r.source_type,
          parser_source_before: r.parser_source,
          evidence_lane: lane || null,
          selected_raw_source: selectedRawSource,
          selected_raw_sample: rawForClassify ? rawForClassify.slice(0, 420) : '',
          raw_contains_squid: rawLooksLikeSquidOrHttpProxy(rawForClassify),
          inferred_family: inferredFamily,
          final_context_label: context_label,
          used_v2_context: {
            event_family: v2?.event_family,
            control_point: v2?.control_point,
            scenario_type: v2?.scenario_type,
            matched_field: v2?.matched_field,
            direction: v2?.direction
          },
          used_match_context: r.match_context || null
        };
      }
      return out;
    });
    perf.enrichMs = Date.now() - enrichStart;
    const total = Number(totalQ.rows?.[0]?.total || 0);
    const totalMs = Date.now() - t0;
    console.info(`[incident-events] incident_id=${idRaw} activity_id=${incident.id} rows=${perf.rows} total=${total} db=${perf.db} ch_used=${perf.chUsed} db_ms=${perf.dbMs} count_ms=${perf.countMs} enrich_ms=${perf.enrichMs} total_ms=${totalMs} limit=${limit} offset=${offset} table=ioc_match_events`);
    return res.json({ events: items, total, limit, offset, items });
  } catch (err) {
    const totalMs = Date.now() - t0;
    console.error(`[incident-events] failed incident_id=${String(req.params?.id || '')} total_ms=${totalMs}`, err);
    return res.status(500).json({ total: 0, items: [] });
  }
});

app.patch('/api/incidents/:id', async (req, res) => {
  const tx = await pool.connect();
  try {
    const idRaw = String(req.params?.id || '').trim();
    if (!idRaw) return res.status(400).json({ message: 'Invalid id' });

    const incident = await findIncidentRow(idRaw);
    if (!incident?.id) return res.status(404).json({ message: 'Incident not found' });

    const bodyVerdict = req.body?.verdict;
    const note = req.body?.note == null ? null : String(req.body.note).trim().slice(0, 4000);
    const takeOwnership = Boolean(req.body?.take_ownership || req.body?.takeOwnership);
    const propagateToEvents = Boolean(req.body?.propagate_to_events || req.body?.propagateToEvents);
    const propagationNote = req.body?.propagation_note == null ? null : String(req.body.propagation_note).trim().slice(0, 4000);
    const reviewer = String(req.user?.username || req.user?.email || '').trim() || null;

    const verdict = bodyVerdict == null || String(bodyVerdict).trim() === ''
      ? null
      : String(bodyVerdict).trim();

    const allowedVerdicts = new Set(['TP', 'FP', 'Suspicious', 'Unreviewed', 'In Progress']);
    if (verdict !== null && !allowedVerdicts.has(verdict)) {
      return res.status(400).json({ message: 'Invalid verdict' });
    }

    const derivedStatus = (v) => {
      if (v === 'TP' || v === 'FP' || v === 'Suspicious') return 'closed';
      return 'open';
    };

    const eventVerdictMap = {
      TP: 'tp',
      FP: 'fp',
      Suspicious: 'suspicious',
      'In Progress': 'in_progress',
      Unreviewed: null
    };

    await tx.query('BEGIN');

    const curQ = await tx.query(
      `SELECT * FROM ioc_activity WHERE id = $1::uuid LIMIT 1 FOR UPDATE`,
      [incident.id]
    );
    if (!curQ.rowCount) {
      await tx.query('ROLLBACK');
      return res.status(404).json({ message: 'Incident not found' });
    }

    const current = curQ.rows[0];
    const nextVerdict = verdict ?? current.verdict ?? 'Unreviewed';
    const nextStatus = derivedStatus(nextVerdict);

    const updQ = await tx.query(
      `UPDATE ioc_activity
       SET verdict = $2::text,
           status = $3::text,
           note = COALESCE($4::text, note),
           assigned_to = CASE
             WHEN $5::boolean = true THEN $6::text
             ELSE assigned_to
           END,
           assigned_at = CASE
             WHEN $5::boolean = true THEN NOW()
             ELSE assigned_at
           END,
           updated_at = NOW()
       WHERE id = $1::uuid
       RETURNING *`,
      [incident.id, nextVerdict, nextStatus, note, takeOwnership, reviewer]
    );

    if (!updQ.rowCount) {
      await tx.query('ROLLBACK');
      return res.status(404).json({ message: 'Incident not found' });
    }

    if (propagateToEvents) {
      await tx.query(
        `UPDATE ioc_match_events
         SET verdict = $2::text,
             reviewed_at = CASE WHEN $2::text IS NULL THEN NULL ELSE NOW() END,
             reviewed_by = CASE WHEN $2::text IS NULL THEN NULL ELSE $3::text END,
             assigned_to = COALESCE($3::text, assigned_to),
             assigned_at = CASE WHEN $3::text IS NULL THEN assigned_at ELSE NOW() END,
             note = COALESCE($4::text, note)
         WHERE activity_id = $1::uuid`,
        [incident.id, eventVerdictMap[nextVerdict], reviewer, propagationNote]
      );
    }

    await tx.query('COMMIT');
    return res.json({ item: updQ.rows[0] });
  } catch (err) {
    await tx.query('ROLLBACK').catch(() => {});
    console.error('[incident-patch] failed', err);
    return res.status(500).json({ message: 'Failed to update incident' });
  } finally {
    tx.release();
  }
});

app.get('/api/analytics/statistics', async (req, res) => {
  try {
    const hours = Math.min(Math.max(Number(req.query?.hours || 24), 1), 168);

    if (USE_CLICKHOUSE) {
      const top_sources = await clickhouseQuery(`
        SELECT source, count() AS events
        FROM syslog_logs
        WHERE ts > now() - INTERVAL ${hours} HOUR
        GROUP BY source
        ORDER BY events DESC
        LIMIT 10
      `);

      const top_clients = await clickhouseQuery(`
        SELECT host, count() AS events
        FROM syslog_logs
        WHERE ts > now() - INTERVAL ${hours} HOUR
        GROUP BY host
        ORDER BY events DESC
        LIMIT 10
      `);

      const timeline = await clickhouseQuery(`
        SELECT toStartOfHour(ts) AS hour, count() AS events
        FROM syslog_logs
        WHERE ts > now() - INTERVAL ${hours} HOUR
        GROUP BY hour
        ORDER BY hour
      `);

      const riskyClientsQ = await pool.query(
        `SELECT
           host_name,
           COUNT(*)::bigint AS risky_event_count,
           MAX(created_at) AS last_risky_seen_at
         FROM ioc_match_events
         WHERE created_at >= NOW() - ($1::text || ' hours')::interval
           AND host_name IS NOT NULL
         GROUP BY host_name
         ORDER BY risky_event_count DESC, last_risky_seen_at DESC
         LIMIT 10`,
        [hours]
      );

      return res.json({
        hours,
        top_sources,
        top_clients,
        risky_clients: riskyClientsQ.rows,
        timeline
      });
    }

    const topSourceQ = await pool.query(
      `SELECT source_key, COUNT(*)::bigint AS event_count
       FROM signal_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
       GROUP BY source_key
       ORDER BY event_count DESC
       LIMIT 10`,
      [hours]
    );

    const topClientQ = await pool.query(
      `SELECT host_name, COUNT(*)::bigint AS event_count
       FROM signal_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
         AND host_name IS NOT NULL
       GROUP BY host_name
       ORDER BY event_count DESC
       LIMIT 10`,
      [hours]
    );

    const timelineQ = await pool.query(
      `SELECT
         date_trunc('hour', created_at) AS bucket,
         source_key,
         host_name,
         COUNT(*)::bigint AS event_count
       FROM signal_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
       GROUP BY bucket, source_key, host_name
       ORDER BY bucket ASC`,
      [hours]
    );

    const riskyClientsQ = await pool.query(
      `SELECT
         host_name,
         COUNT(*)::bigint AS risky_event_count,
         MAX(created_at) AS last_risky_seen_at
       FROM ioc_match_events
       WHERE created_at >= NOW() - ($1::text || ' hours')::interval
         AND host_name IS NOT NULL
       GROUP BY host_name
       ORDER BY risky_event_count DESC, last_risky_seen_at DESC
       LIMIT 10`,
      [hours]
    );

    return res.json({
      hours,
      top_sources: topSourceQ.rows,
      top_clients: topClientQ.rows,
      risky_clients: riskyClientsQ.rows,
      timeline: timelineQ.rows
    });
  } catch (err) {
    console.error('[analytics-statistics] failed', err);
    return res.status(500).json({ hours: 24, top_sources: [], top_clients: [], risky_clients: [], timeline: [] });
  }
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

function mergeIntegrationListRow(feed, latestRunByJobType, latestQueueByKey, asnLastUpdatedAt) {
  const lr = latestRunByJobType.get(feedJobType(feed.key));
  const lq = latestQueueByKey.get(feed.key);
  const recordsProcessed = Number(lr?.records_processed ?? lq?.records_processed ?? 0) || 0;

  if (feed.key === 'asn_enrichment') {
    return {
      ...feed,
      last_status: asnLastUpdatedAt ? 'success' : 'never',
      last_started_at: asnLastUpdatedAt || null,
      last_finished_at: null,
      last_records_processed: 0,
      total_records: null,
      last_error: null
    };
  }

  return {
    ...feed,
    last_status: lr?.status || lq?.status || 'never',
    last_started_at: lr?.started_at || lq?.started_at || lq?.queued_at || null,
    last_finished_at: lr?.finished_at || lq?.finished_at || null,
    last_records_processed: recordsProcessed,
    total_records: recordsProcessed,
    last_error: lr?.error_message || lq?.error_message || null
  };
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

    const feedsQ = `
      SELECT
        f.key,
        f.integration_id,
        f.name,
        f.source_url,
        f.schedule_cron AS schedule,
        f.trust_level,
        f.created_at,
        CASE
          WHEN f.schedule_cron = '*/5 * * * *' THEN date_trunc('minute', NOW()) + (CASE WHEN EXTRACT(MINUTE FROM NOW())::int % 5 = 0 THEN 5 ELSE 5 - (EXTRACT(MINUTE FROM NOW())::int % 5) END) * INTERVAL '1 minute'
          WHEN f.schedule_cron = '*/15 * * * *' THEN date_trunc('minute', NOW()) + (CASE WHEN EXTRACT(MINUTE FROM NOW())::int % 15 = 0 THEN 15 ELSE 15 - (EXTRACT(MINUTE FROM NOW())::int % 15) END) * INTERVAL '1 minute'
          WHEN f.schedule_cron = '*/30 * * * *' THEN date_trunc('minute', NOW()) + (CASE WHEN EXTRACT(MINUTE FROM NOW())::int % 30 = 0 THEN 30 ELSE 30 - (EXTRACT(MINUTE FROM NOW())::int % 30) END) * INTERVAL '1 minute'
          WHEN f.schedule_cron = '0 0 * * *' THEN date_trunc('day', NOW()) + INTERVAL '1 day'
          ELSE date_trunc('hour', NOW()) + INTERVAL '1 hour'
        END AS next_run_at
      FROM integration_feeds f
      WHERE f.active = TRUE
      ORDER BY f.created_at ASC, f.name ASC
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
        q.finished_at
      FROM integration_queue_jobs q
      LEFT JOIN integration_feeds f ON f.key = q.integration_key
      ORDER BY q.queued_at DESC
      LIMIT 20
    `;

    const baseStart = Date.now();
    const feedsRes = await pool.query(feedsQ);
    integrationsTimingLog(timingEnabled, 'integration base query', baseStart);

    const feedKeys = feedsRes.rows.map((r) => r.key);
    const jobTypes = [...new Set(feedKeys.map((key) => feedJobType(key)))];

    const latestRunsQ = `
      SELECT DISTINCT ON (job_type)
        job_type, status, started_at, finished_at, records_processed, error_message
      FROM integration_runs
      WHERE job_type = ANY($1::text[])
      ORDER BY job_type, started_at DESC
    `;

    const latestQueueQ = `
      SELECT DISTINCT ON (integration_key_norm)
        integration_key_norm AS integration_key,
        status, started_at, queued_at, finished_at, records_processed, error_message
      FROM (
        SELECT
          CASE
            WHEN integration_key = 'unknown' AND job_name = 'phishtank-import' THEN 'phishtank-opendnsrr'
            ELSE integration_key
          END AS integration_key_norm,
          status, started_at, queued_at, finished_at, records_processed, error_message
        FROM integration_queue_jobs
        WHERE integration_key = ANY($1::text[])
           OR (integration_key = 'unknown' AND job_name = 'phishtank-import')
      ) qn
      ORDER BY integration_key_norm, COALESCE(started_at, queued_at) DESC
    `;

    const asnQ = `SELECT MAX(updated_at) AS last_updated_at FROM asn_lookup`;

    const latestRunStart = Date.now();
    const [latestRunsRes, latestQueueRes, asnRes, recentRes] = await Promise.all([
      jobTypes.length
        ? queryIntegrationsMetaWithTimeout(pool.query(latestRunsQ, [jobTypes]))
        : Promise.resolve({ rows: [] }),
      feedKeys.length
        ? queryIntegrationsMetaWithTimeout(pool.query(latestQueueQ, [feedKeys]))
        : Promise.resolve({ rows: [] }),
      feedKeys.includes('asn_enrichment')
        ? queryIntegrationsMetaWithTimeout(pool.query(asnQ))
        : Promise.resolve({ rows: [{ last_updated_at: null }] }),
      pool.query(recentQ)
    ]);
    integrationsTimingLog(timingEnabled, 'latest run query', latestRunStart);

    const latestRunByJobType = new Map(latestRunsRes.rows.map((r) => [r.job_type, r]));
    const latestQueueByKey = new Map(latestQueueRes.rows.map((r) => [r.integration_key, r]));
    const asnLastUpdatedAt = asnRes.rows[0]?.last_updated_at || null;

    const integrations = feedsRes.rows.map((feed) =>
      mergeIntegrationListRow(feed, latestRunByJobType, latestQueueByKey, asnLastUpdatedAt)
    );

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
        jobs: jobsRows.rows,
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
    }

    integrationsTimingLog(timingEnabled, 'endpoint total', handlerStart);

    return res.json({
      integrations,
      recent_runs: recentRes.rows,
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
  'phishtank-opendnsrr': 'phishtank-import'
};

const TRUST_LEVELS = new Set(['guvenilir', 'orta', 'not_categorized']);
const SCHEDULE_CRONS = new Set(['*/5 * * * *', '*/15 * * * *', '*/30 * * * *', '0 * * * *']);

app.post('/api/integrations/run-now', async (_req, res) => {
  try {
    const keys = Object.keys(INTEGRATION_JOBS);
    const jobs = await Promise.all(keys.map((key) => importQueue.add(INTEGRATION_JOBS[key], { triggeredBy: 'manual-ui-all', integration_key: key })));

    await Promise.all(jobs.map((j, idx) => pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
       VALUES ($1, $2, $3, 'queued', 'manual-ui-all', NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='queued', updated_at=NOW()`,
      [String(j.id), keys[idx], INTEGRATION_JOBS[keys[idx]]]
    )));

    return res.status(202).json({ ok: true, queued: true, count: jobs.length, job_ids: jobs.map((j) => j.id) });
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
    const job = await importQueue.add(jobName, { triggeredBy: 'manual-ui-one', integration_key: key });
    await pool.query(
      `INSERT INTO integration_queue_jobs (job_id, integration_key, job_name, status, triggered_by, queued_at, updated_at)
       VALUES ($1, $2, $3, 'queued', 'manual-ui-one', NOW(), NOW())
       ON CONFLICT (job_id)
       DO UPDATE SET status='queued', updated_at=NOW()`,
      [String(job.id), key, jobName]
    );
    return res.status(202).json({ ok: true, queued: true, key, job_id: job.id });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to queue integration run', detail: err.message });
  }
});

app.put('/api/integrations/:key/trust-level', async (req, res) => {
  const { key } = req.params;
  const trustLevel = String(req.body?.trust_level || '').trim();

  if (!TRUST_LEVELS.has(trustLevel)) {
    return res.status(400).json({ message: 'Invalid trust_level' });
  }

  try {
    const result = await pool.query(
      `UPDATE integration_feeds
       SET trust_level = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, trust_level`,
      [key, trustLevel]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update trust level', detail: err.message });
  }
});

app.put('/api/integrations/:key/schedule', async (req, res) => {
  const { key } = req.params;
  const scheduleCron = String(req.body?.schedule_cron || '').trim();

  if (!SCHEDULE_CRONS.has(scheduleCron)) {
    return res.status(400).json({ message: 'Invalid schedule_cron' });
  }

  try {
    const result = await pool.query(
      `UPDATE integration_feeds
       SET schedule_cron = $2, updated_at = NOW()
       WHERE key = $1
       RETURNING key, schedule_cron`,
      [key, scheduleCron]
    );

    if (!result.rowCount) {
      return res.status(404).json({ message: 'Integration not found' });
    }

    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to update schedule', detail: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const loginId = String(email || '').trim();

  if (!loginId || password == null || typeof password !== 'string') {
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

  if (loginId === demoEmail && password === demoPassword) {
    const token = signUserToken(loginId);
    appendAuthCookie(req, res, token);
    appendCsrfCookie(req, res);
    return res.json({
      user: { email: loginId, username: loginId, id: null, role: ROLES.ADMIN }
    });
  }

  return res.status(401).json({ message: 'Invalid email or password' });
});

app.post('/api/auth/logout', (req, res) => {
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

registerUserManagementRoutes(app, pool);
registerPublicFeedRoutes(app, pool);
registerPublishedFeedRoutes(app, pool);

function isAdminUser(req) {
  const role = String(req.user?.role || '').trim().toLowerCase();
  return role === ROLES.ADMIN;
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
    const iocExists = await pool.query('SELECT observable_type FROM ioc_items WHERE id = $1 LIMIT 1', [iocId]);
    if (!iocExists.rowCount) return res.status(404).json({ message: 'IOC not found' });

    const iocObservableType = String(iocExists.rows[0].observable_type || '').trim();

    const tagExists = await pool.query('SELECT 1 FROM tags WHERE id = $1 AND enabled = TRUE LIMIT 1', [tagId]);
    if (!tagExists.rowCount) return res.status(404).json({ message: 'Tag not found or disabled' });

    await pool.query(
      `INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, created_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (ioc_id, tag_id) DO NOTHING`,
      [iocId, iocObservableType, tagId, req.user?.id ?? null]
    );

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
    await pool.query(
      `DELETE FROM ioc_tags
       WHERE ioc_id = $1
         AND tag_id = $2
         AND ioc_observable_type = (
           SELECT observable_type FROM ioc_items WHERE id = $1 LIMIT 1
         )`,
      [iocId, tagId]
    );
    return res.status(204).end();
  } catch (err) {
    return res.status(500).json({ message: 'Failed to delete IOC tag', detail: err.message });
  }
});

app.post('/api/ioc/ip', async (req, res) => {
  const { ip, source_name, source_url, confidence = 'medium', category = null, note = null } = req.body || {};

  if (!ip || !source_name) {
    return res.status(400).json({ message: 'ip and source_name are required' });
  }

  const value = String(ip).trim();
  const isUrl = /^https?:\/\//i.test(value);
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(value);
  const inferredType = (isUrl || value.includes('/')) ? 'url' : (isIpv4 ? 'ip' : 'domain');

  try {
    if (inferredType !== 'ip') {
      const qObs = `
        INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note)
        SELECT $1, $2, $3, $4, $5, $6, $7
        WHERE NOT EXISTS (
          SELECT 1
          FROM ioc_items
          WHERE observable = $1
            AND observable_type = $2
            AND source_name = $3
            AND confidence = $5
            AND COALESCE(category, '') = COALESCE($6, '')
            AND COALESCE(source_url, '') = COALESCE($4, '')
        )
        RETURNING *
      `;
      const { rows } = await pool.query(qObs, [value, inferredType, source_name, source_url || null, confidence, category, note]);
      if (!rows.length) return res.status(200).json({ skipped: true, reason: 'duplicate_tuple' });

      await pool.query(
        `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
         VALUES ($1, $2, $3)
         ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
        [rows[0].public_id, rows[0].observable_type, String(rows[0].observable || '').toLowerCase()]
      ).catch(() => {});

      scheduleGeoCacheRefreshAfterAdd();
      await pool.query(
        `INSERT INTO dashboard_map_pending_events (event_type, ioc_id, observable, observable_type)
         VALUES ('add', $1, $2, $3)`,
        [rows[0].id, rows[0].observable, rows[0].observable_type]
      ).catch(() => {});
      return res.status(201).json(rows[0]);
    }

    const q = `
      INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note)
      SELECT $1, 'ip', $2, $3, $4, $5, $6
      WHERE NOT EXISTS (
        SELECT 1
        FROM ioc_items
        WHERE observable = $1
          AND observable_type = 'ip'
          AND source_name = $2
          AND confidence = $4
          AND COALESCE(category, '') = COALESCE($5, '')
          AND COALESCE(source_url, '') = COALESCE($3, '')
      )
      RETURNING *
    `;
    const values = [value, source_name, source_url || null, confidence, category, note];
    const { rows } = await pool.query(q, values);

    if (!rows.length) {
      return res.status(200).json({ skipped: true, reason: 'duplicate_tuple' });
    }

    await pool.query(
      `INSERT INTO ioc_observables (ioc_public_id, observable_type, observable_value)
       VALUES ($1, $2, $3)
       ON CONFLICT (ioc_public_id, observable_type, observable_value) DO NOTHING`,
      [rows[0].public_id, rows[0].observable_type, String(rows[0].observable || '').toLowerCase()]
    ).catch(() => {});

    scheduleGeoCacheRefreshAfterAdd();
    await pool.query(
      `INSERT INTO dashboard_map_pending_events (event_type, ioc_id, observable, observable_type)
       VALUES ('add', $1, $2, $3)`,
      [rows[0].id, rows[0].observable, rows[0].observable_type]
    ).catch(() => {});

    return res.status(201).json(rows[0]);
  } catch (err) {
    return res.status(500).json({ message: 'Failed to create record', detail: err.message });
  }
});

app.delete('/api/ioc/:publicId', async (req, res) => {
  const publicId = String(req.params?.publicId || '').trim();
  if (!publicId) {
    return res.status(400).json({ message: 'valid publicId is required' });
  }

  try {
    const prev = await pool.query('SELECT id, public_id, observable, observable_type FROM ioc_items WHERE public_id = $1::uuid LIMIT 1', [publicId]);
    if (!prev.rows.length) {
      return res.status(404).json({ message: 'IOC not found' });
    }

    await pool.query('DELETE FROM ioc_items WHERE public_id = $1::uuid', [publicId]);
    const row = prev.rows[0];
    await pool.query(
      `INSERT INTO dashboard_map_pending_events (event_type, ioc_id, observable, observable_type)
       VALUES ('delete', $1, $2, $3)`,
      [row.id, row.observable, row.observable_type]
    ).catch(() => {});

    return res.json({ ok: true, deleted_public_id: row.public_id });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to delete IOC', detail: err.message });
  }
});

async function handleIocList(req, res) {
  const timingEnabled = IOC_LIST_TIMING || req.query.timing === '1';
  const t = timingEnabled ? { requestReceived: Date.now() } : null;

  const { source_name, confidence, q, asn, country, page = '1', page_size = '5' } = req.query;
  const allowedSizes = [5, 10, 25, 100];
  const size = Number(page_size);
  const currentPage = Math.max(Number(page) || 1, 1);
  const limit = allowedSizes.includes(size) ? size : 5;
  const offset = (currentPage - 1) * limit;

  const filters = [];
  const params = [];
  let prefixedHashSearch = null;
  let prefixedObservableSearch = null;

  if (source_name) {
    params.push(`%${source_name}%`);
    filters.push(`source_name ILIKE $${params.length}`);
  }

  if (confidence) {
    params.push(confidence);
    filters.push(`confidence = $${params.length}`);
  }

  if (q) {
    const qv = String(q).trim();
    if (qv.length < 3) {
      return res.json({
        items: [],
        pagination: { page: currentPage, page_size: limit, total: 0, total_pages: 1 },
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
          pagination: { page: currentPage, page_size: limit, total: 0, total_pages: 1 },
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
      const prefixedObs = qv.match(/^(ip|ip6|domain|url)\s*:\s*(.+)$/i);
      if (prefixedObs) {
        const obsType = prefixedObs[1].toLowerCase();
        let obsValue = String(prefixedObs[2] || '').trim();
        if (obsType === 'domain' || obsType === 'url') obsValue = obsValue.toLowerCase();
        if (obsValue.length < 2) {
          return res.json({
            items: [],
            pagination: { page: currentPage, page_size: limit, total: 0, total_pages: 1 },
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
  // Filtre varken 20M+ satırda full scan önlemek: sadece son N gün (varsayılan 365)
  const maxAgeDays = Math.min(Math.max(Number(process.env.IOC_LIST_MAX_AGE_DAYS || 365) || 365, 30), 3650);
  const recentClause = fullScan ? ` WHERE created_at > now() - interval '1 day' * $${params.length + 1}` : '';
  const recentParam = fullScan ? maxAgeDays : null;

  if (t) t.searchStringParse = Date.now();

  const asnValueEarly = asn ? Number(asn) : null;
  const countryValueEarly = country ? `%${country}%` : null;
  const useHashFastPathEarly = prefixedHashSearch && asnValueEarly == null && countryValueEarly == null;
  const useObservableOnlyPath = prefixedObservableSearch && asnValueEarly == null && countryValueEarly == null;

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
      const obsQ = `
        SELECT i.id, i.public_id, i.observable, i.observable_type, i.source_name, i.source_url, i.confidence, i.category, i.note, i.created_at
        FROM ioc_observables o
        JOIN ioc_items i ON i.public_id = o.ioc_public_id
        WHERE o.observable_value = $1
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
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.first_seen_at) g.first_seen_at = r.created_at;
          if (r.created_at > g.last_seen_at) g.last_seen_at = r.created_at;
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
        const payload = { items: pageItems, pagination: { page: 1, page_size: limit, total: pageItems.length, total_pages: 1 } };
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
      const exactHashQ = `
        SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at
        FROM ioc_file_hash
        WHERE observable = $1 OR (${noteExpr}) = $1
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
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.first_seen_at) g.first_seen_at = r.created_at;
          if (r.created_at > g.last_seen_at) g.last_seen_at = r.created_at;
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
      const payload = { items: pageItems, pagination: { page: 1, page_size: limit, total: totalExact, total_pages: totalExact ? 1 : 0 } };
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
      const partitionTable = { ip: 'ioc_ip', ip6: 'ioc_ip6', domain: 'ioc_domain', url: 'ioc_url' }[obsType];
      const whereClause = (obsType === 'domain' || obsType === 'url') ? 'LOWER(observable) = $1' : 'observable = $1';
      const obsLimit = Math.max(Math.min(limit * 50, 500), 100);
      const obsQ = `
        SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at
        FROM ${partitionTable}
        WHERE ${whereClause}
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
              _sources: new Set(),
              _conf: new Set(),
              _cat: new Set()
            });
          }
          const g = grouped.get(key);
          if (r.created_at < g.first_seen_at) g.first_seen_at = r.created_at;
          if (r.created_at > g.last_seen_at) g.last_seen_at = r.created_at;
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
      const payload = { items: pageItems, pagination: { page: 1, page_size: limit, total: pageItems.length, total_pages: pageItems.length ? 1 : 0 } };
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
      ? `SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at
         FROM ioc_items
         WHERE (
           (observable_type = '${hashTypeLiteral}' AND LOWER(observable) = $1)
           OR (${prefixedHashSearch.noteExpr} = $1)
         )`
      : prefixedHashSearch
      ? `SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at
         FROM ioc_items
         WHERE (
           (observable_type = $${prefixedHashSearch.typeIdx} AND LOWER(observable) = $${prefixedHashSearch.exactIdx})
           OR (${prefixedHashSearch.noteExpr} = $${prefixedHashSearch.exactIdx})
         )`
      : fullScan
        ? `SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at FROM ioc_items${recentClause}`
        : `SELECT id, public_id, observable, observable_type, source_name, confidence, category, note, created_at
           FROM ioc_items
           ORDER BY created_at DESC
           LIMIT 2000`;

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
          COUNT(*)::int AS source_count,
          ARRAY_AGG(DISTINCT source_name ORDER BY source_name) AS source_names,
          ARRAY_AGG(DISTINCT confidence ORDER BY confidence) AS confidence_set,
          ARRAY_AGG(DISTINCT COALESCE(category, '') ORDER BY COALESCE(category, '')) FILTER (WHERE category IS NOT NULL AND category <> '') AS category_set
        FROM filtered
        GROUP BY observable, observable_type
      )
    `;

    const asnValue = asn ? Number(asn) : null;
    const countryValue = country ? `%${country}%` : null;
    const numBase = params.length + (fullScan ? 1 : 0);
    const geoJoin = `LEFT JOIN ioc_ip_geo_cache c ON c.ip = CASE WHEN g.observable_type = 'ip' THEN g.observable::inet ELSE NULL END`;
    const geoWhere = `($${numBase + 1}::int IS NULL OR c.asn = $${numBase + 1}) AND ($${numBase + 2}::text IS NULL OR c.country_code ILIKE $${numBase + 2})`;

    // Fast path: prefixed hash (sha256:/md5:/sha1:) with no asn/country filter → skip geo join (hash results are not IPs).
    const useHashFastPath = prefixedHashSearch && asnValue == null && countryValue == null;
    const hashLiteralParams = useHashFastPath && hashTypeLiteral ? [params[prefixedHashSearch.exactIdx - 1]] : null;
    const listQ = useHashFastPath
      ? `
      ${base}
      SELECT g.id, g.public_id, g.observable, g.observable_type, g.observable AS ip, g.first_seen_at, g.last_seen_at, g.source_count,
             g.source_names, g.confidence_set, g.category_set,
             NULL::bigint AS asn, NULL::text AS country_code, NULL::text AS as_name,
             COUNT(*) OVER()::int AS total
      FROM grouped g
      ORDER BY g.last_seen_at DESC
      LIMIT $${hashLiteralParams ? 2 : params.length + 1}
      OFFSET $${hashLiteralParams ? 3 : params.length + 2}
    `
      : `
      ${base}
      , with_geo AS (
        SELECT g.*, g.observable AS ip, c.asn, c.country_code, c.as_name,
               COUNT(*) OVER()::int AS total
        FROM grouped g
        ${geoJoin}
        WHERE ${geoWhere}
      )
      SELECT id, public_id, observable, observable_type, ip, first_seen_at, last_seen_at, source_count,
             source_names, confidence_set, category_set, asn, country_code, as_name, total
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
        ? `${base} SELECT COUNT(*)::int AS total FROM grouped g`
        : `
        ${base}
        SELECT COUNT(*)::int AS total
        FROM grouped g
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
    const items = listRes.rows.map(({ total: _drop, ...row }) => row);
    if (t) t.afterResultMapping = Date.now();
    if (t) t.beforeJsonSerialize = Date.now();

    const payload = {
      items,
      pagination: {
        page: currentPage,
        page_size: limit,
        total,
        total_pages: Math.max(Math.ceil(total / limit), 1)
      }
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

/** Hot IOC list: `last_seen_since` = ISO 8601 or relative `24h`, `7d`, `1h`, `30m`, `60s`. */
function parseLastSeenSinceParam(raw) {
  if (raw == null) return { ok: true, since: null };
  const s = String(raw).trim();
  if (!s) return { ok: true, since: null };
  const rel = /^(\d+)\s*(s|m|h|d)$/i.exec(s);
  if (rel) {
    const n = Math.min(Math.max(parseInt(rel[1], 10) || 0, 1), 100000);
    const u = rel[2].toLowerCase();
    let ms;
    if (u === 's') ms = n * 1000;
    else if (u === 'm') ms = n * 60 * 1000;
    else if (u === 'h') ms = n * 3600 * 1000;
    else ms = n * 86400 * 1000;
    return { ok: true, since: new Date(Date.now() - ms) };
  }
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return { ok: true, since: d };
  return { ok: false, error: 'Use ISO 8601 timestamp or a relative window like 24h, 7d, 1h, 30m, 60s.' };
}

app.get('/api/ioc/hot', async (req, res) => {
  const page = Math.max(parseInt(String(req.query.page || '1'), 10) || 1, 1);
  let limit = parseInt(String(req.query.limit ?? req.query.page_size ?? '50'), 10);
  if (!Number.isFinite(limit) || limit < 1) limit = 50;
  limit = Math.min(limit, 200);
  const offset = (page - 1) * limit;

  const typeRaw = String(req.query.type || '').trim().toLowerCase();
  const qRaw = String(req.query.q || '').trim();
  const params = [];
  let extraWhere = '';

  if (typeRaw === 'ip') {
    extraWhere += ` AND observable_type IN ('ip', 'ip6') `;
  } else if (typeRaw === 'domain') {
    extraWhere += ` AND observable_type = 'domain' `;
  } else if (typeRaw === 'hash') {
    extraWhere += ` AND observable_type IN ('md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh') `;
  } else if (typeRaw) {
    return res.status(400).json({
      message: 'Invalid query parameter: type',
      detail: 'Allowed values: ip, domain, hash.'
    });
  }

  const sinceParsed = parseLastSeenSinceParam(req.query.last_seen_since);
  if (!sinceParsed.ok) {
    return res.status(400).json({
      message: 'Invalid query parameter: last_seen_since',
      detail: sinceParsed.error
    });
  }
  if (sinceParsed.since) {
    params.push(sinceParsed.since.toISOString());
    extraWhere += ` AND last_seen_log >= $${params.length}::timestamptz `;
  }

  if (qRaw) {
    params.push(`%${qRaw}%`);
    extraWhere += ` AND (observable ILIKE $${params.length} OR public_id::text ILIKE $${params.length}) `;
  }

  const baseWhere = `match_count > 0${extraWhere}`;

  try {
    const countQ = `
      SELECT COUNT(*)::bigint AS cnt
      FROM (
        SELECT observable, observable_type
        FROM ioc_items
        WHERE ${baseWhere}
        GROUP BY observable, observable_type
      ) g
    `;
    const { rows: countRows } = await pool.query(countQ, params);
    const total = Number(countRows[0]?.cnt || 0);
    const totalPages = total === 0 ? 1 : Math.max(Math.ceil(total / limit), 1);

    const listParams = [...params, limit, offset];
    const limIdx = params.length + 1;
    const offIdx = params.length + 2;

    const listQ = `
      WITH grouped AS (
        SELECT
          MIN(id) AS id,
          MIN(public_id::text) AS public_id,
          observable,
          observable_type,
          COUNT(DISTINCT source_name)::bigint AS source_count,
          MIN(first_seen_log) AS first_seen_log,
          MAX(last_seen_log) AS last_seen_log,
          MAX(match_count) AS sort_match_count
        FROM ioc_items
        WHERE ${baseWhere}
        GROUP BY observable, observable_type
        ORDER BY MAX(last_seen_log) DESC NULLS LAST, MAX(match_count) DESC, observable ASC
        LIMIT $${limIdx} OFFSET $${offIdx}
      )
      SELECT
        g.id,
        g.public_id,
        g.observable,
        g.observable_type,
        ev.evidence_logs,
        g.source_count,
        g.first_seen_log,
        g.last_seen_log
      FROM grouped g
      LEFT JOIN LATERAL (
        SELECT NULLIF(COUNT(DISTINCT rl.evidence_hash)::bigint, 0) AS evidence_logs
        FROM ioc_activity a
        JOIN ioc_match_event_related_logs rl ON rl.activity_id = a.id
        WHERE lower(a.ioc_value) = lower(g.observable)
          AND lower(COALESCE(a.ioc_type, '')) = lower(COALESCE(g.observable_type, a.ioc_type, ''))
      ) ev ON TRUE
      ORDER BY g.last_seen_log DESC NULLS LAST, g.sort_match_count DESC, g.observable ASC
    `;

    const { rows: baseItems } = await pool.query(listQ, listParams);

    let items = baseItems;
    try {
      const pairs = (baseItems || [])
        .map((r) => ({ o: String(r?.observable || '').trim().toLowerCase(), t: String(r?.observable_type || '').trim().toLowerCase() }))
        .filter((x) => x.o && x.t);
      if (pairs.length) {
        const tupleIn = pairs
          .map((p) => `('${escapeChString(p.o)}','${escapeChString(p.t)}')`)
          .join(', ');
        const chRows = await clickhouseQuery(`
          SELECT
            lower(matched_ioc) AS observable,
            lower(observable_type) AS observable_type,
            countDistinct(evidence_hash) AS c
          FROM security_evidence.incident_related_logs
          WHERE (lower(matched_ioc), lower(observable_type)) IN (${tupleIn})
          GROUP BY observable, observable_type
        `);
        const chMap = new Map((chRows || []).map((r) => [`${String(r.observable)}|${String(r.observable_type)}`, Number(r.c || 0)]));
        items = (baseItems || []).map((it) => {
          const key = `${String(it?.observable || '').toLowerCase()}|${String(it?.observable_type || '').toLowerCase()}`;
          const ev = chMap.get(key);
          return { ...it, evidence_logs: Number.isFinite(ev) && ev > 0 ? ev : null };
        });
      }
    } catch {
      items = (baseItems || []).map((it) => ({ ...it, evidence_logs: null }));
    }

    const statsQ = `
      WITH grouped AS (
        SELECT observable, observable_type
        FROM ioc_items
        WHERE ${baseWhere}
        GROUP BY observable, observable_type
      )
      SELECT
        COUNT(*)::bigint AS total,
        COUNT(*) FILTER (WHERE observable_type = 'ip')::bigint AS ip,
        COUNT(*) FILTER (WHERE observable_type = 'url')::bigint AS url,
        COUNT(*) FILTER (WHERE observable_type = 'domain')::bigint AS domain,
        COUNT(*) FILTER (WHERE observable_type = 'ip6')::bigint AS ip6,
        COUNT(*) FILTER (WHERE observable_type IN ('md5','sha1','sha256','ssdeep','imphash','tlsh'))::bigint AS hash
      FROM grouped
    `;
    const { rows: statsRows } = await pool.query(statsQ, params);
    const s = statsRows[0] || {};

    const topSourcesQ = `
      SELECT source_name, COUNT(DISTINCT (observable, observable_type))::bigint AS count
      FROM ioc_items
      WHERE ${baseWhere}
      GROUP BY source_name
      ORDER BY count DESC, source_name ASC
      LIMIT 5
    `;
    const { rows: topSources } = await pool.query(topSourcesQ, params);

    return res.json({
      items,
      summary: {
        total: Number(s.total || 0),
        by_type: [
          { observable_type: 'ip', count: Number(s.ip || 0) },
          { observable_type: 'url', count: Number(s.url || 0) },
          { observable_type: 'domain', count: Number(s.domain || 0) },
          { observable_type: 'ip6', count: Number(s.ip6 || 0) },
          { observable_type: 'hash', count: Number(s.hash || 0) }
        ],
        by_source: topSources.map((r) => ({ source_name: r.source_name, count: Number(r.count || 0) }))
      },
      pagination: {
        page,
        page_size: limit,
        total,
        total_pages: totalPages
      }
    });
  } catch (err) {
    return res.status(500).json({ message: 'Failed to fetch hot IOC list', detail: err.message });
  }
});

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

    const detailsQ = `
      SELECT
        MIN(id)::int AS id,
        observable,
        observable_type,
        source_name,
        MIN(source_url) AS source_url,
        MIN(confidence) AS confidence,
        MIN(category) AS category,
        STRING_AGG(DISTINCT note, ' | ') FILTER (WHERE note IS NOT NULL AND note <> '') AS note,
        MAX(created_at) AS created_at,
        COUNT(*)::int AS total_rows
      FROM ioc_items
      WHERE observable = $1
      ${typeFilter}
      GROUP BY observable, observable_type, source_name
      ORDER BY created_at DESC
    `;
    const { rows } = await pool.query(detailsQ, params);
    return res.json({ observable, observable_type: observableType || null, sources: rows });
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


const IOC_DETAILS_CACHE_TTL_MS = Math.max(Number(process.env.IOC_DETAILS_CACHE_TTL_MS || 15000), 1000);
const iocDetailsCache = new Map();
let signalEventsTableCache = { value: null, checkedAt: 0 };

async function hasSignalEventsTable() {
  const now = Date.now();
  if (signalEventsTableCache.value != null && (now - signalEventsTableCache.checkedAt) < 60000) {
    return signalEventsTableCache.value;
  }
  try {
    const r = await pool.query(`SELECT to_regclass('public.signal_events') AS rel`);
    signalEventsTableCache = { value: Boolean(r.rows?.[0]?.rel), checkedAt: now };
    return signalEventsTableCache.value;
  } catch {
    signalEventsTableCache = { value: false, checkedAt: now };
    return false;
  }
}

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
        i.category,
        i.note,
        i.match_count,
        i.first_seen_log,
        i.last_seen_log,
        i.created_at
      FROM ioc_items i
      INNER JOIN seed s
        ON i.observable = s.observable
       AND (s.observable_type IS NULL OR i.observable_type = s.observable_type)
      ORDER BY i.created_at DESC
      LIMIT 500
    `;

    const tItem = Date.now();
    const itemRes = await pool.query(itemQ, [requestedPublicId]);
    pgMs += Date.now() - tItem;

    const rows = itemRes.rows;
    if (!rows.length) {
      const payload = { summary: null, sources: [], matches: [], incidents: [] };
      iocDetailsCache.set(requestedPublicId, { expiresAt: Date.now() + IOC_DETAILS_CACHE_TTL_MS, payload });
      console.log(`[perf][ioc-details] public_id=${requestedPublicId} cache=miss total_ms=${Date.now() - startedAt} pg_ms=${pgMs} ch_ms=${chMs} rows=0 matches=0`);
      return res.json(payload);
    }

    const observable = rows[0].observable;
    const observableType = rows[0].observable_type;

    const computedMatchCount = rows.reduce((max, r) => Math.max(max, Number(r.match_count || 0)), 0);
    const firstSeenLog = rows
      .map((r) => r.first_seen_log)
      .filter(Boolean)
      .sort()[0] || null;
    const lastSeenLog = rows
      .map((r) => r.last_seen_log)
      .filter(Boolean)
      .sort()
      .slice(-1)[0] || null;

    const signalEventsExists = await hasSignalEventsTable();
    const signalRawExpr = signalEventsExists
      ? `(
          SELECT se.raw_event
          FROM signal_events se
          WHERE se.id = m.signal_event_id
          LIMIT 1
        )`
      : 'NULL';

    const geoIp = extractIpv4ForGeo(observable, observableType);

    const geoPromise = (async () => {
      if (!geoIp) return { ip: null, asn: null, country_code: null, as_name: null };
      const geoQ = `
        WITH ip_input AS (
          SELECT
            $1::inet AS ip,
            ((split_part(host($1::inet), '.', 1)::bigint << 24)
            + (split_part(host($1::inet), '.', 2)::bigint << 16)
            + (split_part(host($1::inet), '.', 3)::bigint << 8)
            +  split_part(host($1::inet), '.', 4)::bigint) AS ip_num
        )
        SELECT
          i.ip::text AS ip,
          COALESCE(c.asn, r.asn) AS asn,
          COALESCE(c.country_code, r.country_code) AS country_code,
          COALESCE(c.as_name, r.as_name) AS as_name
        FROM ip_input i
        LEFT JOIN ioc_ip_geo_cache c ON c.ip = i.ip
        LEFT JOIN LATERAL (
          SELECT r.asn, COALESCE(o.country_code, r.country) AS country_code, r.asn_owner AS as_name
          FROM asn_lookup r
          LEFT JOIN asn_country_overrides o ON o.asn = r.asn
          WHERE i.ip_num BETWEEN r.start_ip_int AND r.end_ip_int
          ORDER BY (r.end_ip_int - r.start_ip_int) ASC
          LIMIT 1
        ) r ON TRUE
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

    const incidentsPromise = (async () => {
      const incidentsQ = `
        SELECT
          a.id,
          a.incident_id,
          a.first_seen,
          a.last_seen,
          COALESCE(stats.detection_events, 0)::int AS detection_events,
          rel.evidence_logs AS evidence_logs,
          COALESCE(stats.observed_hosts, 0)::int AS observed_hosts,
          a.verdict,
          a.status,
          NULL::double precision AS risk_score
        FROM ioc_activity a
        LEFT JOIN LATERAL (
          SELECT
            COUNT(*)::int AS detection_events,
            COUNT(DISTINCT NULLIF(m.host_name, ''))::int AS observed_hosts
          FROM ioc_match_events m
          WHERE m.activity_id = a.id
        ) stats ON TRUE
        LEFT JOIN LATERAL (
          SELECT NULLIF(COUNT(*)::bigint, 0) AS evidence_logs
          FROM ioc_match_event_related_logs rl
          WHERE rl.activity_id = a.id
        ) rel ON TRUE
        WHERE lower(a.ioc_value) = lower($1)
          AND lower(COALESCE(a.ioc_type, '')) = lower(COALESCE($2, a.ioc_type, ''))
        ORDER BY a.last_seen DESC NULLS LAST, a.incident_id DESC
        LIMIT 20
      `;
      const tInc = Date.now();
      const incidentsRes = await pool.query(incidentsQ, [observable, observableType]);
      pgMs += Date.now() - tInc;
      return incidentsRes.rows || [];
    })();

    const [geo, incidentsRaw] = await Promise.all([geoPromise, incidentsPromise]);

    let incidents = incidentsRaw;
    try {
      const activityIds = (incidentsRaw || []).map((x) => String(x?.id || '').trim()).filter(Boolean);
      if (activityIds.length) {
        const inList = activityIds.map((id) => `toUUID('${escapeChString(id)}')`).join(', ');
        const chRows = await clickhouseQuery(`
          SELECT activity_id, countDistinct(evidence_hash) AS c
          FROM security_evidence.incident_related_logs
          WHERE activity_id IN (${inList})
          GROUP BY activity_id
        `);
        const chMap = new Map((chRows || []).map((r) => [String(r.activity_id || '').toLowerCase(), Number(r.c || 0)]));
        incidents = (incidentsRaw || []).map((it) => {
          const k = String(it?.id || '').toLowerCase();
          const chCount = chMap.get(k);
          return {
            ...it,
            evidence_logs: Number.isFinite(chCount) && chCount > 0 ? chCount : (it?.evidence_logs ?? null)
          };
        });
      }
    } catch {
      incidents = incidentsRaw;
    }

    const totalEvidenceLogsCount = (incidents || []).reduce((acc, it) => {
      const n = Number(it?.evidence_logs);
      return acc + (Number.isFinite(n) && n > 0 ? n : 0);
    }, 0);

    const summary = {
      id: rows[0].id,
      public_id: rows[0].public_id,
      observable,
      observable_type: rows[0].observable_type,
      first_seen_at: rows[rows.length - 1]?.created_at || null,
      last_seen_at: rows[0]?.created_at || null,
      match_count: computedMatchCount,
      evidence_logs_count: totalEvidenceLogsCount,
      first_seen_log: firstSeenLog,
      last_seen_log: lastSeenLog,
      source_count: new Set(rows.map((r) => r.source_name)).size,
      confidence_set: [...new Set(rows.map((r) => r.confidence).filter(Boolean))],
      category_set: [...new Set(rows.map((r) => r.category).filter(Boolean))],
      geo,
      file_information: buildFileInformation(rows, observable, rows[0].observable_type)
    };

    const payload = {
      summary,
      match_count: Number(summary.match_count || 0),
      sources: rows,
      matches: [],
      incidents
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
        i.confidence,
        i.category,
        i.created_at,
        c.asn,
        c.country_code,
        c.as_name
      FROM ioc_items i
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
    const now = Date.now();
    // Index-friendly: uses idx on created_at (DESC) instead of full-table MAX() aggregate.
    const lastUpdateQ = await pool.query("SELECT created_at AS last_update FROM ioc_items ORDER BY created_at DESC LIMIT 1");
    const lastUpdate = lastUpdateQ.rows[0]?.last_update || null;
    const cacheKey = `ioc_stats_${lastUpdate ?? 'null'}`;

    if (
      iocStatsCache.data &&
      iocStatsCache.key === cacheKey &&
      now - iocStatsCache.createdAt < IOC_STATS_TTL_MS
    ) {
      return res.json(iocStatsCache.data);
    }

    const base = `
      WITH filtered AS (
        SELECT observable, observable_type, source_name, confidence
        FROM ioc_items
      )
    `;

    const totalQ = `${base} SELECT COUNT(*)::bigint AS count FROM filtered`;
    const uniqueIpsQ = `${base} SELECT COUNT(DISTINCT observable)::bigint AS count FROM filtered WHERE observable_type = 'ip'`;
    const bySourceQ = `${base}
      SELECT source_name, COUNT(*)::bigint AS count
      FROM filtered
      GROUP BY source_name
      ORDER BY count DESC`;
    const byConfidenceQ = `${base}
      SELECT confidence, COUNT(*)::bigint AS count
      FROM filtered
      GROUP BY confidence
      ORDER BY count DESC`;
    const byTypeQ = `${base}
      SELECT observable_type, COUNT(*)::bigint AS count
      FROM filtered
      GROUP BY observable_type
      ORDER BY count DESC`;

    const [total, uniqueIps, bySource, byConfidence, byType] = await Promise.all([
      pool.query(totalQ),
      pool.query(uniqueIpsQ),
      pool.query(bySourceQ),
      pool.query(byConfidenceQ),
      pool.query(byTypeQ)
    ]);

    const payload = {
      last_update: lastUpdate,
      total: Number(total.rows[0]?.count || 0),
      unique_ips: Number(uniqueIps.rows[0]?.count || 0),
      by_source: bySource.rows,
      by_confidence: byConfidence.rows,
      by_type: byType.rows
    };

    iocStatsCache = {
      key: cacheKey,
      data: payload,
      createdAt: now,
      lastUpdate
    };

    return res.json(payload);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch summary', detail: err.message });
  }
});

app.get('/api/ioc/stats', async (_req, res) => {
  // Same cache as summary/today; return a smaller payload for IOC list page.
  try {
    const now = Date.now();
    // Index-friendly: uses idx on created_at (DESC) instead of full-table MAX() aggregate.
    const lastUpdateQ = await pool.query("SELECT created_at AS last_update FROM ioc_items ORDER BY created_at DESC LIMIT 1");
    const lastUpdate = lastUpdateQ.rows[0]?.last_update || null;
    const cacheKey = `ioc_stats_${lastUpdate ?? 'null'}`;

    if (
      iocStatsCache.data &&
      iocStatsCache.key === cacheKey &&
      now - iocStatsCache.createdAt < IOC_STATS_TTL_MS
    ) {
      const cached = iocStatsCache.data;
      return res.json({
        last_update: cached.last_update ?? lastUpdate,
        total: cached.total ?? 0,
        by_type: cached.by_type ?? [],
        by_source: cached.by_source ?? []
      });
    }

    const [totalQ, byTypeQ, topSourcesQ] = await Promise.all([
      pool.query('SELECT COUNT(*)::bigint AS count FROM ioc_items'),
      pool.query(`
        SELECT observable_type, COUNT(*)::bigint AS count
        FROM ioc_items
        GROUP BY observable_type
        ORDER BY count DESC
      `),
      pool.query(`
        SELECT source_name, COUNT(*)::bigint AS count
        FROM ioc_items
        GROUP BY source_name
        ORDER BY count DESC
        LIMIT 20
      `)
    ]);

    const payload = {
      last_update: lastUpdate,
      total: Number(totalQ.rows[0]?.count || 0),
      by_type: byTypeQ.rows,
      by_source: topSourcesQ.rows
    };

    iocStatsCache = {
      key: cacheKey,
      // Keep a superset shape so summary/today can use it if called later.
      data: { ...payload, unique_ips: 0, by_confidence: [] },
      createdAt: now,
      lastUpdate
    };

    return res.json(payload);
  } catch (err) {
    console.error('[ioc/stats] failed', err);
    return res.status(500).json({ message: 'Failed to fetch IOC stats', detail: err.message });
  }
});

if (USE_CLICKHOUSE) {
  ensureSyslogTable()
    .then(() => pingClickhouse())
    .then(() => console.log('[clickhouse] ready'))
    .catch((err) => console.error('[clickhouse] init failed', err));
}

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

const RISK_SNAPSHOT_INTERVAL_MS = Math.max(Number(process.env.RISK_SNAPSHOT_INTERVAL_MS || 5 * 60 * 1000), 60 * 1000);
const PUBLISHED_FEED_TICK_MS = Math.max(Number(process.env.PUBLISHED_FEED_TICK_MS || 60 * 1000), 15 * 1000);
let riskSnapshotInProgress = false;
let publishedFeedTickInProgress = false;

async function saveRiskSnapshot() {
  if (riskSnapshotInProgress) return;
  riskSnapshotInProgress = true;
  try {
    const overview = await computeInstitutionRiskOverview();
    await pool.query(
      `INSERT INTO risk_snapshots (ts, institution_risk)
       VALUES (NOW(), $1)`,
      [Number(overview?.institution_risk_score || 0)]
    );
  } catch (err) {
    console.error('[risk-snapshot] failed', err);
  } finally {
    riskSnapshotInProgress = false;
  }
}

app.listen(port, async () => {
  console.log(`Backend listening on :${port}`);
  if (IOC_LIST_TIMING) {
    console.log('[ioc/list] IOC_LIST_TIMING=1: timing logs enabled (searchStringParse, dbQuery, responseSent, etc.). Use ?timing=1 per request if env not set.');
  }
  await ensureSeedDemoUser();
  saveRiskSnapshot().catch(() => {});
  setInterval(() => {
    saveRiskSnapshot().catch(() => {});
  }, RISK_SNAPSHOT_INTERVAL_MS);
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
