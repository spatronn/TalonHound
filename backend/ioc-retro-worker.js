import './lib/ensure-db-password.js';
import pg from 'pg';
import { createHash } from 'node:crypto';
import { ensureIocCorrelationAssets, syncIocLookupFromPostgres, query as clickhouseQuery, command as clickhouseCommand } from './lib/clickhouse.js';
import { findOrCreateActivity } from './lib/ioc-activity.js';
import { createSuppressionStats, fetchActiveSuppressionIndex, filterSuppressedPairs } from './lib/ioc-suppression.js';
import { buildRelatedEvidenceRow, insertIncidentRelatedLogEvidenceSafe } from './lib/relatedLogsEvidence.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const RETRO_SCAN_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_RETRO_SCAN_INTERVAL_SECONDS || 3600), 30);
const RETRO_LOOKBACK_DAYS = Math.max(Number(process.env.IOC_RETRO_LOOKBACK_DAYS || 30), 1);
const RETRO_MATCH_PAGE_SIZE = Math.max(Number(process.env.IOC_RETRO_BATCH_SIZE || 5000), 500);
const RETRO_IOC_CHUNK_SIZE = Math.max(Number(process.env.IOC_RETRO_IOC_CHUNK_SIZE || 1000), 100);
const IOC_LOOKUP_SYNC_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_LOOKUP_SYNC_INTERVAL_SECONDS || 300), 60);
const IOC_LOOKUP_SYNC_ENABLED = process.env.IOC_LOOKUP_SYNC_ENABLED === '1' || process.env.IOC_LOOKUP_SYNC_ENABLED === 'true';

const DEDUP_WINDOW_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_DEDUP_WINDOW_SECONDS || 300), 60);
const RETRO_CH_MAX_THREADS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_THREADS || 1), 1);
const RETRO_CH_MAX_EXECUTION_TIME_SECONDS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_EXECUTION_TIME_SECONDS || 25), 5);

const RETRO_BACKLOG_FAST_POLL_MS = Math.max(Number(process.env.IOC_RETRO_BACKLOG_FAST_POLL_MS || 15000), 3000);
const RETRO_BACKLOG_MEDIUM_POLL_MS = Math.max(Number(process.env.IOC_RETRO_BACKLOG_MEDIUM_POLL_MS || 60000), 5000);
const RETRO_BACKLOG_THRESHOLD_HIGH = Math.max(Number(process.env.IOC_RETRO_BACKLOG_THRESHOLD_HIGH || 10000), 100);
const RETRO_BACKLOG_THRESHOLD_MEDIUM = Math.max(Number(process.env.IOC_RETRO_BACKLOG_THRESHOLD_MEDIUM || 500), 10);
const RETRO_SLOW_TICK_THRESHOLD_MS = Math.max(Number(process.env.IOC_RETRO_SLOW_TICK_THRESHOLD_MS || 4000), 1000);
const RETRO_ALIGN_MINUTE = Math.min(Math.max(Number(process.env.IOC_RETRO_ALIGN_MINUTE || 10), 0), 59);
const RETRO_ALIGN_ENABLED = process.env.IOC_RETRO_ALIGN_ENABLED === '0' ? false : true;
const IOC_RETRO_POLL_INTERVAL_MS = Math.max(Number(process.env.IOC_RETRO_POLL_INTERVAL_MS || 120000), 5000);

const CURSOR_TS_START = '1970-01-01 00:00:00.000';
const CURSOR_HASH_START = '0';
const MATCH_CURSOR_TS_START = '1970-01-01 00:00:00';
const MATCH_CURSOR_RAW_START = '';

let stopping = false;
let lastIocLookupSyncAtMs = 0;

const workerStatus = {
  backlogSize: 0,
  lastRunDurationMs: 0,
  lastBatchSize: 0,
  mode: 'idle',
  loops: 0,
  chunkIocCount: 0,
  chunkRowsProcessed: 0
};

function makeQueryId(name) {
  return `ioc-retro:${name}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getIdleSleepMs() {
  if (!RETRO_ALIGN_ENABLED) return RETRO_SCAN_INTERVAL_SECONDS * 1000;

  const now = new Date();
  const next = new Date(now);
  next.setUTCSeconds(0, 0);
  next.setUTCMinutes(RETRO_ALIGN_MINUTE);
  if (next <= now) next.setUTCHours(next.getUTCHours() + 1);
  return Math.max(next.getTime() - now.getTime(), 1000);
}

function getIdleProbeSleepMs() {
  return Math.max(Math.min(getIdleSleepMs(), IOC_RETRO_POLL_INTERVAL_MS), 1000);
}

function safeTs(ts) {
  return String(ts || CURSOR_TS_START).replace('T', ' ').replace('Z', '');
}

function safeHash(hash) {
  return String(hash || CURSOR_HASH_START).replace(/[^0-9]/g, '') || CURSOR_HASH_START;
}

function safeDateTime(ts) {
  const s = String(ts || MATCH_CURSOR_TS_START).replace('T', ' ').replace('Z', '');
  const noMs = s.includes('.') ? s.slice(0, s.indexOf('.')) : s;
  if (noMs.length >= 19) return noMs.slice(0, 19);
  if (noMs.length === 10) return `${noMs} 00:00:00`;
  return MATCH_CURSOR_TS_START;
}

function chLiteral(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/'/g, "''");
}

function floorToBucket(tsIso, seconds) {
  const d = new Date(tsIso);
  const ms = d.getTime();
  const bucketMs = seconds * 1000;
  const floored = Math.floor(ms / bucketMs) * bucketMs;
  return new Date(floored).toISOString();
}

function dedupKeyOf(row) {
  return [
    row.match_type || 'unknown',
    row.matched_ioc || '',
    row.host || '',
    row.source || '',
    row.parser_source || 'unknown'
  ].join('|');
}

function idleMatchDefaults() {
  return {
    match_cursor_ts: MATCH_CURSOR_TS_START,
    match_cursor_raw_hash: MATCH_CURSOR_RAW_START,
    match_cursor_observable: '',
    match_cursor_observable_type: '',
    match_cursor_source_name: '',
    chunk_active: 0,
    chunk_end_ts: CURSOR_TS_START,
    chunk_end_row_hash: CURSOR_HASH_START,
    chunk_ioc_count: 0,
    chunk_rows_processed: 0
  };
}

async function loadRetroState() {
  const rows = await clickhouseQuery(`
    SELECT
      last_processed_ts,
      last_processed_row_hash,
      last_run_duration_ms,
      chunk_active,
      chunk_end_ts,
      chunk_end_row_hash,
      chunk_ioc_count,
      chunk_rows_processed,
      match_cursor_ts,
      match_cursor_raw_hash,
      match_cursor_observable,
      match_cursor_observable_type,
      match_cursor_source_name
    FROM default.ioc_retro_state
    WHERE worker_name = 'ioc-retro-v1'
    ORDER BY updated_at DESC
    LIMIT 1
  `, { queryId: makeQueryId('retro-state-load'), logTag: 'ioc-retro.state-load' });

  const r = rows?.[0] || {};
  const idle = idleMatchDefaults();
  return {
    last_processed_ts: r.last_processed_ts || CURSOR_TS_START,
    last_processed_row_hash: r.last_processed_row_hash || CURSOR_HASH_START,
    last_run_duration_ms: Number(r.last_run_duration_ms || 0),
    chunk_active: Number(r.chunk_active || 0),
    chunk_end_ts: r.chunk_end_ts || idle.chunk_end_ts,
    chunk_end_row_hash: r.chunk_end_row_hash || idle.chunk_end_row_hash,
    chunk_ioc_count: Number(r.chunk_ioc_count || 0),
    chunk_rows_processed: Number(r.chunk_rows_processed || 0),
    match_cursor_ts: r.match_cursor_ts || idle.match_cursor_ts,
    match_cursor_raw_hash: r.match_cursor_raw_hash || idle.match_cursor_raw_hash,
    match_cursor_observable: r.match_cursor_observable || idle.match_cursor_observable,
    match_cursor_observable_type: r.match_cursor_observable_type || idle.match_cursor_observable_type,
    match_cursor_source_name: r.match_cursor_source_name || idle.match_cursor_source_name
  };
}

async function saveRetroState(state) {
  const s = { ...idleMatchDefaults(), ...state };
  await clickhouseCommand(`
    INSERT INTO default.ioc_retro_state (
      worker_name,
      last_processed_ts,
      last_processed_row_hash,
      last_run_duration_ms,
      chunk_active,
      chunk_end_ts,
      chunk_end_row_hash,
      chunk_ioc_count,
      chunk_rows_processed,
      match_cursor_ts,
      match_cursor_raw_hash,
      match_cursor_observable,
      match_cursor_observable_type,
      match_cursor_source_name,
      updated_at
    ) VALUES (
      'ioc-retro-v1',
      toDateTime64('${safeTs(s.last_processed_ts)}', 3),
      '${chLiteral(safeHash(s.last_processed_row_hash))}',
      toInt32(${Number(s.last_run_duration_ms || 0)}),
      toUInt8(${Number(s.chunk_active || 0)}),
      toDateTime64('${safeTs(s.chunk_end_ts)}', 3),
      '${chLiteral(safeHash(s.chunk_end_row_hash))}',
      toUInt32(${Number(s.chunk_ioc_count || 0)}),
      toUInt64(${Number(s.chunk_rows_processed || 0)}),
      toDateTime('${safeDateTime(s.match_cursor_ts)}'),
      '${chLiteral(String(s.match_cursor_raw_hash || ''))}',
      '${chLiteral(String(s.match_cursor_observable || ''))}',
      '${chLiteral(String(s.match_cursor_observable_type || ''))}',
      '${chLiteral(String(s.match_cursor_source_name || ''))}',
      now64(3)
    )
  `, { logTag: 'ioc-retro.state-save' });
}

async function insertMatchEvents(client, rows) {
  if (!rows.length) {
    return { inserted: 0, suppressed_count: 0, suppressed_by_global_count: 0, skipped_suppressed_iocs: 0 };
  }

  const pairSeen = new Set();
  const pairs = [];
  for (const r of rows) {
    const key = `${String(r.ioc_type || '').toLowerCase()}\t${String(r.matched_ioc || '').trim().toLowerCase()}`;
    if (!key || key === '\t' || pairSeen.has(key)) continue;
    pairSeen.add(key);
    pairs.push({ iocValue: r.matched_ioc, iocType: r.ioc_type, sourceName: r.source_name ?? null });
  }
  const suppressionIndex = await fetchActiveSuppressionIndex(client, pairs, { logTag: 'ioc-retro' });
  const { kept: allowedRows, stats: suppressionStats } = filterSuppressedPairs(
    suppressionIndex,
    rows,
    (r) => ({ iocValue: r.matched_ioc, iocType: r.ioc_type, sourceName: r.source_name ?? null })
  );
  if (!allowedRows.length) {
    return { inserted: 0, ...suppressionStats.toJSON() };
  }
  rows = allowedRows;

  const uniq = new Map();
  for (const r of rows) {
    const bucketStart = floorToBucket(r.event_time, DEDUP_WINDOW_SECONDS);
    const dedupKey = dedupKeyOf({ ...r, match_type: r.ioc_type });
    const key = `${dedupKey}@@${bucketStart}`;

    const prev = uniq.get(key);
    if (!prev) {
      uniq.set(key, { ...r, _bucketStart: bucketStart, _dedupKey: dedupKey, _hitInc: 1 });
      continue;
    }

    prev._hitInc += 1;
    if (String(r.event_time || '') > String(prev.event_time || '')) prev.event_time = r.event_time;
    if (!prev.source_name && r.source_name) prev.source_name = r.source_name;
    if (!prev.confidence && r.confidence) prev.confidence = r.confidence;
  }

  const deduped = Array.from(uniq.values());
  const values = [];
  const params = [];
  const activityCache = new Map();

  for (let i = 0; i < deduped.length; i += 1) {
    const r = deduped[i];
    const activity = await findOrCreateActivity(client, {
      iocValue: r.matched_ioc,
      iocType: r.ioc_type,
      eventTime: r.event_time,
      hitCount: r._hitInc,
      cache: activityCache
    });
    if (activity?.id) r.activity_id = activity.id;

    const base = i * 26;
    values.push(`($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6},$${base + 7},$${base + 8},$${base + 9},$${base + 10},$${base + 11},$${base + 12},$${base + 13},$${base + 14},$${base + 15},$${base + 16},$${base + 17},$${base + 18},$${base + 19},$${base + 20},$${base + 21},$${base + 22},$${base + 23},$${base + 24},$${base + 25},$${base + 26})`);
    params.push(
      r.event_time, r.host || null, null, r.destination_ip || null, null, r.protocol || null,
      r.matched_ioc, r.source_name || null, r.confidence || null, r.ioc_type, null,
      r.parser_source || null, r.source || null, JSON.stringify(r.match_context || {}),
      r._dedupKey, r._bucketStart, r.event_time, r._hitInc,
      r.detection_type || 'retroactive',
      r.match_source ?? null,
      activity?.id || null,
      r.normalized_event_json ? JSON.stringify(r.normalized_event_json) : null,
      r.raw_log_snapshot || null,
      r.raw_log_hash || null,
      r.syslog_log_id || null,
      r.source_type || null
    );
  }

  await client.query(
    `INSERT INTO ioc_match_events (
      event_time, host_name, process_name, destination_ip, destination_port, protocol,
      matched_ioc, source_name, confidence, ioc_type, ioc_item_id,
      parser_source, source, match_context, dedup_key, bucket_start, last_seen_at, hit_count,
      detection_type, match_source, activity_id,
      normalized_event_json, raw_log_snapshot, raw_log_hash, syslog_log_id, source_type
    ) VALUES ${values.join(',')}
    ON CONFLICT (dedup_key, bucket_start)
    DO UPDATE SET
      hit_count = ioc_match_events.hit_count + EXCLUDED.hit_count,
      last_seen_at = GREATEST(ioc_match_events.last_seen_at, EXCLUDED.last_seen_at),
      confidence = COALESCE(EXCLUDED.confidence, ioc_match_events.confidence),
      source_name = COALESCE(EXCLUDED.source_name, ioc_match_events.source_name),
      match_context = COALESCE(EXCLUDED.match_context, ioc_match_events.match_context),
      detection_type = CASE
        WHEN COALESCE(ioc_match_events.detection_type, 'realtime') = 'realtime' THEN ioc_match_events.detection_type
        ELSE COALESCE(EXCLUDED.detection_type, ioc_match_events.detection_type)
      END,
      match_source = COALESCE(EXCLUDED.match_source, ioc_match_events.match_source),
      activity_id = COALESCE(EXCLUDED.activity_id, ioc_match_events.activity_id)`,
    params
  );

  for (const r of deduped) {
    if (!r?.activity_id) continue;
    const row = buildRelatedEvidenceRow({
      activityId: r.activity_id,
      incidentId: r?.incident_id || 0,
      matchEventId: r?.id || 0,
      logTs: r.event_time || null,
      matchedIoc: r.matched_ioc,
      observableType: r.ioc_type,
      logHost: r.host || '',
      observedHost: r?.match_context?.src_ip || r?.match_context?.client_ip || '',
      parserSource: r.parser_source || '',
      sourceType: r.source_type || '',
      rawMessage: r.raw_log_snapshot || ''
    });
    await insertIncidentRelatedLogEvidenceSafe(row);
  }

  const withRaw = deduped.filter((r) => Boolean(r.raw_log_snapshot)).length;
  const withNorm = deduped.filter((r) => Boolean(r.normalized_event_json)).length;
  console.info(`[retro-event-create] inserted=${deduped.length} source_type_sample=${deduped[0]?.source_type || 'unknown'} has_raw_log_snapshot=${withRaw > 0} has_normalized_event_json=${withNorm > 0}`);
  return { inserted: deduped.length, ...suppressionStats.toJSON() };
}

function normalizeSourceType(event = {}) {
  const tokens = [event.parser_source, event.source, event.protocol, event?.match_context?.query_type]
    .map((v) => String(v || '').toLowerCase())
    .join(' ');
  if (/(proxy|url|http|webproxy|swg)/.test(tokens)) return 'proxy';
  if (/(^|\s)dns(\s|$)|resolver|query/.test(tokens)) return 'dns';
  if (/(waf|f5|asm|modsecurity|nginx-waf)/.test(tokens)) return 'waf';
  if (/(endpoint|edr|xdr|sysmon|process|file)/.test(tokens)) return 'endpoint';
  if (/(firewall|traffic|forti|palo|pan-os|checkpoint|netflow)/.test(tokens)) return 'firewall';
  return 'generic';
}

function mapRowToEvent(r) {
  const eventMs = r?.ts ? new Date(r.ts).getTime() : 0;
  const iocUpdatedMs = r?.ioc_updated_at ? new Date(r.ioc_updated_at).getTime() : 0;
  const iocWasPresentAtIngest = eventMs > 0 && iocUpdatedMs > 0 ? iocUpdatedMs <= eventMs : false;
  const rawLogSnapshot = r?.raw_log ? String(r.raw_log) : null;
  const matchContext = {
    retroactive: true,
    observable_source: 'syslog_observables',
    processing_path: 'retro-window',
    detection_type: 'retroactive',
    ioc_was_present_at_ingest: iocWasPresentAtIngest,
    ioc_updated_at: r.ioc_updated_at || null
  };
  const sourceType = normalizeSourceType({ parser_source: 'syslog_observables', source: r.source, protocol: 'dns', match_context: matchContext });
  const normalizedEvent = {
    source_type: sourceType,
    parser_source: 'syslog_observables',
    matched_ioc: r.matched_ioc,
    ioc_type: r.ioc_type,
    src_ip: null,
    client_ip: null,
    dst_ip: null,
    response_ip: null,
    domain: r.ioc_type === 'domain' ? r.matched_ioc : null,
    query: r.ioc_type === 'domain' ? r.matched_ioc : null,
    url: r.ioc_type === 'url' ? r.matched_ioc : null,
    action: null,
    status: null,
    method: null,
    port: null,
    protocol: 'dns',
    event_time: r.ts || null
  };
  return {
    event_time: r.ts,
    host: r.host,
    source: r.source,
    parser_source: 'syslog_observables',
    destination_ip: null,
    protocol: 'dns',
    matched_ioc: r.matched_ioc,
    ioc_type: r.ioc_type,
    source_name: r.source_name || null,
    confidence: String(r.confidence || ''),
    detection_type: 'retroactive',
    match_source: null,
    match_context: matchContext,
    normalized_event_json: normalizedEvent,
    raw_log_snapshot: rawLogSnapshot,
    raw_log_hash: rawLogSnapshot ? createHash('sha256').update(rawLogSnapshot).digest('hex') : null,
    syslog_log_id: r?.event_id || r?.log_id || r?.id || null,
    source_type: sourceType
  };
}

async function maybeSyncIocLookup(force = false) {
  if (!IOC_LOOKUP_SYNC_ENABLED) return false;
  const now = Date.now();
  if (!force && (now - lastIocLookupSyncAtMs) < (IOC_LOOKUP_SYNC_INTERVAL_SECONDS * 1000)) return false;
  const syncRes = await syncIocLookupFromPostgres();
  lastIocLookupSyncAtMs = now;
  console.log(`[ioc-retro] ioc_lookup sync completed interval_s=${IOC_LOOKUP_SYNC_INTERVAL_SECONDS} changed=${Boolean(syncRes?.changed)} fetched=${Number(syncRes?.fetched || 0)} written=${Number(syncRes?.written || 0)}`);
  return true;
}

async function getPendingStats(ts, hash) {
  const rows = await clickhouseQuery(`
    SELECT
      count() AS pending,
      min(updated_at) AS min_pending_ts,
      max(updated_at) AS max_pending_ts
    FROM default.ioc_lookup_by_updated
    WHERE (
      updated_at > toDateTime64('${safeTs(ts)}', 3)
      OR (updated_at = toDateTime64('${safeTs(ts)}', 3)
          AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${safeHash(hash)}'))
    )
  `, { queryId: makeQueryId('pending-stats'), logTag: 'ioc-retro.pending-stats' });

  return {
    pending: Number(rows?.[0]?.pending || 0),
    minPendingTs: rows?.[0]?.min_pending_ts || null,
    maxPendingTs: rows?.[0]?.max_pending_ts || null
  };
}

async function fetchIocChunk(startTs, startHash, limit) {
  return clickhouseQuery(`
    SELECT
      observable,
      observable_type,
      source_name,
      confidence,
      updated_at,
      toString(cityHash64(concat(observable, '|', observable_type, '|', source_name))) AS row_hash
    FROM default.ioc_lookup_by_updated
    WHERE (
      updated_at > toDateTime64('${safeTs(startTs)}', 3)
      OR (updated_at = toDateTime64('${safeTs(startTs)}', 3)
          AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${safeHash(startHash)}'))
    )
    ORDER BY updated_at, toUInt64(row_hash)
    LIMIT ${Math.max(Number(limit || RETRO_IOC_CHUNK_SIZE), 1)}
  `, { queryId: makeQueryId('retro-ioc-chunk'), logTag: 'ioc-retro.ioc-chunk' });
}

async function fetchWindowMatchPage({
  startTs,
  startHash,
  endTs,
  endHash,
  cursorTs,
  cursorRawHash,
  cursorObservable,
  cursorObservableType,
  cursorSourceName,
  limit
}) {
  return clickhouseQuery(`
    WITH ioc_window AS (
      SELECT
        observable,
        observable_type,
        source_name,
        confidence,
        updated_at,
        toString(cityHash64(concat(observable, '|', observable_type, '|', source_name))) AS row_hash
      FROM default.ioc_lookup_by_updated
      WHERE (
        updated_at > toDateTime64('${safeTs(startTs)}', 3)
        OR (updated_at = toDateTime64('${safeTs(startTs)}', 3)
            AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${safeHash(startHash)}'))
      )
      AND (
        updated_at < toDateTime64('${safeTs(endTs)}', 3)
        OR (updated_at = toDateTime64('${safeTs(endTs)}', 3)
            AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) <= toUInt64('${safeHash(endHash)}'))
      )
    )
    SELECT
      so.ts,
      so.source,
      so.host,
      so.raw_row_hash,
      iw.observable AS matched_ioc,
      iw.observable_type AS ioc_type,
      iw.source_name AS source_name,
      toInt32(iw.confidence) AS confidence,
      iw.updated_at AS ioc_updated_at
    FROM default.syslog_observables so
    INNER JOIN ioc_window iw
      ON so.observable = iw.observable
     AND so.observable_type = iw.observable_type
    WHERE so.ts >= now() - INTERVAL ${RETRO_LOOKBACK_DAYS} DAY
      AND tuple(so.ts, so.raw_row_hash, iw.observable, iw.observable_type, iw.source_name)
          > tuple(
              toDateTime('${safeDateTime(cursorTs)}'),
              '${chLiteral(String(cursorRawHash || ''))}',
              '${chLiteral(String(cursorObservable || ''))}',
              '${chLiteral(String(cursorObservableType || ''))}',
              '${chLiteral(String(cursorSourceName || ''))}'
            )
    ORDER BY so.ts ASC, so.raw_row_hash ASC, iw.observable ASC, iw.observable_type ASC, iw.source_name ASC
    LIMIT ${Math.max(Number(limit || RETRO_MATCH_PAGE_SIZE), 1)}
    SETTINGS max_threads = ${RETRO_CH_MAX_THREADS}, max_execution_time = ${RETRO_CH_MAX_EXECUTION_TIME_SECONDS}
  `, { queryId: makeQueryId('retro-window-page'), logTag: 'ioc-retro.window-page' });
}

async function runRetroWindowBatch() {
  const startedAt = Date.now();
  const st = await loadRetroState();
  const pendingBeforeStats = await getPendingStats(st.last_processed_ts, st.last_processed_row_hash);

  let working = { ...st };

  if (!working.chunk_active) {
    const iocChunk = await fetchIocChunk(working.last_processed_ts, working.last_processed_row_hash, RETRO_IOC_CHUNK_SIZE);
    if (!iocChunk.length) {
      const durationMs = Date.now() - startedAt;
      await saveRetroState({ ...working, last_run_duration_ms: durationMs });
      return {
        ran: true,
        workDone: false,
        pendingBefore: pendingBeforeStats.pending,
        pendingAfter: pendingBeforeStats.pending,
        durationMs,
        skipped: 'no_new_ioc'
      };
    }

    const end = iocChunk[iocChunk.length - 1];
    working = {
      ...working,
      chunk_active: 1,
      chunk_end_ts: end.updated_at,
      chunk_end_row_hash: end.row_hash,
      chunk_ioc_count: iocChunk.length,
      chunk_rows_processed: 0,
      match_cursor_ts: MATCH_CURSOR_TS_START,
      match_cursor_raw_hash: MATCH_CURSOR_RAW_START,
      match_cursor_observable: '',
      match_cursor_observable_type: '',
      match_cursor_source_name: ''
    };
  }

  const rows = await fetchWindowMatchPage({
    startTs: working.last_processed_ts,
    startHash: working.last_processed_row_hash,
    endTs: working.chunk_end_ts,
    endHash: working.chunk_end_row_hash,
    cursorTs: working.match_cursor_ts,
    cursorRawHash: working.match_cursor_raw_hash,
    cursorObservable: working.match_cursor_observable,
    cursorObservableType: working.match_cursor_observable_type,
    cursorSourceName: working.match_cursor_source_name,
    limit: RETRO_MATCH_PAGE_SIZE
  });

  let inserted = 0;
  let suppressedCount = 0;
  if (rows.length > 0) {
    const mapped = rows.map((r) => mapRowToEvent(r));
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const insertResult = await insertMatchEvents(client, mapped);
      inserted = Number(insertResult.inserted || 0);
      suppressedCount = Number(insertResult.suppressed_count || 0);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      client.release();
      throw err;
    }
    client.release();
  }

  const durationMs = Date.now() - startedAt;
  const pageFull = rows.length === RETRO_MATCH_PAGE_SIZE;

  if (pageFull) {
    const last = rows[rows.length - 1];
    const nextState = {
      ...working,
      chunk_rows_processed: Number(working.chunk_rows_processed || 0) + rows.length,
      match_cursor_ts: safeDateTime(last.ts),
      match_cursor_raw_hash: String(last.raw_row_hash || ''),
      match_cursor_observable: String(last.matched_ioc || ''),
      match_cursor_observable_type: String(last.ioc_type || ''),
      match_cursor_source_name: String(last.source_name || ''),
      last_run_duration_ms: durationMs
    };
    await saveRetroState(nextState);

    return {
      ran: true,
      workDone: true,
      pendingBefore: pendingBeforeStats.pending,
      pendingAfter: pendingBeforeStats.pending,
      inserted,
      suppressed_count: suppressedCount,
      matchedRows: rows.length,
      durationMs,
      pageFull: true,
      chunkCompleted: false,
      chunkIocCount: Number(working.chunk_ioc_count || 0),
      chunkRowsProcessed: Number(nextState.chunk_rows_processed || 0),
      pendingMinTs: pendingBeforeStats.minPendingTs,
      pendingMaxTs: pendingBeforeStats.maxPendingTs
    };
  }

  const doneState = {
    last_processed_ts: working.chunk_end_ts,
    last_processed_row_hash: working.chunk_end_row_hash,
    last_run_duration_ms: durationMs,
    ...idleMatchDefaults()
  };
  await saveRetroState(doneState);

  const pendingAfterStats = await getPendingStats(doneState.last_processed_ts, doneState.last_processed_row_hash);

  return {
    ran: true,
    workDone: true,
    pendingBefore: pendingBeforeStats.pending,
    pendingAfter: pendingAfterStats.pending,
    inserted,
    suppressed_count: suppressedCount,
    matchedRows: rows.length,
    durationMs,
    pageFull: false,
    chunkCompleted: true,
    chunkIocCount: Number(working.chunk_ioc_count || 0),
    chunkRowsProcessed: Number(working.chunk_rows_processed || 0) + rows.length,
    pendingMinTs: pendingAfterStats.minPendingTs,
    pendingMaxTs: pendingAfterStats.maxPendingTs
  };
}

function logStatus(extra = '') {
  const suffix = extra ? ` ${extra}` : '';
  console.log(
    `[ioc-retro][status] mode=${workerStatus.mode} backlog=${workerStatus.backlogSize} last_duration_ms=${workerStatus.lastRunDurationMs} last_batch_size=${workerStatus.lastBatchSize} chunk_ioc_count=${workerStatus.chunkIocCount} chunk_rows_processed=${workerStatus.chunkRowsProcessed} loops=${workerStatus.loops}${suffix}`
  );
}

async function runAdaptiveLoop() {
  const st = await loadRetroState();
  const pending = await getPendingStats(st.last_processed_ts, st.last_processed_row_hash);
  workerStatus.backlogSize = pending.pending;
  workerStatus.loops += 1;

  if (pending.pending <= 0 && !st.chunk_active) {
    workerStatus.mode = 'idle';
    const idleSleepMs = getIdleProbeSleepMs();
    logStatus(`pending_range=none mode=idle probe_ms=${idleSleepMs} align_remaining_ms=${getIdleSleepMs()}`);
    await sleep(idleSleepMs);
    return;
  }

  workerStatus.mode = pending.pending > RETRO_BACKLOG_THRESHOLD_HIGH ? 'catchup' : 'normal';
  const res = await runRetroWindowBatch();
  workerStatus.lastRunDurationMs = Number(res?.durationMs || 0);
  workerStatus.lastBatchSize = Number(res?.matchedRows || 0);
  workerStatus.backlogSize = Number(res?.pendingAfter ?? pending.pending);
  workerStatus.chunkIocCount = Number(res?.chunkIocCount || 0);
  workerStatus.chunkRowsProcessed = Number(res?.chunkRowsProcessed || 0);

  if (res?.skipped === 'no_new_ioc' || !res?.workDone) {
    workerStatus.mode = 'idle';
    const idleSleepMs = getIdleProbeSleepMs();
    logStatus(`skip_reason=${res?.skipped || 'none'} probe_ms=${idleSleepMs} align_remaining_ms=${getIdleSleepMs()}`);
    await sleep(idleSleepMs);
    return;
  }

  let nextSleepMs;
  let pace;

  // If backlog exists, do not return to aligned/idle pacing.
  if (workerStatus.backlogSize > 0) {
    if (workerStatus.backlogSize > RETRO_BACKLOG_THRESHOLD_HIGH) {
      nextSleepMs = RETRO_BACKLOG_FAST_POLL_MS;
      pace = 'fast';
    } else {
      nextSleepMs = RETRO_BACKLOG_MEDIUM_POLL_MS;
      pace = 'medium';
    }
  } else {
    nextSleepMs = getIdleSleepMs();
    pace = RETRO_ALIGN_ENABLED ? `normal-aligned-${String(RETRO_ALIGN_MINUTE).padStart(2, '0')}` : 'normal';
  }

  if (workerStatus.lastRunDurationMs > RETRO_SLOW_TICK_THRESHOLD_MS) {
    nextSleepMs = Math.max(nextSleepMs, RETRO_BACKLOG_MEDIUM_POLL_MS);
    pace = `${pace}+slowguard`;
  }

  const chunkState = res.chunkCompleted ? 'chunk_complete' : 'chunk_page';
  logStatus(
    `${chunkState} page_full=${res.pageFull ? 1 : 0} pending_before=${res.pendingBefore} pending_after=${res.pendingAfter} pending_range=${res.pendingMinTs || 'none'}..${res.pendingMaxTs || 'none'} inserted=${res.inserted || 0} suppressed_count=${res.suppressed_count || 0} matched_rows=${res.matchedRows || 0} duration_ms=${res.durationMs} pace=${pace} sleep_ms=${nextSleepMs}`
  );

  await sleep(nextSleepMs);
}

async function bootstrap() {
  await ensureIocCorrelationAssets();
  await maybeSyncIocLookup(true);

  console.log(
    `[ioc-retro] started mode=window-bulk retro_interval_s=${RETRO_SCAN_INTERVAL_SECONDS} align_enabled=${RETRO_ALIGN_ENABLED ? 1 : 0} align_minute=${RETRO_ALIGN_MINUTE} idle_probe_ms=${IOC_RETRO_POLL_INTERVAL_MS} ioc_chunk_size=${RETRO_IOC_CHUNK_SIZE} match_page_size=${RETRO_MATCH_PAGE_SIZE} lookback_d=${RETRO_LOOKBACK_DAYS} sync_interval_s=${IOC_LOOKUP_SYNC_INTERVAL_SECONDS} ch_max_threads=${RETRO_CH_MAX_THREADS} ch_max_exec_s=${RETRO_CH_MAX_EXECUTION_TIME_SECONDS}`
  );

  while (!stopping) {
    try {
      await maybeSyncIocLookup(false);
      await runAdaptiveLoop();
    } catch (err) {
      console.error('[ioc-retro] tick failed', err?.message || err);
      await sleep(RETRO_BACKLOG_MEDIUM_POLL_MS);
    }
  }
}

process.on('SIGINT', async () => { stopping = true; await pool.end(); process.exit(0); });
process.on('SIGTERM', async () => { stopping = true; await pool.end(); process.exit(0); });

bootstrap().catch(async (err) => {
  console.error('[ioc-retro] bootstrap failed', err?.message || err);
  await pool.end();
  process.exit(1);
});
