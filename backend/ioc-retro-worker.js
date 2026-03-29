import pg from 'pg';
import { ensureIocCorrelationAssets, syncIocLookupFromPostgres, query as clickhouseQuery, command as clickhouseCommand } from './lib/clickhouse.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD || 'demo123',
  database: process.env.DB_NAME || 'demo'
});

const RETRO_SCAN_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_RETRO_SCAN_INTERVAL_SECONDS || 3600), 30);
const RETRO_POLL_INTERVAL_MS = Math.max(Number(process.env.IOC_RETRO_POLL_INTERVAL_MS || 5000), 500);
const RETRO_LOOKBACK_DAYS = Math.max(Number(process.env.IOC_RETRO_LOOKBACK_DAYS || 30), 1);
const RETRO_BATCH_SIZE = Math.max(Number(process.env.IOC_RETRO_BATCH_SIZE || 20000), 1000);
const IOC_LOOKUP_SYNC_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_LOOKUP_SYNC_INTERVAL_SECONDS || 1800), 60);
const DEDUP_WINDOW_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_DEDUP_WINDOW_SECONDS || 300), 60);
const RETRO_CH_MAX_THREADS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_THREADS || 2), 1);
const RETRO_CH_MAX_EXECUTION_TIME_SECONDS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_EXECUTION_TIME_SECONDS || 25), 5);
const RETRO_NEW_IOC_WINDOW_HOURS = Math.max(Number(process.env.IOC_RETRO_NEW_IOC_WINDOW_HOURS || 2), 1);
const IOC_LOOKUP_SYNC_ENABLED = process.env.IOC_LOOKUP_SYNC_ENABLED === '1' || process.env.IOC_LOOKUP_SYNC_ENABLED === 'true';

const RETRO_BACKLOG_FAST_POLL_MS = Math.max(Number(process.env.IOC_RETRO_BACKLOG_FAST_POLL_MS || 15000), 3000);
const RETRO_BACKLOG_MEDIUM_POLL_MS = Math.max(Number(process.env.IOC_RETRO_BACKLOG_MEDIUM_POLL_MS || 60000), 5000);
const RETRO_DRAIN_POLL_MS = Math.max(Number(process.env.IOC_RETRO_DRAIN_POLL_MS || 10000), 2000);
const RETRO_BACKLOG_THRESHOLD_HIGH = Math.max(Number(process.env.IOC_RETRO_BACKLOG_THRESHOLD_HIGH || 10000), 100);
const RETRO_BACKLOG_THRESHOLD_MEDIUM = Math.max(Number(process.env.IOC_RETRO_BACKLOG_THRESHOLD_MEDIUM || 500), 10);
const RETRO_SLOW_TICK_THRESHOLD_MS = Math.max(Number(process.env.IOC_RETRO_SLOW_TICK_THRESHOLD_MS || 4000), 1000);
const RETRO_ALIGN_MINUTE = Math.min(Math.max(Number(process.env.IOC_RETRO_ALIGN_MINUTE || 10), 0), 59);
const RETRO_ALIGN_ENABLED = process.env.IOC_RETRO_ALIGN_ENABLED === '0' ? false : true;

/** Start-of-time cursor: tuple (ts, raw_row_hash) > this includes all real syslog rows. */
const MATCH_CURSOR_TS_START = '1970-01-01 00:00:00';
const MATCH_CURSOR_RAW_START = '';

let stopping = false;
let lastIocLookupSyncAtMs = 0;

const workerStatus = {
  backlogSize: 0,
  lastRunDurationMs: 0,
  lastBatchSize: 0,
  mode: 'idle',
  lastRunAt: null,
  loops: 0
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

  if (next <= now) {
    next.setUTCHours(next.getUTCHours() + 1);
  }

  const ms = next.getTime() - now.getTime();
  return Math.max(ms, 1000);
}

function safeTs(ts) {
  return String(ts || '1970-01-01 00:00:00.000').replace('T', ' ').replace('Z', '');
}

function safeHash(hash) {
  return String(hash || '0').replace(/[^0-9]/g, '') || '0';
}

/** ClickHouse single-quoted string literal (DateTime / String). */
function chLiteral(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/'/g, "''");
}

/** Normalizes to YYYY-MM-DD HH:MM:SS for ClickHouse DateTime. */
function safeDateTime(ts) {
  const s = String(ts || MATCH_CURSOR_TS_START).replace('T', ' ').replace('Z', '');
  const noMs = s.includes('.') ? s.slice(0, s.indexOf('.')) : s;
  if (noMs.length >= 19) return noMs.slice(0, 19);
  if (noMs.length === 10) return `${noMs} 00:00:00`;
  return MATCH_CURSOR_TS_START;
}

function logStatus(extra = '') {
  const suffix = extra ? ` ${extra}` : '';
  console.log(
    `[ioc-retro][status] mode=${workerStatus.mode} backlog=${workerStatus.backlogSize} last_duration_ms=${workerStatus.lastRunDurationMs} last_batch_size=${workerStatus.lastBatchSize} loops=${workerStatus.loops}${suffix}`
  );
}

function compareCursor(aTs, aHash, bTs, bHash) {
  const ta = new Date(safeTs(aTs).replace(' ', 'T') + 'Z').getTime();
  const tb = new Date(safeTs(bTs).replace(' ', 'T') + 'Z').getTime();
  if (ta > tb) return 1;
  if (ta < tb) return -1;
  const ha = BigInt(safeHash(aHash));
  const hb = BigInt(safeHash(bHash));
  if (ha > hb) return 1;
  if (ha < hb) return -1;
  return 0;
}

function idleMatchDefaults() {
  return {
    match_observable: '',
    match_observable_type: '',
    match_source_name: '',
    match_cursor_ts: MATCH_CURSOR_TS_START,
    match_cursor_raw_hash: MATCH_CURSOR_RAW_START,
    match_ioc_updated_at: '1970-01-01 00:00:00.000',
    match_ioc_confidence: 0,
    match_ioc_row_hash: ''
  };
}

async function loadRetroState() {
  const rows = await clickhouseQuery(`
    SELECT
      last_processed_ts,
      last_processed_row_hash,
      match_observable,
      match_observable_type,
      match_source_name,
      match_cursor_ts,
      match_cursor_raw_hash,
      match_ioc_updated_at,
      match_ioc_confidence,
      match_ioc_row_hash
    FROM default.ioc_retro_state
    WHERE worker_name = 'ioc-retro-v1'
    ORDER BY updated_at DESC
    LIMIT 1
  `, { queryId: makeQueryId('retro-state-load'), logTag: 'ioc-retro.state-load' });
  const r = rows?.[0] || {};
  const idle = idleMatchDefaults();
  return {
    last_processed_ts: r.last_processed_ts || '1970-01-01 00:00:00.000',
    last_processed_row_hash: r.last_processed_row_hash || '0',
    match_observable: r.match_observable ?? idle.match_observable,
    match_observable_type: r.match_observable_type ?? idle.match_observable_type,
    match_source_name: r.match_source_name ?? idle.match_source_name,
    match_cursor_ts: r.match_cursor_ts ?? idle.match_cursor_ts,
    match_cursor_raw_hash: r.match_cursor_raw_hash ?? idle.match_cursor_raw_hash,
    match_ioc_updated_at: r.match_ioc_updated_at || idle.match_ioc_updated_at,
    match_ioc_confidence: Number(r.match_ioc_confidence ?? idle.match_ioc_confidence),
    match_ioc_row_hash: r.match_ioc_row_hash ?? idle.match_ioc_row_hash
  };
}

/**
 * Persists retro state to ClickHouse. Call only after Postgres COMMIT (or when no PG write).
 */
async function saveRetroState({
  last_processed_ts,
  last_processed_row_hash,
  match_observable = '',
  match_observable_type = '',
  match_source_name = '',
  match_cursor_ts = MATCH_CURSOR_TS_START,
  match_cursor_raw_hash = MATCH_CURSOR_RAW_START,
  match_ioc_updated_at = '1970-01-01 00:00:00.000',
  match_ioc_confidence = 0,
  match_ioc_row_hash = ''
}) {
  const mdt = safeDateTime(match_cursor_ts);
  const mraw = chLiteral(String(match_cursor_raw_hash ?? ''));
  await clickhouseCommand(`
    INSERT INTO default.ioc_retro_state (
      worker_name,
      last_processed_ts,
      last_processed_row_hash,
      match_observable,
      match_observable_type,
      match_source_name,
      match_cursor_ts,
      match_cursor_raw_hash,
      match_ioc_updated_at,
      match_ioc_confidence,
      match_ioc_row_hash,
      updated_at
    )
    VALUES (
      'ioc-retro-v1',
      toDateTime64('${safeTs(last_processed_ts)}', 3),
      '${chLiteral(String(last_processed_row_hash))}',
      '${chLiteral(String(match_observable))}',
      '${chLiteral(String(match_observable_type))}',
      '${chLiteral(String(match_source_name))}',
      toDateTime('${mdt}'),
      '${mraw}',
      toDateTime64('${safeTs(match_ioc_updated_at)}', 3),
      toInt32(${Number(match_ioc_confidence) || 0}),
      '${chLiteral(String(match_ioc_row_hash))}',
      now64(3)
    )
  `, { logTag: 'ioc-retro.state-save' });
}

function floorToBucket(tsIso, seconds) {
  const d = new Date(tsIso);
  const ms = d.getTime();
  const bucketMs = seconds * 1000;
  const floored = Math.floor(ms / bucketMs) * bucketMs;
  return new Date(floored).toISOString();
}

function dedupKeyOf(row) {
  return [row.match_type || 'unknown', row.matched_ioc || '', row.host || '', row.source || '', row.parser_source || 'unknown'].join('|');
}

async function insertMatchEvents(client, rows) {
  if (!rows.length) return 0;
  const values = [];
  const params = [];
  for (let i = 0; i < rows.length; i += 1) {
    const r = rows[i];
    const bucketStart = floorToBucket(r.event_time, DEDUP_WINDOW_SECONDS);
    const dedupKey = dedupKeyOf({ ...r, match_type: r.ioc_type });
    const base = i * 17;
    values.push(`($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6},$${base + 7},$${base + 8},$${base + 9},$${base + 10},$${base + 11},$${base + 12},$${base + 13},$${base + 14},$${base + 15},$${base + 16},$${base + 17})`);
    params.push(
      r.event_time, r.host || null, null, r.destination_ip || null, null, r.protocol || null,
      r.matched_ioc, r.source_name || null, r.confidence || null, r.ioc_type, null,
      r.parser_source || null, r.source || null, JSON.stringify(r.match_context || {}),
      dedupKey, bucketStart, r.event_time
    );
  }
  await client.query(
    `INSERT INTO ioc_match_events (
      event_time, host_name, process_name, destination_ip, destination_port, protocol,
      matched_ioc, source_name, confidence, ioc_type, ioc_item_id,
      parser_source, source, match_context, dedup_key, bucket_start, last_seen_at
    ) VALUES ${values.join(',')}
    ON CONFLICT (dedup_key, bucket_start)
    DO UPDATE SET
      hit_count = ioc_match_events.hit_count + 1,
      last_seen_at = GREATEST(ioc_match_events.last_seen_at, EXCLUDED.last_seen_at),
      confidence = COALESCE(EXCLUDED.confidence, ioc_match_events.confidence),
      source_name = COALESCE(EXCLUDED.source_name, ioc_match_events.source_name),
      match_context = COALESCE(EXCLUDED.match_context, ioc_match_events.match_context)`
    , params
  );
  return rows.length;
}

async function maybeSyncIocLookup(force = false) {
  if (!IOC_LOOKUP_SYNC_ENABLED) return false;
  const now = Date.now();
  if (!force && (now - lastIocLookupSyncAtMs) < (IOC_LOOKUP_SYNC_INTERVAL_SECONDS * 1000)) return false;
  const syncRes = await syncIocLookupFromPostgres();
  lastIocLookupSyncAtMs = now;
  console.log(`[ioc-retro] ioc_lookup sync completed interval_s=${IOC_LOOKUP_SYNC_INTERVAL_SECONDS} changed=${Boolean(syncRes?.changed)}`);
  return true;
}

async function getPendingCount(ts, hash) {
  const rows = await clickhouseQuery(`
    SELECT count() AS pending
    FROM default.ioc_lookup
    WHERE (
      updated_at > toDateTime64('${safeTs(ts)}', 3)
      OR (updated_at = toDateTime64('${safeTs(ts)}', 3)
          AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${safeHash(hash)}'))
    )
  `, { queryId: makeQueryId('pending-count'), logTag: 'ioc-retro.pending-count' });
  return Number(rows?.[0]?.pending || 0);
}

async function getBacklogFromState() {
  const st = await loadRetroState();
  const lastTs = safeTs(st.last_processed_ts);
  const lastHash = safeHash(st.last_processed_row_hash);
  const pending = await getPendingCount(lastTs, lastHash);
  return { pending, lastTs, lastHash };
}

async function hasNewIocs() {
  const st = await loadRetroState();
  const lastTs = safeTs(st.last_processed_ts);
  const lastHash = safeHash(st.last_processed_row_hash);
  const rows = await clickhouseQuery(`
    WITH new_iocs AS (
      SELECT observable, observable_type, source_name, updated_at,
             toString(cityHash64(concat(observable, '|', observable_type, '|', source_name))) AS row_hash
      FROM default.ioc_lookup
      WHERE (
        updated_at > toDateTime64('${lastTs}', 3)
        OR (updated_at = toDateTime64('${lastTs}', 3)
            AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${lastHash}'))
      )
      ORDER BY updated_at, toUInt64(row_hash)
      LIMIT 1
    )
    SELECT 1 AS has_new FROM new_iocs LIMIT 1
  `, { queryId: makeQueryId('retro-has-new-iocs'), logTag: 'ioc-retro.has-new-iocs' });
  return Array.isArray(rows) && rows.length > 0;
}

async function fetchNextIocRow(iocTs, iocHash) {
  return clickhouseQuery(`
    SELECT
      observable,
      observable_type,
      confidence,
      source_name,
      updated_at,
      toString(cityHash64(concat(observable, '|', observable_type, '|', source_name))) AS row_hash
    FROM default.ioc_lookup
    WHERE (
      updated_at > toDateTime64('${iocTs}', 3)
      OR (updated_at = toDateTime64('${iocTs}', 3)
          AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${iocHash}'))
    )
    ORDER BY updated_at, toUInt64(row_hash)
    LIMIT 1
  `, { queryId: makeQueryId('retro-next-ioc'), logTag: 'ioc-retro.next-ioc' });
}

async function fetchMatchPage(meta, matchTs, matchRawEscaped, batchSize) {
  const obs = chLiteral(meta.observable);
  const oty = chLiteral(meta.observable_type);
  const mts = safeDateTime(matchTs);
  return clickhouseQuery(`
    SELECT
      so.ts,
      so.source,
      so.host,
      so.raw_row_hash,
      'syslog_observables' AS parser_source,
      CAST(NULL, 'Nullable(String)') AS parsed_ip,
      CAST(NULL, 'Nullable(String)') AS parsed_query,
      '${obs}' AS matched_ioc,
      '${oty}' AS ioc_type,
      toInt32(${Number(meta.confidence) || 0}) AS confidence,
      '${chLiteral(meta.source_name)}' AS source_name,
      toDateTime64('${safeTs(meta.updated_at)}', 3) AS ioc_updated_at
    FROM default.syslog_observables so
    WHERE so.observable = '${obs}'
      AND so.observable_type = '${oty}'
      AND so.ts >= now() - INTERVAL ${RETRO_LOOKBACK_DAYS} DAY
      AND tuple(so.ts, so.raw_row_hash) > tuple(toDateTime('${mts}'), '${matchRawEscaped}')
    ORDER BY so.ts ASC, so.raw_row_hash ASC
    LIMIT ${batchSize}
    SETTINGS max_threads = ${RETRO_CH_MAX_THREADS}, max_execution_time = ${RETRO_CH_MAX_EXECUTION_TIME_SECONDS}
  `, { queryId: makeQueryId('retro-pass-page'), logTag: 'ioc-retro.retro-pass-page' });
}

/**
 * One IOC step: paginated syslog scan, Postgres insert, then ClickHouse state (after COMMIT).
 */
async function runRetroBatch({ batchSize = RETRO_BATCH_SIZE } = {}) {
  const passStartedAtMs = Date.now();

  const st = await loadRetroState();
  const iocTs = safeTs(st.last_processed_ts);
  const iocHash = safeHash(st.last_processed_row_hash);
  const pendingBefore = await getPendingCount(iocTs, iocHash);

  const resuming = String(st.match_observable || '').length > 0;

  let meta;
  let matchTsForQuery;
  let matchRawEscaped;

  if (resuming) {
    meta = {
      observable: st.match_observable,
      observable_type: st.match_observable_type,
      source_name: st.match_source_name,
      confidence: Number(st.match_ioc_confidence) || 0,
      updated_at: st.match_ioc_updated_at,
      row_hash: String(st.match_ioc_row_hash || '0')
    };
    matchTsForQuery = st.match_cursor_ts;
    matchRawEscaped = chLiteral(String(st.match_cursor_raw_hash ?? ''));
  } else {
    const nextRows = await fetchNextIocRow(iocTs, iocHash);
    if (!nextRows.length) {
      const durationMs = Date.now() - passStartedAtMs;
      console.log(`[ioc-retro] pending_before=${pendingBefore} ioc_step=none matched_rows=0 pending_after=${pendingBefore} duration_ms=${durationMs} skipped=no_new_ioc`);
      return {
        ran: true,
        workDone: false,
        inserted: 0,
        matchedRows: 0,
        iocCompleted: false,
        matchPageFull: false,
        pendingBefore,
        pendingAfter: pendingBefore,
        durationMs,
        skipped: 'no_new_ioc'
      };
    }
    const nr = nextRows[0];
    meta = {
      observable: nr.observable,
      observable_type: nr.observable_type,
      source_name: nr.source_name,
      confidence: Number(nr.confidence) || 0,
      updated_at: nr.updated_at,
      row_hash: String(nr.row_hash || '0')
    };
    matchTsForQuery = MATCH_CURSOR_TS_START;
    matchRawEscaped = chLiteral(MATCH_CURSOR_RAW_START);
  }

  const rows = await fetchMatchPage(meta, matchTsForQuery, matchRawEscaped, batchSize);
  const matchPageFull = rows.length === batchSize;
  const lastSo = rows.length ? rows[rows.length - 1] : null;

  const nextIocTs = safeTs(meta.updated_at);
  const nextIocHash = safeHash(meta.row_hash);

  if (matchPageFull && lastSo) {
    let inserted = 0;
    const mapped = rows.map((r) => mapRowToEvent(r));
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      inserted = await insertMatchEvents(client, mapped);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      client.release();
      throw err;
    }
    client.release();

    await saveRetroState({
      last_processed_ts: iocTs,
      last_processed_row_hash: iocHash,
      match_observable: meta.observable,
      match_observable_type: meta.observable_type,
      match_source_name: meta.source_name,
      match_cursor_ts: safeDateTime(lastSo.ts),
      match_cursor_raw_hash: String(lastSo.raw_row_hash ?? ''),
      match_ioc_updated_at: meta.updated_at,
      match_ioc_confidence: meta.confidence,
      match_ioc_row_hash: meta.row_hash
    });

    const pendingAfter = await getPendingCount(iocTs, iocHash);
    const durationMs = Date.now() - passStartedAtMs;
    console.log(`[ioc-retro] pending_before=${pendingBefore} ioc_step=page matched_rows=${rows.length} inserted_or_upserted=${inserted} match_page_full=1 ioc_cursor_unchanged=1 pending_after=${pendingAfter} duration_ms=${durationMs}`);
    return {
      ran: true,
      workDone: true,
      inserted,
      matchedRows: rows.length,
      iocCompleted: false,
      matchPageFull: true,
      pendingBefore,
      pendingAfter,
      durationMs
    };
  }

  // IOC finished this tick: last page (< batch) or zero rows
  if (compareCursor(nextIocTs, nextIocHash, iocTs, iocHash) < 0) {
    console.warn(`[ioc-retro] cursor regression blocked cursor_before_ts=${iocTs} cursor_before_hash=${iocHash} cursor_after_ts=${nextIocTs} cursor_after_hash=${nextIocHash}`);
    return {
      ran: false,
      workDone: false,
      inserted: 0,
      matchedRows: 0,
      iocCompleted: false,
      matchPageFull: false,
      pendingBefore,
      pendingAfter: pendingBefore,
      durationMs: Date.now() - passStartedAtMs,
      skipped: 'cursor_regression'
    };
  }

  let inserted = 0;
  if (rows.length > 0) {
    const mapped = rows.map((r) => mapRowToEvent(r));
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      inserted = await insertMatchEvents(client, mapped);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      client.release();
      throw err;
    }
    client.release();
  }

  const idle = idleMatchDefaults();
  await saveRetroState({
    last_processed_ts: nextIocTs,
    last_processed_row_hash: nextIocHash,
    ...idle
  });

  const pendingAfter = await getPendingCount(nextIocTs, nextIocHash);
  const durationMs = Date.now() - passStartedAtMs;
  console.log(`[ioc-retro] pending_before=${pendingBefore} ioc_step=complete matched_rows=${rows.length} inserted_or_upserted=${inserted} match_page_full=0 pending_after=${pendingAfter} cursor_after_ts=${nextIocTs} duration_ms=${durationMs}`);
  return {
    ran: true,
    workDone: true,
    inserted,
    matchedRows: rows.length,
    iocCompleted: true,
    matchPageFull: false,
    pendingBefore,
    pendingAfter,
    durationMs
  };
}

function mapRowToEvent(r) {
  const eventMs = r?.ts ? new Date(r.ts).getTime() : 0;
  const iocUpdatedMs = r?.ioc_updated_at ? new Date(r.ioc_updated_at).getTime() : 0;
  const iocWasPresentAtIngest = eventMs > 0 && iocUpdatedMs > 0 ? iocUpdatedMs <= eventMs : false;
  return {
    event_time: r.ts,
    host: r.host,
    source: r.source,
    parser_source: r.parser_source,
    destination_ip: r.parsed_ip || null,
    protocol: 'dns',
    matched_ioc: r.matched_ioc,
    ioc_type: r.ioc_type,
    source_name: r.source_name || null,
    confidence: String(r.confidence || ''),
    match_context: {
      retroactive: true,
      observable_source: 'syslog_observables',
      processing_path: 'retro',
      ioc_was_present_at_ingest: iocWasPresentAtIngest
    }
  };
}

async function runAdaptiveLoop() {
  const initial = await getBacklogFromState();
  workerStatus.backlogSize = initial.pending;
  workerStatus.loops = 1;

  if (initial.pending <= 0) {
    workerStatus.mode = 'idle';
    const idleSleepMs = getIdleSleepMs();
    logStatus(`estimated_backlog=no sleep_ms=${idleSleepMs}`);
    await sleep(idleSleepMs);
    return;
  }

  await maybeSyncIocLookup(false);

  const hasIncrementalIocs = await hasNewIocs();
  if (!hasIncrementalIocs) {
    workerStatus.mode = 'idle';
    workerStatus.lastBatchSize = 0;
    workerStatus.backlogSize = 0;
    const skipSleepMs = Math.max(RETRO_POLL_INTERVAL_MS, RETRO_BACKLOG_MEDIUM_POLL_MS);
    logStatus(`processed_iocs=0 estimated_backlog=no mode=idle skip_reason=no_new_ioc_precheck sleep_ms=${skipSleepMs}`);
    await sleep(skipSleepMs);
    return;
  }

  workerStatus.mode = 'single-pass';
  const res = await runRetroBatch({ batchSize: RETRO_BATCH_SIZE });

  workerStatus.lastRunDurationMs = Number(res?.durationMs || 0);
  workerStatus.lastBatchSize = Number(res?.matchedRows || 0);
  workerStatus.backlogSize = Number(res?.pendingAfter ?? initial.pending);
  workerStatus.lastRunAt = new Date().toISOString();

  if (res?.skipped === 'no_new_ioc' || res?.skipped === 'cursor_regression' || !res?.workDone) {
    workerStatus.mode = 'idle';
    const skipSleepMs = Math.max(RETRO_POLL_INTERVAL_MS, RETRO_BACKLOG_MEDIUM_POLL_MS);
    logStatus(`work_done=0 batch_duration_ms=${workerStatus.lastRunDurationMs} estimated_backlog=no mode=idle skip_reason=${res?.skipped || 'none'} sleep_ms=${skipSleepMs}`);
    await sleep(skipSleepMs);
    return;
  }

  const backlogAfter = Number(res?.pendingAfter || 0);
  let nextSleepMs = getIdleSleepMs();
  let pace = RETRO_ALIGN_ENABLED ? `normal-aligned-${String(RETRO_ALIGN_MINUTE).padStart(2, '0')}` : 'normal';

  // Auto-drain mode: while backlog exists, keep near-term ticks (no inner loop).
  if (backlogAfter > 0) {
    nextSleepMs = RETRO_DRAIN_POLL_MS;
    pace = 'drain';
  }

  if (backlogAfter > RETRO_BACKLOG_THRESHOLD_HIGH) {
    nextSleepMs = RETRO_BACKLOG_FAST_POLL_MS;
    pace = 'fast';
  } else if (backlogAfter > RETRO_BACKLOG_THRESHOLD_MEDIUM) {
    nextSleepMs = Math.min(RETRO_BACKLOG_MEDIUM_POLL_MS, RETRO_DRAIN_POLL_MS);
    pace = 'medium';
  }

  if (workerStatus.lastRunDurationMs > RETRO_SLOW_TICK_THRESHOLD_MS) {
    nextSleepMs = Math.max(nextSleepMs, RETRO_DRAIN_POLL_MS);
    pace = `${pace}+slowguard`;
  }

  const backlogState = backlogAfter > 0 ? 'yes' : 'no';
  const iocLabel = res.iocCompleted ? 'ioc_complete' : 'ioc_page';
  logStatus(`work_done=1 ${iocLabel} batch_duration_ms=${workerStatus.lastRunDurationMs} estimated_backlog=${backlogState} pace=${pace} sleep_ms=${nextSleepMs}`);
  await sleep(nextSleepMs);
}

async function bootstrap() {
  await ensureIocCorrelationAssets();
  await maybeSyncIocLookup(true);
  console.log(`[ioc-retro] started adaptive=1 mode=single-pass+ioc-pagination retro_interval_s=${RETRO_SCAN_INTERVAL_SECONDS} align_enabled=${RETRO_ALIGN_ENABLED ? 1 : 0} align_minute=${RETRO_ALIGN_MINUTE} poll_ms=${RETRO_POLL_INTERVAL_MS} drain_poll_ms=${RETRO_DRAIN_POLL_MS} backlog_fast_poll_ms=${RETRO_BACKLOG_FAST_POLL_MS} backlog_medium_poll_ms=${RETRO_BACKLOG_MEDIUM_POLL_MS} backlog_high=${RETRO_BACKLOG_THRESHOLD_HIGH} backlog_medium=${RETRO_BACKLOG_THRESHOLD_MEDIUM} slow_tick_threshold_ms=${RETRO_SLOW_TICK_THRESHOLD_MS} lookback_d=${RETRO_LOOKBACK_DAYS} new_ioc_window_h=${RETRO_NEW_IOC_WINDOW_HOURS} (log_only) batch=${RETRO_BATCH_SIZE}`);

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
