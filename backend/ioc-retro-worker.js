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

const POLL_INTERVAL_MS = Math.max(Number(process.env.IOC_RETRO_POLL_INTERVAL_MS || 10000), 1000);
const RETRO_SCAN_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_RETRO_SCAN_INTERVAL_SECONDS || 3600), 300);
const RETRO_LOOKBACK_DAYS = Math.max(Number(process.env.IOC_RETRO_LOOKBACK_DAYS || 30), 1);
const RETRO_BATCH_SIZE = Math.max(Number(process.env.IOC_RETRO_BATCH_SIZE || 20000), 1000);
const IOC_LOOKUP_SYNC_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_LOOKUP_SYNC_INTERVAL_SECONDS || 1800), 60);
const DEDUP_WINDOW_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_DEDUP_WINDOW_SECONDS || 300), 60);
const RETRO_CH_MAX_THREADS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_THREADS || 2), 1);
const RETRO_CH_MAX_EXECUTION_TIME_SECONDS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_EXECUTION_TIME_SECONDS || 25), 5);
const RETRO_NEW_IOC_WINDOW_HOURS = Math.max(Number(process.env.IOC_RETRO_NEW_IOC_WINDOW_HOURS || 2), 1);
const RETRO_MAX_NEW_IOCS = Math.max(Number(process.env.IOC_RETRO_MAX_NEW_IOCS || 5000), 100);
const IOC_LOOKUP_SYNC_ENABLED = process.env.IOC_LOOKUP_SYNC_ENABLED === '1' || process.env.IOC_LOOKUP_SYNC_ENABLED === 'true';

let stopping = false;
let lastIocLookupSyncAtMs = 0;
let lastRetroRunAtMs = 0;

function makeQueryId(name) {
  return `ioc-retro:${name}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}`;
}


async function loadRetroState() {
  const rows = await clickhouseQuery(`
    SELECT last_processed_ts, last_processed_row_hash
    FROM default.ioc_retro_state
    WHERE worker_name = 'ioc-retro-v1'
    ORDER BY updated_at DESC
    LIMIT 1
  `, { queryId: makeQueryId('retro-state-load'), logTag: 'ioc-retro.state-load' });
  return {
    last_processed_ts: rows?.[0]?.last_processed_ts || '1970-01-01 00:00:00.000',
    last_processed_row_hash: rows?.[0]?.last_processed_row_hash || '0'
  };
}

async function saveRetroState(ts, hash) {
  await clickhouseCommand(`
    INSERT INTO default.ioc_retro_state (worker_name, last_processed_ts, last_processed_row_hash, updated_at)
    VALUES ('ioc-retro-v1', toDateTime64('${String(ts).replace('T',' ').replace('Z','')}', 3), '${String(hash)}', now64(3))
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

async function runRetroactivePass() {
  const now = Date.now();
  if ((now - lastRetroRunAtMs) < (RETRO_SCAN_INTERVAL_SECONDS * 1000)) return { ran: false, inserted: 0 };

  const st = await loadRetroState();
  const lastTs = String(st.last_processed_ts || '1970-01-01 00:00:00.000').replace('T', ' ').replace('Z', '');
  const lastHash = String(st.last_processed_row_hash || '0').replace(/[^0-9]/g, '') || '0';

  const cursorRows = await clickhouseQuery(`
    WITH new_iocs AS (
      SELECT
        observable,
        observable_type,
        confidence,
        source_name,
        updated_at,
        toString(cityHash64(concat(observable, '|', observable_type, '|', source_name))) AS row_hash
      FROM default.ioc_lookup
      WHERE (
        updated_at > toDateTime64('${lastTs}', 3)
        OR (updated_at = toDateTime64('${lastTs}', 3)
            AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${lastHash}'))
      )
      ORDER BY updated_at, toUInt64(row_hash)
      LIMIT ${RETRO_MAX_NEW_IOCS}
    )
    SELECT updated_at, row_hash
    FROM new_iocs
    ORDER BY updated_at DESC, toUInt64(row_hash) DESC
    LIMIT 1
  `, { queryId: makeQueryId('retro-cursor-probe'), logTag: 'ioc-retro.cursor-probe' });

  if (!cursorRows.length) {
    lastRetroRunAtMs = now;
    return { ran: true, inserted: 0, skipped: 'no_new_ioc' };
  }

  const rows = await clickhouseQuery(`
    WITH new_iocs AS (
      SELECT
        observable,
        observable_type,
        confidence,
        source_name,
        updated_at,
        toString(cityHash64(concat(observable, '|', observable_type, '|', source_name))) AS row_hash
      FROM default.ioc_lookup
      WHERE (
        updated_at > toDateTime64('${lastTs}', 3)
        OR (updated_at = toDateTime64('${lastTs}', 3)
            AND cityHash64(concat(observable, '|', observable_type, '|', source_name)) > toUInt64('${lastHash}'))
      )
      ORDER BY updated_at, toUInt64(row_hash)
      LIMIT ${RETRO_MAX_NEW_IOCS}
    )
    SELECT
      so.ts,
      so.source,
      so.host,
      'syslog_observables' AS parser_source,
      CAST(NULL, 'Nullable(String)') AS parsed_ip,
      CAST(NULL, 'Nullable(String)') AS parsed_query,
      ni.observable AS matched_ioc,
      ni.observable_type AS ioc_type,
      ni.confidence AS confidence,
      ni.source_name AS source_name,
      ni.updated_at AS ioc_updated_at
    FROM default.syslog_observables so
    ANY INNER JOIN new_iocs ni
      ON ni.observable = so.observable
     AND ni.observable_type = so.observable_type
    WHERE so.ts >= now() - INTERVAL ${RETRO_LOOKBACK_DAYS} DAY
    ORDER BY so.ts DESC
    LIMIT ${RETRO_BATCH_SIZE}
    SETTINGS max_threads = ${RETRO_CH_MAX_THREADS}, max_execution_time = ${RETRO_CH_MAX_EXECUTION_TIME_SECONDS}
  `, { queryId: makeQueryId('retro-pass'), logTag: 'ioc-retro.retro-pass' });

  const cursorTs = String(cursorRows[0].updated_at || lastTs);
  const cursorHash = String(cursorRows[0].row_hash || lastHash);
  await saveRetroState(cursorTs, cursorHash);

  if (!rows.length) {
    lastRetroRunAtMs = now;
    return { ran: true, inserted: 0 };
  }

  const mapped = rows.map((r) => {
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
  });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const inserted = await insertMatchEvents(client, mapped);
    await client.query('COMMIT');
    lastRetroRunAtMs = now;
    console.log(`[ioc-retro] scanned=${rows.length} inserted_or_upserted=${inserted} cursor_ts=${cursorTs}`);
    return { ran: true, inserted };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}


async function bootstrap() {
  await ensureIocCorrelationAssets();
  await maybeSyncIocLookup(true);
  console.log(`[ioc-retro] started poll_ms=${POLL_INTERVAL_MS} retro_interval_s=${RETRO_SCAN_INTERVAL_SECONDS} lookback_d=${RETRO_LOOKBACK_DAYS} new_ioc_window_h=${RETRO_NEW_IOC_WINDOW_HOURS} max_new_iocs=${RETRO_MAX_NEW_IOCS} batch=${RETRO_BATCH_SIZE}`);

  while (!stopping) {
    try {
      await maybeSyncIocLookup(false);
      await runRetroactivePass();
    } catch (err) {
      console.error('[ioc-retro] tick failed', err?.message || err);
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

process.on('SIGINT', async () => { stopping = true; await pool.end(); process.exit(0); });
process.on('SIGTERM', async () => { stopping = true; await pool.end(); process.exit(0); });

bootstrap().catch(async (err) => {
  console.error('[ioc-retro] bootstrap failed', err?.message || err);
  await pool.end();
  process.exit(1);
});
