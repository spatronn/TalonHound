import pg from 'pg';
import { ensureIocCorrelationAssets, syncIocLookupFromPostgres, query as clickhouseQuery } from './lib/clickhouse.js';

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
const RETRO_CH_MAX_THREADS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_THREADS || 4), 1);
const RETRO_CH_MAX_EXECUTION_TIME_SECONDS = Math.max(Number(process.env.IOC_RETRO_CH_MAX_EXECUTION_TIME_SECONDS || 25), 5);
const RETRO_NEW_IOC_WINDOW_HOURS = Math.max(Number(process.env.IOC_RETRO_NEW_IOC_WINDOW_HOURS || 2), 1);

let stopping = false;
let lastIocLookupSyncAtMs = 0;
let lastRetroRunAtMs = 0;

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
  const now = Date.now();
  if (!force && (now - lastIocLookupSyncAtMs) < (IOC_LOOKUP_SYNC_INTERVAL_SECONDS * 1000)) return false;
  await syncIocLookupFromPostgres();
  lastIocLookupSyncAtMs = now;
  console.log(`[ioc-retro] ioc_lookup sync completed interval_s=${IOC_LOOKUP_SYNC_INTERVAL_SECONDS}`);
  return true;
}

async function runRetroactivePass() {
  const now = Date.now();
  if ((now - lastRetroRunAtMs) < (RETRO_SCAN_INTERVAL_SECONDS * 1000)) return { ran: false, inserted: 0 };

  const rows = await clickhouseQuery(`
    WITH new_iocs AS (
      SELECT observable, observable_type, confidence, source_name
      FROM default.ioc_lookup
      WHERE updated_at >= now() - INTERVAL ${RETRO_NEW_IOC_WINDOW_HOURS} HOUR
    ), domain_matches AS (
      SELECT s.ts, s.source, s.host, s.parser_source, s.parsed_ip, s.parsed_query,
             ni.observable AS matched_ioc, ni.observable_type AS ioc_type,
             ni.confidence AS confidence, ni.source_name AS source_name
      FROM default.syslog_logs s
      ANY INNER JOIN new_iocs ni
        ON ni.observable = lower(ifNull(s.ioc_query, ''))
       AND ni.observable_type IN ('domain', 'url')
      WHERE s.ts >= now() - INTERVAL ${RETRO_LOOKBACK_DAYS} DAY
        AND notEmpty(ifNull(s.ioc_query, ''))
    ), ip_matches AS (
      SELECT s.ts, s.source, s.host, s.parser_source, s.parsed_ip, s.parsed_query,
             ni.observable AS matched_ioc, ni.observable_type AS ioc_type,
             ni.confidence AS confidence, ni.source_name AS source_name
      FROM default.syslog_logs s
      ANY INNER JOIN new_iocs ni
        ON ni.observable = ifNull(s.ioc_ip, '')
       AND ni.observable_type = 'ip'
      WHERE s.ts >= now() - INTERVAL ${RETRO_LOOKBACK_DAYS} DAY
        AND notEmpty(ifNull(s.ioc_ip, ''))
    )
    SELECT * FROM (
      SELECT * FROM domain_matches
      UNION ALL
      SELECT * FROM ip_matches
    )
    LIMIT ${RETRO_BATCH_SIZE}
    SETTINGS max_threads = ${RETRO_CH_MAX_THREADS}, max_execution_time = ${RETRO_CH_MAX_EXECUTION_TIME_SECONDS}
  `);

  if (!rows.length) {
    lastRetroRunAtMs = now;
    return { ran: true, inserted: 0 };
  }

  const mapped = rows.map((r) => ({
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
    match_context: { retroactive: true, parsed_query: r.parsed_query || null, parsed_ip: r.parsed_ip || null }
  }));

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const inserted = await insertMatchEvents(client, mapped);
    await client.query('COMMIT');
    lastRetroRunAtMs = now;
    console.log(`[ioc-retro] scanned=${rows.length} inserted_or_upserted=${inserted}`);
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
  console.log(`[ioc-retro] started poll_ms=${POLL_INTERVAL_MS} retro_interval_s=${RETRO_SCAN_INTERVAL_SECONDS} lookback_d=${RETRO_LOOKBACK_DAYS} new_ioc_window_h=${RETRO_NEW_IOC_WINDOW_HOURS} batch=${RETRO_BATCH_SIZE}`);

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
