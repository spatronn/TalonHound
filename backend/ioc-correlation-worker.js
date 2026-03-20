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

const WORKER_NAME = process.env.IOC_CORRELATION_WORKER_NAME || 'clickhouse-ioc-correlation-v1';
const POLL_INTERVAL_MS = Math.max(Number(process.env.IOC_CORRELATION_POLL_INTERVAL_MS || 3000), 500);
const BATCH_SIZE = Math.max(Number(process.env.IOC_CORRELATION_BATCH_SIZE || 5000), 100);
const MAX_BATCHES_PER_TICK = Math.max(Number(process.env.IOC_CORRELATION_MAX_BATCHES_PER_TICK || 5), 1);
const DEDUP_WINDOW_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_DEDUP_WINDOW_SECONDS || 300), 60);
const IOC_LOOKUP_SYNC_INTERVAL_SECONDS = Math.max(Number(process.env.IOC_LOOKUP_SYNC_INTERVAL_SECONDS || 1800), 60);
const CH_MAX_THREADS = Math.max(Number(process.env.IOC_CORRELATION_CH_MAX_THREADS || 4), 1);
const CH_MAX_EXECUTION_TIME_SECONDS = Math.max(Number(process.env.IOC_CORRELATION_CH_MAX_EXECUTION_TIME_SECONDS || 20), 5);

let stopping = false;
let lastIocLookupSyncAtMs = 0;

function esc(value) {
  return String(value || '').replace(/'/g, "''");
}

function formatChDateTime(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return '1970-01-01 00:00:00';
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

function floorToBucket(tsIso, seconds) {
  const d = new Date(tsIso);
  const ms = d.getTime();
  const bucketMs = seconds * 1000;
  const floored = Math.floor(ms / bucketMs) * bucketMs;
  return new Date(floored).toISOString();
}

function dedupKeyOf(row) {
  // Stable key per source + ioc type/value + parser context + host.
  return [
    row.match_type || 'unknown',
    row.matched_ioc || '',
    row.host || '',
    row.source || '',
    row.parser_source || 'unknown'
  ].join('|');
}

async function getOrInitState(client) {
  const q = await client.query(
    `SELECT worker_name, last_ts, last_row_hash
     FROM ioc_correlation_state
     WHERE worker_name = $1`,
    [WORKER_NAME]
  );

  if (q.rowCount) return q.rows[0];

  const init = await client.query(
    `INSERT INTO ioc_correlation_state (worker_name, last_ts, last_row_hash, batch_size)
     VALUES ($1, to_timestamp(0), 0, $2)
     RETURNING worker_name, last_ts, last_row_hash`,
    [WORKER_NAME, BATCH_SIZE]
  );
  return init.rows[0];
}

async function saveState(client, lastTs, lastRowHash) {
  await client.query(
    `UPDATE ioc_correlation_state
     SET last_ts = $2,
         last_row_hash = $3,
         batch_size = $4,
         updated_at = NOW()
     WHERE worker_name = $1`,
    [WORKER_NAME, lastTs, String(lastRowHash), BATCH_SIZE]
  );
}

function buildScanQuery(lastTs, lastRowHash, limit) {
  const ts = esc(formatChDateTime(lastTs));
  const hash = String(lastRowHash || '0').replace(/[^0-9]/g, '') || '0';
  const lim = Number(limit || BATCH_SIZE);

  return `
    WITH src AS (
      SELECT
        ts,
        source,
        host,
        parser_source,
        parsed_ip,
        parsed_query,
        ioc_ip,
        ioc_query,
        toString(cityHash64(concat(toString(ts), '|', coalesce(source, ''), '|', coalesce(raw, '')))) AS row_hash
      FROM default.syslog_logs
      WHERE (ts > toDateTime('${ts}')
         OR (ts = toDateTime('${ts}')
             AND cityHash64(concat(toString(ts), '|', coalesce(source, ''), '|', coalesce(raw, ''))) > toUInt64('${hash}')))
        AND (notEmpty(ifNull(ioc_query, '')) OR notEmpty(ifNull(ioc_ip, '')))
      ORDER BY ts, toUInt64(row_hash)
      LIMIT ${lim}
    )
    SELECT
      ts,
      source,
      host,
      parser_source,
      parsed_ip,
      parsed_query,
      ioc_ip,
      ioc_query,
      row_hash,
      lower(ifNull(s.ioc_query, '')) AS norm_query,
      ifNull(s.ioc_ip, '') AS norm_ip,
      (dq.observable != '') AS has_domain_match,
      (ipq.observable != '') AS has_ip_match,
      toUInt64(0) AS domain_ioc_item_id,
      dq.source_name AS domain_source_name,
      toString(dq.confidence) AS domain_confidence,
      toUInt64(0) AS ip_ioc_item_id,
      ipq.source_name AS ip_source_name,
      toString(ipq.confidence) AS ip_confidence
    FROM src s
    LEFT JOIN ioc_lookup dq
      ON dq.observable = lower(ifNull(s.ioc_query, ''))
     AND dq.observable_type IN ('domain', 'url')
    LEFT JOIN ioc_lookup ipq
      ON ipq.observable = ifNull(s.ioc_ip, '')
     AND ipq.observable_type = 'ip'
    SETTINGS max_threads = ${CH_MAX_THREADS}, max_execution_time = ${CH_MAX_EXECUTION_TIME_SECONDS}
  `;
}

function toMatchRows(chRows) {
  const out = [];
  for (const r of chRows) {
    if (r.has_domain_match) {
      out.push({
        event_time: r.ts,
        host: r.host,
        source: r.source,
        parser_source: r.parser_source,
        destination_ip: r.parsed_ip || null,
        protocol: 'dns',
        matched_ioc: r.norm_query,
        ioc_type: 'domain',
        ioc_item_id: null,
        source_name: r.domain_source_name || null,
        confidence: r.domain_confidence || null,
        match_context: {
          parsed_query: r.parsed_query || null,
          parsed_ip: r.parsed_ip || null,
          ioc_query: r.ioc_query || null
        }
      });
    }

    if (r.has_ip_match) {
      out.push({
        event_time: r.ts,
        host: r.host,
        source: r.source,
        parser_source: r.parser_source,
        destination_ip: r.parsed_ip || null,
        protocol: 'dns',
        matched_ioc: r.norm_ip,
        ioc_type: 'ip',
        ioc_item_id: null,
        source_name: r.ip_source_name || null,
        confidence: r.ip_confidence || null,
        match_context: {
          parsed_query: r.parsed_query || null,
          parsed_ip: r.parsed_ip || null,
          ioc_ip: r.ioc_ip || null
        }
      });
    }
  }
  return out;
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
      r.event_time,
      r.host || null,
      null, // process_name
      r.destination_ip || null,
      null, // destination_port
      r.protocol || null,
      r.matched_ioc,
      r.source_name || null,
      r.confidence || null,
      r.ioc_type,
      r.ioc_item_id,
      r.parser_source || null,
      r.source || null,
      JSON.stringify(r.match_context || {}),
      dedupKey,
      bucketStart,
      r.event_time // last_seen_at seed
    );
  }

  const sql = `
    INSERT INTO ioc_match_events (
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
      match_context = COALESCE(EXCLUDED.match_context, ioc_match_events.match_context)
  `;

  await client.query(sql, params);
  return rows.length;
}

async function runBatch() {
  const startedAtMs = Date.now();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const state = await getOrInitState(client);
    const query = buildScanQuery(state.last_ts, state.last_row_hash, BATCH_SIZE);
    const scanned = await clickhouseQuery(query);

    if (!scanned.length) {
      await client.query('COMMIT');
      return { scanned: 0, matched: 0, inserted: 0, duration_ms: Date.now() - startedAtMs };
    }

    const matchedRows = toMatchRows(scanned);
    const inserted = await insertMatchEvents(client, matchedRows);

    const last = scanned[scanned.length - 1];
    await saveState(client, last.ts, last.row_hash);
    await client.query('COMMIT');

    return {
      scanned: scanned.length,
      matched: matchedRows.length,
      inserted,
      last_ts: last.ts,
      last_row_hash: last.row_hash,
      duration_ms: Date.now() - startedAtMs
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function tick() {
  let totalScanned = 0;
  let totalMatched = 0;
  let totalInserted = 0;
  let totalDurationMs = 0;

  for (let i = 0; i < MAX_BATCHES_PER_TICK; i += 1) {
    const result = await runBatch();
    totalScanned += result.scanned;
    totalMatched += result.matched;
    totalInserted += result.inserted;
    totalDurationMs += Number(result.duration_ms || 0);
    if (result.scanned < BATCH_SIZE) break;
  }

  if (totalScanned > 0) {
    console.log(`[ioc-correlation] scanned=${totalScanned} matched=${totalMatched} inserted_or_upserted=${totalInserted} duration_ms=${totalDurationMs}`);
  }
}


async function maybeSyncIocLookup(force = false) {
  const now = Date.now();
  if (!force && (now - lastIocLookupSyncAtMs) < (IOC_LOOKUP_SYNC_INTERVAL_SECONDS * 1000)) return false;
  await syncIocLookupFromPostgres();
  lastIocLookupSyncAtMs = now;
  console.log(`[ioc-correlation] ioc_lookup sync completed interval_s=${IOC_LOOKUP_SYNC_INTERVAL_SECONDS}`);
  return true;
}


async function bootstrap() {
  await ensureIocCorrelationAssets();
  await maybeSyncIocLookup(true);
  console.log(`[ioc-correlation] started worker=${WORKER_NAME} poll_ms=${POLL_INTERVAL_MS} batch=${BATCH_SIZE} dedup_window_s=${DEDUP_WINDOW_SECONDS}`);

  while (!stopping) {
    try {
      await maybeSyncIocLookup(false);
      await tick();
    } catch (err) {
      console.error('[ioc-correlation] tick failed', err?.message || err);
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

process.on('SIGINT', async () => {
  stopping = true;
  await pool.end();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  stopping = true;
  await pool.end();
  process.exit(0);
});

bootstrap().catch(async (err) => {
  console.error('[ioc-correlation] bootstrap failed', err?.message || err);
  await pool.end();
  process.exit(1);
});
