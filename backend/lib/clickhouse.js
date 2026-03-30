import { createClient } from '@clickhouse/client';

const clickhouseUrl = process.env.CLICKHOUSE_URL || 'http://demo-clickhouse:8123';
const clickhouseDb = process.env.CLICKHOUSE_DB || 'default';
const clickhouseUser = process.env.CLICKHOUSE_USER || 'default';
const clickhousePassword = process.env.CLICKHOUSE_PASSWORD || '';

export const clickhouse = createClient({
  host: clickhouseUrl,
  username: clickhouseUser,
  password: clickhousePassword,
  database: clickhouseDb,
  clickhouse_settings: {
    async_insert: 1,
    wait_for_async_insert: 0
  }
});

function withTag(sql, tag) {
  if (!tag) return sql;
  return `/* ${tag} */\n${sql}`;
}

export async function command(sql, opts = {}) {
  const { logTag, settings } = opts;
  await clickhouse.command({ query: withTag(sql, logTag), clickhouse_settings: settings });
}

export async function insertLogs(batch, opts = {}) {
  if (!Array.isArray(batch) || batch.length === 0) return { inserted: 0 };
  const { queryId, logTag } = opts;
  await clickhouse.insert({
    table: 'syslog_logs',
    values: batch,
    format: 'JSONEachRow',
    query_id: queryId,
    clickhouse_settings: logTag ? { log_comment: logTag } : undefined
  });
  return { inserted: batch.length };
}

export async function insertObservables(batch, opts = {}) {
  if (!Array.isArray(batch) || batch.length === 0) return { inserted: 0 };
  const { queryId, logTag } = opts;
  await clickhouse.insert({
    table: 'syslog_observables',
    values: batch,
    format: 'JSONEachRow',
    query_id: queryId,
    clickhouse_settings: logTag ? { log_comment: logTag } : undefined
  });
  return { inserted: batch.length };
}

export async function query(sql, opts = {}) {
  const { queryId, logTag, settings } = opts;
  const rs = await clickhouse.query({
    query: withTag(sql, logTag),
    format: 'JSONEachRow',
    query_id: queryId,
    clickhouse_settings: settings
  });
  return rs.json();
}

export async function pingClickhouse() {
  return clickhouse.ping();
}

export async function ensureSyslogTable() {
  await command(`
    CREATE TABLE IF NOT EXISTS syslog_logs (
      ts DateTime,
      ingest_time DateTime DEFAULT now(),
      source String,
      host String,
      program String,
      severity String,
      facility String,
      message String,
      raw String,
      parser_source LowCardinality(String) DEFAULT 'unknown',
      parsed_ip Nullable(String),
      parsed_query Nullable(String),
      parsed_ip_private Nullable(Bool),
      ioc_ip Nullable(String),
      ioc_query Nullable(String),
      merged_observables String DEFAULT '[]'
    )
    ENGINE = MergeTree
    PARTITION BY toYYYYMMDD(ts)
    ORDER BY (ts, host)
    TTL ts + INTERVAL 30 DAY
  `);

  await command(`
    CREATE TABLE IF NOT EXISTS syslog_observables (
      ts DateTime,
      source LowCardinality(String),
      host LowCardinality(String),
      observable String,
      observable_type LowCardinality(String),
      raw_row_hash String
    )
    ENGINE = MergeTree
    PARTITION BY toYYYYMMDD(ts)
    ORDER BY (observable, observable_type, ts, raw_row_hash)
    TTL ts + INTERVAL 30 DAY
  `);

  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS ingest_time DateTime DEFAULT now()`);
  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parser_source LowCardinality(String) DEFAULT 'unknown'`);
  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parsed_ip Nullable(String)`);
  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parsed_query Nullable(String)`);
  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parsed_ip_private Nullable(Bool)`);
  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS ioc_ip Nullable(String)`);
  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS ioc_query Nullable(String)`);
  await command(`ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS merged_observables String DEFAULT '[]'`);
  await command(`ALTER TABLE syslog_logs DROP COLUMN IF EXISTS parsed_src_ip`);
  await command(`ALTER TABLE syslog_logs DROP COLUMN IF EXISTS parsed_src_ip_private`);
}

export async function ensureIocCorrelationAssets() {
  await command(`DROP DICTIONARY IF EXISTS default.ioc_domain_dict`);
  await command(`DROP DICTIONARY IF EXISTS default.ioc_ip_dict`);

  await command(`
    CREATE TABLE IF NOT EXISTS ioc_lookup (
      observable String,
      observable_type LowCardinality(String),
      confidence Int32,
      source_name String,
      updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY (observable, observable_type)
    SETTINGS index_granularity = 8192
  `);

  await command(`
    CREATE TABLE IF NOT EXISTS ioc_lookup_sync_state (
      worker_name String,
      last_sync_ts DateTime64(3),
      last_sync_id UInt64,
      updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY worker_name
  `);

  await command(`
    CREATE TABLE IF NOT EXISTS ioc_retro_state (
      worker_name String,
      last_processed_ts DateTime64(3),
      last_processed_row_hash String,
      updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY worker_name
  `);

  // Retro worker v2: IOC stream cursor + per-IOC match pagination (no OFFSET).
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_observable String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_observable_type String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_source_name String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_cursor_ts DateTime DEFAULT toDateTime(0)`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_cursor_raw_hash String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_ioc_updated_at DateTime64(3) DEFAULT toDateTime64('1970-01-01 00:00:00.000', 3)`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_ioc_confidence Int32 DEFAULT 0`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_ioc_row_hash String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS last_run_duration_ms Int32 DEFAULT 0`);
  // Window-bulk retro state (v3)
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS chunk_active UInt8 DEFAULT 0`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS chunk_end_ts DateTime64(3) DEFAULT toDateTime64('1970-01-01 00:00:00.000', 3)`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS chunk_end_row_hash String DEFAULT '0'`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS chunk_ioc_count UInt32 DEFAULT 0`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS chunk_rows_processed UInt64 DEFAULT 0`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_cursor_observable String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_cursor_observable_type String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS match_cursor_source_name String DEFAULT ''`);
}

function confidenceToInt(v) {
  const s = String(v || '').toLowerCase();
  if (s === 'high') return 90;
  if (s === 'medium') return 60;
  if (s === 'low') return 30;
  return 50;
}

export async function syncIocLookupFromPostgres(opts = {}) {
  const workerName = opts.workerName || 'ioc-correlation-sync-v1';
  const batchSize = Math.max(Number(opts.batchSize || 20000), 1000);

  const st = await query(`
    SELECT last_sync_ts, last_sync_id
    FROM ioc_lookup_sync_state
    WHERE worker_name = '${workerName.replace(/'/g, "''")}'
    ORDER BY updated_at DESC
    LIMIT 1
  `);

  const lastId = Number(st?.[0]?.last_sync_id || 0);

  // IMPORTANT: Cursor by monotonic id only.
  // Using (created_at, id) can miss rows committed later with older created_at
  // (e.g. long-running transactions/imports with clock_timestamp() semantics).
  const delta = await query(`
    SELECT
      toUInt64(id) AS id,
      lower(observable) AS observable,
      if(observable_type = 'hostname', 'domain', observable_type) AS observable_type,
      source_name,
      confidence,
      toDateTime64(created_at, 3) AS created_at
    FROM postgresql('db:5432', 'demo', 'ioc_items', 'demo', 'demo123')
    WHERE observable IS NOT NULL
      AND observable != ''
      AND observable_type IN ('domain', 'hostname', 'url', 'ip', 'sha256')
      AND toUInt64(id) > ${lastId}
    ORDER BY id
    LIMIT ${batchSize}
  `, { logTag: 'ioc-lookup.sync-incremental' });

  if (!delta.length) {
    return { changed: false, fetched: 0 };
  }

  const agg = new Map();
  for (const r of delta) {
    const key = `${r.observable}|${r.observable_type}`;
    const conf = confidenceToInt(r.confidence);
    const created = String(r.created_at || '1970-01-01 00:00:00.000');
    const prev = agg.get(key);
    if (!prev || conf > prev.confidence || created > prev.updated_at) {
      agg.set(key, {
        observable: r.observable,
        observable_type: r.observable_type,
        confidence: conf,
        source_name: r.source_name || 'unknown',
        updated_at: created
      });
    }
  }

  await clickhouse.insert({ table: 'ioc_lookup', values: Array.from(agg.values()), format: 'JSONEachRow' });

  const last = delta[delta.length - 1];
  await clickhouse.insert({
    table: 'ioc_lookup_sync_state',
    values: [{
      worker_name: workerName,
      last_sync_ts: String(last.created_at),
      last_sync_id: String(last.id),
      updated_at: new Date().toISOString().replace('T', ' ').replace('Z', '')
    }],
    format: 'JSONEachRow'
  });

  return {
    changed: true,
    fetched: delta.length,
    written: agg.size,
    last_sync_ts: String(last.created_at),
    last_sync_id: Number(last.id)
  };
}
