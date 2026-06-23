import './ensure-db-password.js';
import './ensure-clickhouse-password.js';
import { createClient } from '@clickhouse/client';
import { normalizeObservable } from './observable-normalization.js';

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

  // Replay queries are ingest_time-cursor based; add aligned projection for lower scan CPU.
  await command(`
    ALTER TABLE syslog_logs
    ADD PROJECTION IF NOT EXISTS prj_ingest_cursor (
      SELECT
        ts, source, host, program, severity, facility, message, raw,
        parser_source, parsed_query, ioc_ip, ioc_query, parsed_ip, parsed_ip_private,
        ingest_time, merged_observables
      ORDER BY (ingest_time, ts, host)
    )
  `);
}

export async function ensureRelatedLogsEvidenceTable() {
  try {
    await command(`CREATE DATABASE IF NOT EXISTS security_evidence`);
    await command(`
      CREATE TABLE IF NOT EXISTS security_evidence.incident_related_logs (
        activity_id UUID,
        incident_id UInt64,
        match_event_id UInt64,
        evidence_hash String,
        log_ts DateTime64(3, 'UTC'),
        created_at DateTime64(3, 'UTC') DEFAULT now64(3),
        matched_ioc String,
        observable_type LowCardinality(String),
        log_host String,
        observed_host String,
        parser_source LowCardinality(String),
        source_type LowCardinality(String),
        raw_message_hash String,
        raw_message_sample String
      )
      ENGINE = ReplacingMergeTree(created_at)
      PARTITION BY toYYYYMM(log_ts)
      ORDER BY (activity_id, match_event_id, evidence_hash, log_ts)
    `);
  } catch (e) {
    console.error('[clickhouse] ensureRelatedLogsEvidenceTable failed (non-fatal)', e?.message || e);
  }
}

export async function ensureIocCorrelationAssets() {
  await ensureRelatedLogsEvidenceTable();
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
    CREATE TABLE IF NOT EXISTS ioc_lookup_by_updated (
      observable String,
      observable_type LowCardinality(String),
      confidence Int32,
      source_name String,
      updated_at DateTime64(3),
      row_hash UInt64 MATERIALIZED cityHash64(observable, observable_type, source_name)
    )
    ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY (updated_at, row_hash, observable, observable_type, source_name)
    SETTINGS index_granularity = 8192
  `);

  await command(`
    CREATE MATERIALIZED VIEW IF NOT EXISTS mv_ioc_lookup_to_by_updated
    TO ioc_lookup_by_updated
    AS
    SELECT observable, observable_type, confidence, source_name, updated_at
    FROM ioc_lookup
  `);

  await command(`
    CREATE TABLE IF NOT EXISTS ioc_lookup_sync_state (
      worker_name String,
      last_sync_ts DateTime64(3),
      last_sync_id UInt64,
      sync_cursors String DEFAULT '',
      updated_at DateTime64(3) DEFAULT now64(3)
    )
    ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY worker_name
  `);

  await command(`ALTER TABLE ioc_lookup_sync_state ADD COLUMN IF NOT EXISTS sync_cursors String DEFAULT ''`);

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
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS last_error_type String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS last_error_message String DEFAULT ''`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS last_error_at DateTime64(3) DEFAULT toDateTime64('1970-01-01 00:00:00.000', 3)`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS last_success_at DateTime64(3) DEFAULT toDateTime64('1970-01-01 00:00:00.000', 3)`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS last_chunk_size UInt32 DEFAULT 0`);
  await command(`ALTER TABLE default.ioc_retro_state ADD COLUMN IF NOT EXISTS last_chunk_retry_count UInt8 DEFAULT 0`);
}

function confidenceToInt(v) {
  const s = String(v || '').toLowerCase();
  if (s === 'high') return 90;
  if (s === 'medium') return 60;
  if (s === 'low') return 30;
  return 50;
}

function pgLiteralForPostgresqlEngine(value) {
  return String(value ?? '').replace(/'/g, "''");
}

export async function pushIocLookupTombstones(rows = []) {
  if (!Array.isArray(rows) || rows.length === 0) return { deleted: 0 };

  const normalized = rows
    .map((r) => ({
      observable: String(r?.observable || '').trim().toLowerCase(),
      observable_type: String(r?.observable_type || '').trim().toLowerCase(),
      source_name: String(r?.source_name || '').trim()
    }))
    .filter((r) => r.observable && r.observable_type && r.source_name);

  if (!normalized.length) return { deleted: 0 };

  const valuesSql = normalized
    .map((r) => `('${r.observable.replace(/'/g, "''")}', '${r.observable_type.replace(/'/g, "''")}', '${r.source_name.replace(/'/g, "''")}')`)
    .join(',');

  await command(`
    ALTER TABLE ioc_lookup
    DELETE WHERE (observable, observable_type, source_name) IN (${valuesSql})
  `, { logTag: 'ioc-lookup.tombstones' });

  return { deleted: normalized.length };
}

export { syncIocLookupFromPostgres } from './iocLookupSync.js';

/** Re-insert expired IOCs into ClickHouse lookup (reverse legacy tombstones). */
export async function backfillExpiredIocsToLookup(pgPool, opts = {}) {
  const batchSize = Math.max(Number(opts.batchSize || 5000), 100);
  if (!pgPool?.query) return { written: 0 };

  const { rows } = await pgPool.query(
    `SELECT DISTINCT ON (lower(i.observable), lower(i.observable_type), COALESCE(i.source_name, ''))
            lower(i.observable) AS observable,
            CASE WHEN i.observable_type = 'hostname' THEN 'domain' ELSE i.observable_type END AS observable_type,
            i.confidence,
            COALESCE(i.source_name, 'unknown') AS source_name,
            COALESCE(i.last_seen_log, i.last_seen_at, i.created_at) AS updated_at
     FROM ioc_items i
     WHERE COALESCE(i.status, 'active') = 'expired'
       AND i.observable IS NOT NULL
       AND i.observable != ''
       AND i.observable_type IN ('domain', 'hostname', 'url', 'ip', 'sha256')
     ORDER BY lower(i.observable), lower(i.observable_type), COALESCE(i.source_name, ''), i.created_at ASC
     LIMIT $1`,
    [batchSize]
  );

  if (!rows?.length) return { written: 0 };

  const values = rows.map((r) => {
    const observableType = String(r.observable_type || '').toLowerCase();
    const observable = observableType === 'url'
      ? normalizeObservable('url', String(r.observable || ''))
      : String(r.observable || '').toLowerCase();
    const updatedAt = r.updated_at instanceof Date
      ? r.updated_at.toISOString().replace('T', ' ').replace('Z', '')
      : String(r.updated_at || '').replace('T', ' ').replace('Z', '');
    return {
      observable,
      observable_type: observableType,
      confidence: confidenceToInt(r.confidence),
      source_name: r.source_name || 'unknown',
      updated_at: updatedAt
    };
  });

  await clickhouse.insert({ table: 'ioc_lookup', values, format: 'JSONEachRow' });
  return { written: values.length };
}
