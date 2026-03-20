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

export async function insertLogs(batch) {
  if (!Array.isArray(batch) || batch.length === 0) return { inserted: 0 };
  await clickhouse.insert({
    table: 'syslog_logs',
    values: batch,
    format: 'JSONEachRow'
  });
  return { inserted: batch.length };
}

export async function query(sql) {
  const rs = await clickhouse.query({ query: sql, format: 'JSONEachRow' });
  return rs.json();
}

export async function pingClickhouse() {
  return clickhouse.ping();
}

export async function ensureSyslogTable() {
  await clickhouse.command({
    query: `
      CREATE TABLE IF NOT EXISTS syslog_logs (
        ts DateTime,
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
        ioc_query Nullable(String)
      )
      ENGINE = MergeTree
      PARTITION BY toYYYYMMDD(ts)
      ORDER BY (ts, host)
      TTL ts + INTERVAL 30 DAY
    `
  });

  await clickhouse.command({ query: `ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parser_source LowCardinality(String) DEFAULT 'unknown'` });
  await clickhouse.command({ query: `ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parsed_ip Nullable(String)` });
  await clickhouse.command({ query: `ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parsed_query Nullable(String)` });
  await clickhouse.command({ query: `ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS parsed_ip_private Nullable(Bool)` });
  await clickhouse.command({ query: `ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS ioc_ip Nullable(String)` });
  await clickhouse.command({ query: `ALTER TABLE syslog_logs ADD COLUMN IF NOT EXISTS ioc_query Nullable(String)` });
  await clickhouse.command({ query: `ALTER TABLE syslog_logs DROP COLUMN IF EXISTS parsed_src_ip` });
  await clickhouse.command({ query: `ALTER TABLE syslog_logs DROP COLUMN IF EXISTS parsed_src_ip_private` });
}

export async function ensureIocCorrelationAssets() {
  await clickhouse.command({ query: `DROP DICTIONARY IF EXISTS default.ioc_domain_dict` });
  await clickhouse.command({ query: `DROP DICTIONARY IF EXISTS default.ioc_ip_dict` });

  await clickhouse.command({
    query: `
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
    `
  });
}

export async function syncIocLookupFromPostgres() {
  await clickhouse.command({ query: `TRUNCATE TABLE IF EXISTS ioc_lookup` });
  await clickhouse.command({
    query: `
      INSERT INTO ioc_lookup (observable, observable_type, confidence, source_name)
      SELECT
        lower(observable) AS observable,
        if(observable_type = 'hostname', 'domain', observable_type) AS observable_type,
        max(multiIf(lower(coalesce(confidence, '')) = 'high', 90,
                    lower(coalesce(confidence, '')) = 'medium', 60,
                    lower(coalesce(confidence, '')) = 'low', 30,
                    50)) AS confidence,
        any(source_name) AS source_name
      FROM postgresql('db:5432', 'demo', 'ioc_items', 'demo', 'demo123')
      WHERE observable IS NOT NULL
        AND observable != ''
        AND observable_type IN ('domain', 'hostname', 'url', 'ip')
      GROUP BY observable, observable_type
    `
  });
}
