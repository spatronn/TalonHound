import { createClient } from '@clickhouse/client';

const clickhouseUrl = process.env.CLICKHOUSE_URL || 'http://demo-clickhouse:8123';
const clickhouseDb = process.env.CLICKHOUSE_DB || 'default';
const clickhouseUser = process.env.CLICKHOUSE_USER || 'default';
const clickhousePassword = process.env.CLICKHOUSE_PASSWORD || '';
const IOC_DICT_LIFETIME_MIN = Math.max(Number(process.env.IOC_DICT_LIFETIME_MIN || 300), 60);
const IOC_DICT_LIFETIME_MAX = Math.max(Number(process.env.IOC_DICT_LIFETIME_MAX || 600), IOC_DICT_LIFETIME_MIN);
const IOC_DICT_FORCE_RELOAD_ON_BOOT = process.env.IOC_DICT_FORCE_RELOAD_ON_BOOT === '1' || process.env.IOC_DICT_FORCE_RELOAD_ON_BOOT === 'true';

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

  // Forward-compatible schema evolution on existing tables.
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
  // Domain dictionary (query/domain observables)
  await clickhouse.command({
    query: `
      CREATE DICTIONARY IF NOT EXISTS default.ioc_domain_dict (
        observable String,
        ioc_item_id UInt64,
        source_name String,
        confidence String
      )
      PRIMARY KEY observable
      SOURCE(POSTGRESQL(
        HOST 'db'
        PORT 5432
        USER 'demo'
        PASSWORD 'demo123'
        DB 'demo'
        QUERY 'SELECT lower(observable) AS observable, id AS ioc_item_id, source_name, confidence FROM ioc_items WHERE observable_type IN (''domain'', ''hostname'', ''url'')'
      ))
      LAYOUT(HASHED())
      LIFETIME(MIN ${IOC_DICT_LIFETIME_MIN} MAX ${IOC_DICT_LIFETIME_MAX})
    `
  });

  // IP dictionary (public IP observables)
  await clickhouse.command({
    query: `
      CREATE DICTIONARY IF NOT EXISTS default.ioc_ip_dict (
        observable String,
        ioc_item_id UInt64,
        source_name String,
        confidence String
      )
      PRIMARY KEY observable
      SOURCE(POSTGRESQL(
        HOST 'db'
        PORT 5432
        USER 'demo'
        PASSWORD 'demo123'
        DB 'demo'
        QUERY 'SELECT observable, id AS ioc_item_id, source_name, confidence FROM ioc_items WHERE observable_type = ''ip'''
      ))
      LAYOUT(HASHED())
      LIFETIME(MIN ${IOC_DICT_LIFETIME_MIN} MAX ${IOC_DICT_LIFETIME_MAX})
    `
  });

  if (IOC_DICT_FORCE_RELOAD_ON_BOOT) {
    await clickhouse.command({ query: `SYSTEM RELOAD DICTIONARY default.ioc_domain_dict` });
    await clickhouse.command({ query: `SYSTEM RELOAD DICTIONARY default.ioc_ip_dict` });
  }
}
