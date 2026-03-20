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
  await clickhouse.command({ query: `/* ioc-assets.drop-legacy-dicts */ DROP DICTIONARY IF EXISTS default.ioc_domain_dict` });
  await clickhouse.command({ query: `/* ioc-assets.drop-legacy-dicts */ DROP DICTIONARY IF EXISTS default.ioc_ip_dict` });

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
  const changed = await query(`
    SELECT
      (
        SELECT toDateTime64(max(created_at), 3)
        FROM postgresql('db:5432', 'demo', 'ioc_items', 'demo', 'demo123')
      ) AS pg_last_update,
      (
        SELECT toDateTime64(max(updated_at), 3)
        FROM default.ioc_lookup
      ) AS ch_last_update
  `, { logTag: 'ioc-lookup.sync-change-check' });
  const pgLast = changed?.[0]?.pg_last_update || null;
  const chLast = changed?.[0]?.ch_last_update || null;
  if (pgLast && chLast && String(pgLast) === String(chLast)) {
    return { changed: false, pg_last_update: pgLast, ch_last_update: chLast };
  }

  await clickhouse.command({ query: `/* ioc-lookup.sync-truncate */ TRUNCATE TABLE IF EXISTS ioc_lookup` });
  await clickhouse.command({
    query: withTag(`
      INSERT INTO ioc_lookup (observable, observable_type, confidence, source_name, updated_at)
      SELECT
        lower(observable) AS observable,
        if(observable_type = 'hostname', 'domain', observable_type) AS observable_type,
        max(multiIf(lower(coalesce(confidence, '')) = 'high', 90,
                    lower(coalesce(confidence, '')) = 'medium', 60,
                    lower(coalesce(confidence, '')) = 'low', 30,
                    50)) AS confidence,
        any(source_name) AS source_name,
        toDateTime64(max(created_at), 3) AS updated_at
      FROM postgresql('db:5432', 'demo', 'ioc_items', 'demo', 'demo123')
      WHERE observable IS NOT NULL
        AND observable != ''
        AND observable_type IN ('domain', 'hostname', 'url', 'ip')
      GROUP BY observable, observable_type
    `, 'ioc-lookup.sync-full-refresh')
  });
  return { changed: true, pg_last_update: pgLast, ch_last_update: chLast };
}
