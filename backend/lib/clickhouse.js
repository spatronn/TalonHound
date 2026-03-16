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
        raw String
      )
      ENGINE = MergeTree
      PARTITION BY toYYYYMMDD(ts)
      ORDER BY (ts, host)
      TTL ts + INTERVAL 30 DAY
    `
  });
}
