import './lib/ensure-db-password.js';
import './lib/ensure-clickhouse-password.js';
import pg from 'pg';
import { query as clickhouseQuery } from './lib/clickhouse.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const LOOP_INTERVAL_MS = Math.max(Number(process.env.IOC_MATCH_COUNT_INTERVAL_MS || 60000), 10000);
const UPSERT_BATCH_SIZE = Math.max(Number(process.env.IOC_MATCH_COUNT_BATCH_SIZE || 2000), 500);

function toPgTs(v) {
  if (!v) return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

async function fetchAggregatesFromClickHouse() {
  const sql = `
    SELECT
      lowerUTF8(observable) AS observable_value,
      count() AS match_count,
      min(ts) AS first_seen_log,
      max(ts) AS last_seen_log
    FROM default.syslog_observables
    WHERE observable != ''
    GROUP BY observable_value
  `;

  const rows = await clickhouseQuery(sql, {
    logTag: 'ioc-match-count.aggregate',
    settings: {
      max_threads: Math.max(Number(process.env.IOC_MATCH_COUNT_CH_MAX_THREADS || 1), 1),
      max_execution_time: Math.max(Number(process.env.IOC_MATCH_COUNT_CH_MAX_EXECUTION_TIME_SECONDS || 30), 5)
    }
  });

  return (rows || []).map((r) => ({
    observable_value: String(r.observable_value || '').trim().toLowerCase(),
    match_count: Number(r.match_count || 0),
    first_seen_log: toPgTs(r.first_seen_log),
    last_seen_log: toPgTs(r.last_seen_log)
  })).filter((r) => r.observable_value);
}

async function upsertSnapshot(client, rows) {
  if (!rows.length) return;

  for (let i = 0; i < rows.length; i += UPSERT_BATCH_SIZE) {
    const chunk = rows.slice(i, i + UPSERT_BATCH_SIZE);
    const values = [];
    const params = [];

    for (let j = 0; j < chunk.length; j += 1) {
      const r = chunk[j];
      const base = j * 4;
      values.push(`($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, NOW())`);
      params.push(r.observable_value, r.match_count, r.first_seen_log, r.last_seen_log);
    }

    await client.query(
      `INSERT INTO ioc_match_count_snapshot (observable_value, match_count, first_seen_log, last_seen_log, updated_at)
       VALUES ${values.join(',')}
       ON CONFLICT (observable_value)
       DO UPDATE SET
         match_count = EXCLUDED.match_count,
         first_seen_log = EXCLUDED.first_seen_log,
         last_seen_log = EXCLUDED.last_seen_log,
         updated_at = NOW()`,
      params
    );
  }
}

async function applySnapshotToIocItems(client) {
  const updated = await client.query(
    `UPDATE ioc_items i
     SET
       match_count = s.match_count,
       first_seen_log = s.first_seen_log,
       last_seen_log = s.last_seen_log
     FROM ioc_match_count_snapshot s
     WHERE lower(i.observable) = s.observable_value
       AND (
         i.match_count IS DISTINCT FROM s.match_count
         OR i.first_seen_log IS DISTINCT FROM s.first_seen_log
         OR i.last_seen_log IS DISTINCT FROM s.last_seen_log
       )`
  );

  const reset = await client.query(
    `UPDATE ioc_items i
     SET
       match_count = 0,
       first_seen_log = NULL,
       last_seen_log = NULL
     WHERE NOT EXISTS (
       SELECT 1 FROM ioc_match_count_snapshot s WHERE s.observable_value = lower(i.observable)
     )
       AND (
         i.match_count <> 0
         OR i.first_seen_log IS NOT NULL
         OR i.last_seen_log IS NOT NULL
       )`
  );

  return { updatedItems: Number(updated.rowCount || 0), resetItems: Number(reset.rowCount || 0) };
}

async function tick() {
  const start = Date.now();
  const rows = await fetchAggregatesFromClickHouse();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await upsertSnapshot(client, rows);
    const result = await applySnapshotToIocItems(client);
    await client.query('COMMIT');

    const ms = Date.now() - start;
    console.log(`[ioc-match-count-worker] synced observables=${rows.length} updated_ioc_items=${result.updatedItems} reset_ioc_items=${result.resetItems} duration_ms=${ms}`);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function main() {
  console.log(`[ioc-match-count-worker] started interval_ms=${LOOP_INTERVAL_MS} batch_size=${UPSERT_BATCH_SIZE}`);

  while (true) {
    try {
      await tick();
    } catch (err) {
      console.error('[ioc-match-count-worker] tick failed', err?.message || err);
    }

    await new Promise((resolve) => setTimeout(resolve, LOOP_INTERVAL_MS));
  }
}

main().catch((err) => {
  console.error('[ioc-match-count-worker] fatal', err?.message || err);
  process.exit(1);
});
