import '../lib/ensure-db-password.js';
import pg from 'pg';

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const feedId = arg('feed-id') ? Number(arg('feed-id')) : null;
const batchSize = Math.max(100, Math.min(20000, Number(arg('batch-size', 10000)) || 10000));
const indexesOnly = process.argv.includes('--indexes-only');

async function createReconciliationIndex(client) {
  // CREATE INDEX CONCURRENTLY cannot run inside a transaction; use a dedicated autocommit connection.
  await client.query('COMMIT').catch(() => {});
  await client.query(
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pf_items_feed_recon_bucket
     ON published_feed_items (
       feed_id, snapshot_window, reconciliation_bucket, identity_key
     )
     WHERE snapshot_window = 'all' AND reconciliation_bucket IS NOT NULL`
  );
  console.log('[reconciliation-buckets] index idx_pf_items_feed_recon_bucket ready');
}

async function backfillBuckets(client) {
  let cursor = '';
  let updated = 0;

  for (;;) {
    const params = feedId ? [cursor, batchSize, feedId] : [cursor, batchSize];
    const feedClause = feedId ? 'AND feed_id = $3' : '';
    // eslint-disable-next-line no-await-in-loop
    const { rows } = await client.query(
      `SELECT identity_key, feed_id, snapshot_window
       FROM published_feed_items
       WHERE snapshot_window = 'all'
         AND reconciliation_bucket IS NULL
         AND identity_key > $1
         ${feedClause}
       ORDER BY identity_key
       LIMIT $2`,
      params
    );
    if (!rows.length) break;
    // eslint-disable-next-line no-await-in-loop
    await client.query(
      feedId
        ? `UPDATE published_feed_items
           SET reconciliation_bucket = published_feed_reconciliation_bucket(partition_identity)
           WHERE feed_id = $2
             AND snapshot_window = 'all'
             AND reconciliation_bucket IS NULL
             AND identity_key = ANY($1::text[])`
        : `UPDATE published_feed_items
           SET reconciliation_bucket = published_feed_reconciliation_bucket(partition_identity)
           WHERE snapshot_window = 'all'
             AND reconciliation_bucket IS NULL
             AND identity_key = ANY($1::text[])`,
      feedId
        ? [rows.map((r) => r.identity_key), feedId]
        : [rows.map((r) => r.identity_key)]
    );
    cursor = rows.at(-1).identity_key;
    updated += rows.length;
    console.log(`[reconciliation-buckets] backfilled=${updated}`);
  }

  const verify = await client.query(
    `SELECT COUNT(*) FILTER (WHERE reconciliation_bucket IS NULL AND partition_identity IS NOT NULL)::bigint AS missing,
            COUNT(*)::bigint AS total,
            MIN(reconciliation_bucket) AS min_bucket,
            MAX(reconciliation_bucket) AS max_bucket
     FROM published_feed_items
     WHERE snapshot_window = 'all' ${feedId ? 'AND feed_id = $1' : ''}`,
    feedId ? [feedId] : []
  );
  const row = verify.rows[0];
  if (Number(row?.missing || 0) > 0) {
    throw new Error(`Reconciliation bucket backfill incomplete: ${row.missing} rows missing`);
  }
  return { updated, ...row };
}

async function reportDistribution(client) {
  const { rows } = await client.query(
    `SELECT reconciliation_bucket AS bucket, COUNT(*)::bigint AS n
     FROM published_feed_items
     WHERE snapshot_window = 'all' AND reconciliation_bucket IS NOT NULL
       ${feedId ? 'AND feed_id = $1' : ''}
     GROUP BY 1
     ORDER BY 1`,
    feedId ? [feedId] : []
  );
  const counts = rows.map((r) => Number(r.n));
  const total = counts.reduce((a, b) => a + b, 0);
  const min = counts.length ? Math.min(...counts) : 0;
  const max = counts.length ? Math.max(...counts) : 0;
  const avg = counts.length ? total / counts.length : 0;
  console.log(JSON.stringify({
    ok: true,
    buckets: rows.length,
    total_rows: total,
    min_per_bucket: min,
    max_per_bucket: max,
    avg_per_bucket: Number(avg.toFixed(1))
  }));
}

async function main() {
  const client = await pool.connect();
  try {
    await createReconciliationIndex(client);
    if (!indexesOnly) {
      const result = await backfillBuckets(client);
      console.log(JSON.stringify({ ok: true, ...result }));
      await reportDistribution(client);
    } else {
      console.log(JSON.stringify({ ok: true, indexes_only: true }));
    }
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[reconciliation-buckets] failed', err?.message || err);
  process.exitCode = 1;
});
