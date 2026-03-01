import pg from 'pg';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD || 'demo123',
  database: process.env.DB_NAME || 'demo'
});

const retentionDays = Number(process.env.RAW_RETENTION_DAYS || 30);
const intervalSeconds = Number(process.env.RETENTION_CHECK_INTERVAL_SECONDS || 3600);

async function cleanup() {
  const startedAt = Date.now();
  const client = await pool.connect();
  try {
    const result = await client.query(
      `DELETE FROM signal_events
       WHERE created_at < NOW() - ($1::text || ' days')::interval`,
      [retentionDays]
    );

    const tookMs = Date.now() - startedAt;
    console.log(`[raw-retention] deleted=${result.rowCount} retention_days=${retentionDays} took_ms=${tookMs}`);
  } catch (err) {
    console.error('[raw-retention] failed', err?.message || err);
  } finally {
    client.release();
  }
}

console.log(`[raw-retention] worker started retention_days=${retentionDays} interval_seconds=${intervalSeconds}`);

await cleanup();
setInterval(() => {
  cleanup().catch(() => {});
}, intervalSeconds * 1000);
