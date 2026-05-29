import pg from 'pg';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const feedQ = await pool.query(
  `SELECT key, schedule_cron, active FROM integration_feeds ORDER BY key`
);
console.log('feeds', feedQ.rows);

const phishRuns = await pool.query(
  `SELECT id, status, started_at, finished_at, LEFT(COALESCE(error_message, ''), 120) AS err
   FROM integration_runs WHERE job_type = 'phishtank_import'
   ORDER BY started_at DESC LIMIT 8`
);
console.log('phishtank_runs', phishRuns.rows);

const phishQueue = await pool.query(
  `SELECT job_id, integration_key, status, queued_at, started_at, finished_at, LEFT(COALESCE(error_message, ''), 120) AS err
   FROM integration_queue_jobs
   WHERE job_name = 'phishtank-import' OR integration_key = 'phishtank-opendnsrr'
   ORDER BY queued_at DESC LIMIT 8`
);
console.log('phishtank_queue', phishQueue.rows);

await pool.end();
