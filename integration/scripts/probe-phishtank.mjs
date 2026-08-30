import { createIntegrationPool } from '../lib/pg-pool.js';
import { importQueue, redis } from '../queue.js';

const pool = createIntegrationPool();

try {
  const feedQ = await pool.query(
    `SELECT key, schedule_cron, active FROM integration_feeds WHERE key LIKE '%phish%'`
  );
  console.log('feed', JSON.stringify(feedQ.rows, null, 2));

  const runsQ = await pool.query(
    `SELECT id, job_type, status, started_at, finished_at, LEFT(COALESCE(error_message,''), 120) AS err
     FROM integration_runs WHERE job_type = 'phishtank_import'
     ORDER BY started_at DESC LIMIT 8`
  );
  console.log('runs', JSON.stringify(runsQ.rows, null, 2));

  const queueQ = await pool.query(
    `SELECT job_id, integration_key, job_name, status, queued_at, started_at, finished_at, LEFT(COALESCE(error_message,''), 120) AS err
     FROM integration_queue_jobs
     WHERE job_name = 'phishtank-import' OR integration_key = 'phishtank-opendnsrr'
     ORDER BY queued_at DESC LIMIT 10`
  );
  console.log('queue_jobs', JSON.stringify(queueQ.rows, null, 2));

  const repeatables = await importQueue.getRepeatableJobs();
  console.log(
    'repeatables',
    JSON.stringify(
      repeatables.filter((r) => String(r.name || '').includes('phish') || String(r.id || '').includes('phish')),
      null,
      2
    )
  );

  const counts = await importQueue.getJobCounts('waiting', 'active', 'delayed', 'failed', 'completed');
  console.log('queue_counts', counts);
} finally {
  await importQueue.close();
  await redis.quit();
  await pool.end();
}
