import { reconcileBullmqWithDb, releaseOrphanDbSourceLocks } from './integrationQueueBullmqReconciliation.js';
import { computeQueueHealth } from './integrationQueueHealth.js';
import { runQueueRecovery } from './integrationQueueRecovery.js';

export async function loadIntegrationQueueHealthSnapshot(pool, queue) {
  const { loadStalledBullJobs } = await import('./integrationQueueBullmqReconciliation.js');
  const [bullCounts, stalledJobs, workers, dbStatusRes, dbRunningRes, oldestQueuedRes] = await Promise.all([
    queue.getJobCounts('waiting', 'active', 'completed', 'failed', 'delayed', 'paused'),
    loadStalledBullJobs(queue, 500),
    queue.getWorkers().catch(() => []),
    pool.query(
      `SELECT status, COUNT(*)::int AS cnt
       FROM integration_queue_jobs
       WHERE queued_at >= NOW() - INTERVAL '24 hours'
       GROUP BY status`
    ),
    pool.query(
      `SELECT job_id, integration_key, status, started_at, heartbeat_at, worker_id
       FROM integration_queue_jobs
       WHERE status = 'running'`
    ),
    pool.query(
      `SELECT EXTRACT(EPOCH FROM (NOW() - MIN(queued_at)))::int AS age_seconds
       FROM integration_queue_jobs
       WHERE status = 'queued' AND queued_at >= NOW() - INTERVAL '24 hours'`
    )
  ]);

  const bullCountsFull = { ...bullCounts, stalled: stalledJobs.length };

  const dbCounts = { waiting: 0, active: 0, failed: 0, completed: 0 };
  for (const row of dbStatusRes.rows) {
    if (row.status === 'queued') dbCounts.waiting += row.cnt;
    else if (row.status === 'running') dbCounts.active += row.cnt;
    else if (row.status === 'failed') dbCounts.failed += row.cnt;
    else if (row.status === 'success') dbCounts.completed += row.cnt;
  }

  const dryBull = await reconcileBullmqWithDb({ pool, queue, dryRun: true, logPrefix: '[queue-health]' });
  // use full counts including stalled for health presentation
  const dryLocks = await releaseOrphanDbSourceLocks({ pool, queue, dryRun: true, logPrefix: '[queue-health]' });

  const workerConsuming = Array.isArray(workers) && workers.length > 0;
  const recoveryNeeded = dryBull.reconciled_count > 0 || dryLocks.released_count > 0;

  const health = computeQueueHealth({
    bullCounts: bullCountsFull,
    dbCounts,
    dbRunningCount: dbRunningRes.rowCount,
    staleActiveJobs: dryBull.stale_active_jobs,
    staleStalledJobs: dryBull.stale_stalled_jobs,
    workerConsuming,
    recoveryNeeded,
    warnings: []
  });

  const sourceLocks = dbRunningRes.rows.map((r) => ({
    job_id: r.job_id,
    integration_key: r.integration_key,
    worker_id: r.worker_id,
    started_at: r.started_at,
    heartbeat_at: r.heartbeat_at
  }));

  return {
    health,
    bull_counts: bullCountsFull,
    db_counts: dbCounts,
    source_locks: sourceLocks,
    oldest_waiting_age_seconds: Number(oldestQueuedRes.rows[0]?.age_seconds || 0) || null,
    dry_run_reconcile: dryBull,
    dry_run_locks: dryLocks,
    worker_count: workers?.length || 0
  };
}

export async function runIntegrationQueueRecover(pool, queue, { dryRun = false, logPrefix = '[queue-recover]' } = {}) {
  const recovery = await runQueueRecovery(pool, { logPrefix, queue, dryRun });
  return {
    stale_active_jobs: recovery.bullReconcile?.stale_active_jobs || [],
    stale_stalled_jobs: recovery.bullReconcile?.stale_stalled_jobs || [],
    orphan_locks: recovery.lockRelease?.orphan_locks || [],
    actions_taken: [
      ...(recovery.bullReconcile?.actions_taken || []),
      ...(recovery.lockRelease?.actions_taken || [])
    ],
    skipped: recovery.bullReconcile?.skipped || [],
    reconciled_count: recovery.totalReconciled || 0,
    dry_run: dryRun,
    recovery
  };
}
