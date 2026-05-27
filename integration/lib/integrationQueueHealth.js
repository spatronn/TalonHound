import { isDbTerminalStatus } from './integrationQueueBullmqReconciliation.js';

export function computeQueueHealth({
  bullCounts = {},
  dbCounts = {},
  dbRunningCount = 0,
  staleActiveJobs = [],
  staleStalledJobs = [],
  workerConsuming = null,
  recoveryNeeded = false,
  warnings = []
} = {}) {
  const waiting = Number(bullCounts.waiting || dbCounts.waiting || 0);
  const activeBull = Number(bullCounts.active || 0);
  const stalledBull = Number(bullCounts.stalled || 0);
  const activeDb = Number(dbCounts.active || dbRunningCount || 0);

  const w = [...warnings];
  let queueHealth = 'Healthy';
  let workerStatus = workerConsuming === false ? 'Not consuming' : (workerConsuming ? 'Running' : 'Unknown');

  const blockingStale = [...staleActiveJobs, ...staleStalledJobs].filter((entry) => {
    const dbStatus = entry.db ? String(entry.db.status || '').toLowerCase() : null;
    return !entry.db || isDbTerminalStatus(dbStatus) || dbStatus === 'running';
  });

  if (blockingStale.length > 0) {
    queueHealth = 'Blocked';
    w.push('Stale active job is blocking queue.');
  } else if (recoveryNeeded || stalledBull > 0) {
    queueHealth = 'Degraded';
  }

  if (waiting > 0 && activeBull === 0 && activeDb === 0 && workerConsuming) {
    w.push('Jobs are waiting but no worker is consuming. Possible stale lock or queue mismatch.');
    if (queueHealth === 'Healthy') queueHealth = 'Degraded';
  }

  if (waiting > 0 && activeBull === 0 && workerConsuming === false) {
    queueHealth = 'Blocked';
    w.push('Worker is not consuming jobs.');
  }

  return {
    worker_status: workerStatus,
    queue_health: queueHealth,
    bullmq_active: activeBull,
    bullmq_stalled: stalledBull,
    bullmq_waiting: waiting,
    bullmq_delayed: Number(bullCounts.delayed || 0),
    db_running: activeDb,
    db_waiting: Number(dbCounts.waiting || 0),
    recovery_needed: Boolean(recoveryNeeded || blockingStale.length > 0),
    warnings: w,
    blocking_stale_jobs: blockingStale.map((e) => ({
      job_id: e.job_id,
      bullmq_state: e.bullmq_state,
      db_status: e.db?.status || null,
      integration_key: e.db?.integration_key || null
    }))
  };
}

export function buildQueuedJobHint({
  jobId,
  integrationKey,
  bullCounts = {},
  dbRunningBySource = new Map(),
  queueHealth = null,
  blockingStaleJobs = []
}) {
  const hints = [];
  if (queueHealth?.recovery_needed) {
    hints.push('Queue recovery required');
  }
  if (queueHealth?.worker_status === 'Not consuming') {
    hints.push('Worker not consuming');
  }
  const blocking = dbRunningBySource.get(integrationKey);
  if (blocking && String(blocking.job_id) !== String(jobId)) {
    hints.push(`Waiting for source lock: ${integrationKey} (job #${blocking.job_id})`);
  }
  const staleBlock = blockingStaleJobs.find((b) => String(b.job_id) !== String(jobId));
  if (staleBlock) {
    hints.push(`Queued behind stale active job #${staleBlock.job_id}`);
  }
  if (Number(bullCounts.active || 0) > 0) {
    hints.push(`Queued behind active BullMQ job(s): ${bullCounts.active} active`);
  }
  if (!hints.length) return null;
  return hints.join(' · ');
}
