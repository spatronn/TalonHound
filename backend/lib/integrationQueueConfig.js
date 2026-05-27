function readPositiveInt(name, fallback, min = 1000) {
  const n = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(n) || n < min) return fallback;
  return Math.floor(n);
}

export const QUEUE_HARDENING = {
  jobTimeoutMs: readPositiveInt('INTEGRATION_JOB_TIMEOUT_MS', 600_000, 60_000),
  heartbeatIntervalMs: readPositiveInt('INTEGRATION_JOB_HEARTBEAT_INTERVAL_MS', 30_000, 5_000),
  staleAfterMs: readPositiveInt('INTEGRATION_JOB_STALE_AFTER_MS', 900_000, 60_000),
  shutdownGraceMs: readPositiveInt('INTEGRATION_WORKER_SHUTDOWN_GRACE_MS', 30_000, 5_000),
  cleanupIntervalMs: readPositiveInt('INTEGRATION_QUEUE_CLEANUP_INTERVAL_MS', 60_000, 10_000),
  sourceBusyDeferMs: readPositiveInt('INTEGRATION_SOURCE_BUSY_DEFER_MS', 30_000, 5_000),
  legacyStaleRunningMinutes: Math.max(Number(process.env.INTEGRATION_STALE_RUNNING_MINUTES || 180), 60)
};

export const FAILURE_MESSAGES = {
  stale: 'Job was running but heartbeat became stale. Marked as failed during queue recovery.',
  timeout: 'Job exceeded timeout and was marked as failed.',
  worker_shutdown: 'Worker shut down before job completed; marked for recovery.',
  source_busy: 'Deferred because another job for this integration is already running.',
  reconciled: 'Reconciled stale BullMQ state with DB terminal state.',
  bullmq_orphan: 'BullMQ job was active/stalled without a valid DB running record; closed during queue recovery.'
};

export const FAILURE_TYPES = {
  STALE: 'stale',
  TIMEOUT: 'timeout',
  WORKER_SHUTDOWN: 'worker_shutdown',
  SOURCE_BUSY: 'source_busy',
  FETCH_ERROR: 'fetch_error',
  PARSE_ERROR: 'parse_error',
  RECONCILED: 'reconciled',
  BULLMQ_ORPHAN: 'bullmq_orphan'
};
