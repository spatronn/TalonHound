function readPositiveInt(name, fallback, min = 1000) {
  const n = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(n) || n < min) return fallback;
  return Math.floor(n);
}

const SOURCE_JOB_TIMEOUTS = Object.freeze({
  'phishtank-opendnsrr': { env: 'PHISHTANK_JOB_TIMEOUT_MS', fallback: 3_600_000 },
  'threatfox-abusech': { env: 'THREATFOX_JOB_TIMEOUT_MS', fallback: 600_000 },
  'usom-trcert': { env: 'USOM_JOB_TIMEOUT_MS', fallback: 7_200_000 },
  'urlhaus-abusech': { env: 'URLHAUS_JOB_TIMEOUT_MS', fallback: 600_000 },
  'malwarebazaar-abusech': { env: 'MALWAREBAZAAR_JOB_TIMEOUT_MS', fallback: 600_000 },
  'et-blockrules': { env: 'EMERGINGTHREATS_JOB_TIMEOUT_MS', fallback: 2_700_000 },
  'alienvault-otx': { env: 'ALIENVAULT_OTX_JOB_TIMEOUT_MS', fallback: 600_000 }
});

export function resolveIntegrationJobTimeoutMs(integrationKey, jobName, globalTimeoutMs = 600_000) {
  if (jobName === 'feed_data_purge') {
    return {
      timeoutMs: readPositiveInt('FEED_PURGE_JOB_TIMEOUT_MS', 86_400_000, 600_000),
      source: 'FEED_PURGE_JOB_TIMEOUT_MS'
    };
  }
  if (jobName === 'custom-threat-feed-sync') {
    return {
      timeoutMs: readPositiveInt('CUSTOM_THREAT_FEED_JOB_TIMEOUT_MS', 600_000, 60_000),
      source: 'CUSTOM_THREAT_FEED_JOB_TIMEOUT_MS'
    };
  }
  if (jobName === 'spamhaus-drop-sync') {
    return {
      timeoutMs: readPositiveInt('SPAMHAUS_DROP_JOB_TIMEOUT_MS', 120_000, 30_000),
      source: 'SPAMHAUS_DROP_JOB_TIMEOUT_MS'
    };
  }
  if (jobName === 'malwarebazaar-historical-recovery') {
    return {
      timeoutMs: readPositiveInt('MALWAREBAZAAR_RECOVERY_JOB_TIMEOUT_MS', 1_800_000, 60_000),
      source: 'MALWAREBAZAAR_RECOVERY_JOB_TIMEOUT_MS'
    };
  }

  const spec = SOURCE_JOB_TIMEOUTS[String(integrationKey || '').trim()];
  if (!spec) return { timeoutMs: globalTimeoutMs, source: 'global' };
  return {
    timeoutMs: readPositiveInt(spec.env, spec.fallback, 60_000),
    source: spec.env
  };
}

export const QUEUE_HARDENING = {
  jobTimeoutMs: readPositiveInt('INTEGRATION_JOB_TIMEOUT_MS', 600_000, 10_000),
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
  aborted: 'Integration job was aborted before completion.',
  worker_shutdown: 'Worker shut down before job completed; marked for recovery.',
  source_busy: 'Deferred because another job for this integration is already running.',
  reconciled: 'Reconciled stale BullMQ state with DB terminal state.',
  bullmq_orphan: 'BullMQ job was active/stalled without a valid DB running record; closed during queue recovery.'
};

export const FAILURE_TYPES = {
  STALE: 'stale',
  TIMEOUT: 'timeout',
  ABORTED: 'aborted',
  WORKER_SHUTDOWN: 'worker_shutdown',
  SOURCE_BUSY: 'source_busy',
  FETCH_ERROR: 'fetch_error',
  PARSE_ERROR: 'parse_error',
  RECONCILED: 'reconciled',
  BULLMQ_ORPHAN: 'bullmq_orphan'
};
