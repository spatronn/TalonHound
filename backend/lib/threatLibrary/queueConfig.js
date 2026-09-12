import { THREAT_LIBRARY_QUEUE_NAME } from './constants.js';

export function getThreatLibraryQueueName() {
  return process.env.THREAT_LIBRARY_QUEUE_NAME || THREAT_LIBRARY_QUEUE_NAME;
}

/** Job options for enqueue. Attempts kept low — retries are explicit via UI. */
export function getThreatLibraryJobOptions() {
  return {
    removeOnComplete: 100,
    removeOnFail: 200,
    attempts: 1,
    backoff: { type: 'exponential', delay: 5000 }
  };
}

/**
 * BullMQ defaults lockDuration=30s which stalls long Ollama jobs.
 * Keep the lock longer than the max total analysis ceiling (2h).
 */
export function getThreatLibraryWorkerOptions() {
  const lockDuration = Math.max(
    Number(process.env.THREAT_LIBRARY_LOCK_DURATION_MS || 2 * 60 * 60 * 1000),
    10 * 60 * 1000
  );
  return {
    lockDuration,
    stalledInterval: Math.min(Math.max(Math.floor(lockDuration / 4), 30_000), 120_000),
    maxStalledCount: 2
  };
}
