import { THREAT_LIBRARY_QUEUE_NAME } from './constants.js';

export function getThreatLibraryQueueName() {
  return process.env.THREAT_LIBRARY_QUEUE_NAME || THREAT_LIBRARY_QUEUE_NAME;
}

export function getThreatLibraryJobOptions() {
  return {
    removeOnComplete: 100,
    removeOnFail: 200,
    attempts: 2,
    backoff: { type: 'exponential', delay: 5000 }
  };
}
