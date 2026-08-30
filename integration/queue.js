import IORedis from 'ioredis';
import { Queue } from 'bullmq';
import { config } from './config.js';

export const redis = new IORedis(config.redisUrl, { maxRetriesPerRequest: null });

export const importQueue = new Queue(config.queueName, {
  connection: redis,
  defaultJobOptions: {
    attempts: 5,
    backoff: { type: 'exponential', delay: 30_000 },
    removeOnComplete: 50,
    removeOnFail: 200
    // Job timeout is enforced cooperatively in worker.js (INTEGRATION_JOB_TIMEOUT_MS / per-feed overrides).
  }
});
