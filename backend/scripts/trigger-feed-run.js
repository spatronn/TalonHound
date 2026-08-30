import { Queue } from 'bullmq';
import IORedis from 'ioredis';

const FEED_JOBS = {
  'et-blockrules': 'hourly-import',
  'usom-trcert': 'usom-import',
  'urlhaus-abusech': 'urlhaus-import',
  'threatfox-abusech': 'threatfox-import',
  'malwarebazaar-abusech': 'malwarebazaar-import',
  'phishtank-opendnsrr': 'phishtank-import',
  'alienvault-otx': 'alienvault-otx-import',
  'certpl-warning-list': 'certpl-import'
};

const feedKey = String(process.argv[2] || 'phishtank-opendnsrr').trim();
const jobName = FEED_JOBS[feedKey];
if (!jobName) {
  console.error('Unknown feed key:', feedKey);
  process.exit(1);
}

const redis = new IORedis({
  host: process.env.REDIS_HOST || 'redis',
  port: Number(process.env.REDIS_PORT || 6379),
  password: process.env.REDIS_PASSWORD || undefined,
  maxRetriesPerRequest: null
});

const queue = new Queue(process.env.QUEUE_NAME || 'integration-imports', { connection: redis });
const job = await queue.add(
  jobName,
  { triggeredBy: 'manual-script', integration_key: feedKey },
  { priority: 1, jobId: `${feedKey}-manual-${Date.now()}` }
);

console.log(JSON.stringify({ ok: true, feedKey, jobId: job.id, jobName }, null, 2));
await queue.close();
await redis.quit();
