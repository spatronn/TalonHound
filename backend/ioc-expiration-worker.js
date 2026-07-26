import './lib/ensure-db-password.js';
import pg from 'pg';
import { createAuditLogService } from './lib/auditLogService.js';
import { runExpirationWorkerBatch } from './lib/iocExpiration.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'demo',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'demo'
});

const POLL_MS = Math.max(Number(process.env.IOC_EXPIRATION_POLL_INTERVAL_MS || 60000), 5000);
const BATCH_SIZE = Math.max(Number(process.env.IOC_EXPIRATION_BATCH_SIZE || 500), 50);

const audit = createAuditLogService(pool);
let stopping = false;

async function tick() {
  const client = await pool.connect();
  try {
    const res = await runExpirationWorkerBatch(client, {
      batchSize: BATCH_SIZE,
      audit
    });

    if (res.expiredMemberships > 0 || res.iocGlobalExpired > 0) {
      console.log(
        `[ioc-expiration] expired_memberships=${res.expiredMemberships} ioc_recomputed=${res.iocRecomputed} ioc_global_expired=${res.iocGlobalExpired}`
      );
    }
  } catch (err) {
    console.error('[ioc-expiration] tick failed', err?.message || err);
  } finally {
    client.release();
  }
}

async function main() {
  const { waitUntilSetupComplete } = await import('./lib/systemTime.js');
  const tz = await waitUntilSetupComplete(pool, { logPrefix: '[ioc-expiration]' });
  process.env.TZ = tz;
  process.env.SYSTEM_TIMEZONE = tz;
  console.log(`[ioc-expiration] worker started poll_ms=${POLL_MS} batch_size=${BATCH_SIZE} tz=${tz}`);
  while (!stopping) {
    await tick();
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

process.on('SIGINT', () => { stopping = true; });
process.on('SIGTERM', () => { stopping = true; });

main().catch((err) => {
  console.error('[ioc-expiration] fatal', err);
  process.exit(1);
});
