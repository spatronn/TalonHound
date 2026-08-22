import './lib/ensure-db-password.js';
import pg from 'pg';
import { createAuditLogService } from './lib/auditLogService.js';
import { runExpirationWorkerBatch } from './lib/iocExpiration.js';
import {
  runAuditLogRetentionCleanup,
  AUDIT_LOG_RETENTION_DEFAULT_BATCH_SIZE
} from './lib/auditLogRetention.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const POLL_MS = Math.max(Number(process.env.IOC_EXPIRATION_POLL_INTERVAL_MS || 60000), 5000);
const BATCH_SIZE = Math.max(Number(process.env.IOC_EXPIRATION_BATCH_SIZE || 500), 50);

// Audit log retention cleanup runs at most once per interval (default daily).
// The cleanup routine itself enforces the same gate in the DB (last_run_at) so
// multiple instances / restarts cannot cause repeated heavy runs.
const AUDIT_RETENTION_INTERVAL_MS = Math.max(
  Number(process.env.AUDIT_LOG_RETENTION_INTERVAL_HOURS || 24) * 60 * 60 * 1000,
  60 * 1000
);
const AUDIT_RETENTION_BATCH_SIZE = Math.max(
  Number(process.env.AUDIT_LOG_RETENTION_BATCH_SIZE || AUDIT_LOG_RETENTION_DEFAULT_BATCH_SIZE),
  1
);
// Throttle how often we even consult the DB gate (cheap, but avoids per-tick reads).
const AUDIT_RETENTION_CHECK_MS = Math.min(AUDIT_RETENTION_INTERVAL_MS, 30 * 60 * 1000);
let lastAuditRetentionCheck = 0;

const audit = createAuditLogService(pool);
let stopping = false;

async function maybeRunAuditRetention() {
  const now = Date.now();
  if (now - lastAuditRetentionCheck < AUDIT_RETENTION_CHECK_MS) return;
  lastAuditRetentionCheck = now;
  try {
    await runAuditLogRetentionCleanup(pool, {
      batchSize: AUDIT_RETENTION_BATCH_SIZE,
      minIntervalMs: AUDIT_RETENTION_INTERVAL_MS,
      logger: console
    });
  } catch (err) {
    console.error('[audit-retention] run failed', err?.message || err);
  }
}

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

  await maybeRunAuditRetention();
}

async function main() {
  const { waitUntilSetupComplete } = await import('./lib/systemTime.js');
  const tz = await waitUntilSetupComplete(pool, { logPrefix: '[ioc-expiration]' });
  process.env.TZ = tz;
  process.env.SYSTEM_TIMEZONE = tz;
  console.log(`[ioc-expiration] worker started poll_ms=${POLL_MS} batch_size=${BATCH_SIZE} tz=${tz}`);
  console.log(
    `[audit-retention] scheduled interval_ms=${AUDIT_RETENTION_INTERVAL_MS} batch_size=${AUDIT_RETENTION_BATCH_SIZE}`
  );
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
