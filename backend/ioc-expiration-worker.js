import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import pg from 'pg';
import IORedis from 'ioredis';
import { createAuditLogService } from './lib/auditLogService.js';
import { runExpirationWorkerBatch } from './lib/iocExpiration.js';
import {
  runAuditLogRetentionCleanup,
  AUDIT_LOG_RETENTION_DEFAULT_BATCH_SIZE
} from './lib/auditLogRetention.js';
import {
  runOperationalHistoryRetentionCleanup,
  OPERATIONAL_HISTORY_RETENTION_DEFAULT_BATCH_SIZE
} from './lib/operationalHistoryRetention.js';
import { cleanupSessions } from './lib/authSessions.js';
import { runDueEnrichmentHealthProbes } from './lib/enrichmentHealthProbeScheduler.js';
import { getRedisUrl } from './lib/redis-url.js';
import { HEARTBEAT_KEYS, touchWorkerHeartbeat } from './lib/workerHeartbeat.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: Math.max(Number(process.env.DB_POOL_CONNECTION_TIMEOUT_MS || 10000), 1000)
});

const redis = new IORedis(getRedisUrl(), {
  maxRetriesPerRequest: 1,
  enableReadyCheck: true,
  lazyConnect: false
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

// Operational history retention (integration_runs / queue jobs / ip geo cache).
// Same throttle pattern as audit retention so restarts cannot hammer DELETE.
const OPS_RETENTION_INTERVAL_MS = Math.max(
  Number(process.env.OPS_HISTORY_RETENTION_INTERVAL_HOURS || 24) * 60 * 60 * 1000,
  60 * 1000
);
const OPS_RETENTION_BATCH_SIZE = Math.max(
  Number(process.env.OPS_HISTORY_RETENTION_BATCH_SIZE || OPERATIONAL_HISTORY_RETENTION_DEFAULT_BATCH_SIZE),
  1
);
const OPS_RETENTION_CHECK_MS = Math.min(OPS_RETENTION_INTERVAL_MS, 30 * 60 * 1000);
let lastOpsRetentionCheck = 0;
let lastOpsRetentionRunAtMs = 0;

// Bounded cleanup of terminal (revoked / absolutely-expired) auth_sessions rows past
// their retention window. Cheap indexed delete; runs on the same throttle as audit
// retention so it never dominates a tick.
const SESSION_CLEANUP_CHECK_MS = Math.max(
  Number(process.env.SESSION_CLEANUP_INTERVAL_MS || 60 * 60 * 1000),
  60 * 1000
);
const SESSION_CLEANUP_BATCH_SIZE = Math.max(
  Number(process.env.SESSION_CLEANUP_BATCH_SIZE || 1000),
  1
);
let lastSessionCleanupCheck = 0;

async function maybeRunSessionCleanup() {
  const now = Date.now();
  if (now - lastSessionCleanupCheck < SESSION_CLEANUP_CHECK_MS) return;
  lastSessionCleanupCheck = now;
  try {
    let total = 0;
    // Drain in bounded batches so a large backlog cannot be a single heavy statement.
    for (let i = 0; i < 20; i += 1) {
      const { deleted } = await cleanupSessions(pool, { batchSize: SESSION_CLEANUP_BATCH_SIZE });
      total += deleted;
      if (deleted < SESSION_CLEANUP_BATCH_SIZE) break;
    }
    if (total > 0) console.log(`[session-cleanup] deleted=${total}`);
  } catch (err) {
    console.error('[session-cleanup] run failed', err?.message || err);
  }
}

// Scheduled enrichment-provider health probes. The per-provider 24h cadence and
// retry timing are derived from persisted last_check_at, so we only need a cheap
// throttle here to decide how often to consult the due-check (default every 15m).
// runDueEnrichmentHealthProbes takes an advisory lock, so overlapping ticks or
// multiple worker instances cannot double-probe a provider.
const HEALTH_PROBE_CHECK_MS = Math.max(
  Number(process.env.ENRICHMENT_HEALTH_PROBE_CHECK_MS || 15 * 60 * 1000),
  60 * 1000
);
let lastHealthProbeCheck = 0;

async function maybeRunHealthProbes() {
  const now = Date.now();
  if (now - lastHealthProbeCheck < HEALTH_PROBE_CHECK_MS) return;
  lastHealthProbeCheck = now;
  try {
    const result = await runDueEnrichmentHealthProbes(pool, { logger: console });
    if (result?.probed?.length) {
      console.log(`[health-probe] probed=${result.probed.join(',')}`);
    }
  } catch (err) {
    console.error('[health-probe] run failed', err?.message || err);
  }
}

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

async function maybeRunOpsRetention() {
  const now = Date.now();
  if (now - lastOpsRetentionCheck < OPS_RETENTION_CHECK_MS) return;
  lastOpsRetentionCheck = now;
  try {
    const result = await runOperationalHistoryRetentionCleanup(pool, {
      batchSize: OPS_RETENTION_BATCH_SIZE,
      minIntervalMs: OPS_RETENTION_INTERVAL_MS,
      lastRunAtMs: lastOpsRetentionRunAtMs || null,
      logger: console
    });
    if (result?.lastRunAtMs) lastOpsRetentionRunAtMs = result.lastRunAtMs;
  } catch (err) {
    console.error('[ops-retention] run failed', err?.message || err);
  }
}

async function tick() {
  try {
    await touchWorkerHeartbeat(redis, HEARTBEAT_KEYS.ioc_expiration_worker);
  } catch (err) {
    console.error('[ioc-expiration] heartbeat failed', err?.message || err);
  }

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
  await maybeRunOpsRetention();
  await maybeRunSessionCleanup();
  await maybeRunHealthProbes();
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
  console.log(
    `[ops-retention] scheduled interval_ms=${OPS_RETENTION_INTERVAL_MS} batch_size=${OPS_RETENTION_BATCH_SIZE}`
  );
  while (!stopping) {
    await tick();
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

process.on('SIGINT', () => { stopping = true; });
process.on('SIGTERM', () => { stopping = true; });

async function shutdown() {
  try { await redis.quit(); } catch { /* ignore */ }
  try { await pool.end(); } catch { /* ignore */ }
}

main()
  .catch((err) => {
    console.error('[ioc-expiration] fatal', err);
    process.exitCode = 1;
  })
  .finally(() => shutdown());
