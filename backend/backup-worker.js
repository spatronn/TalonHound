import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker, Queue } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { createAuditLogService } from './lib/auditLogService.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './lib/auditConstants.js';
import {
  getBackupConfig,
  BACKUP_QUEUE_NAME,
  executeBackupJob,
  cronMatchesInTimezone,
  minuteKeyUtc
} from './lib/backup/index.js';
import {
  interruptAllActive,
  interruptStale,
  failOrphanQueued,
  countBlockingBackups,
  createBackupRow,
  setJobId,
  markFailed,
  getBackupById
} from './lib/backup/backupStore.js';
import { generateBackupId } from './lib/backup/ids.js';
import { ensureBackupDir } from './lib/backup/config.js';
import { runRetentionSweep } from './routes/backups.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const audit = createAuditLogService(pool);
const cfg = getBackupConfig();
const redis = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
const backupQueue = new Queue(BACKUP_QUEUE_NAME, { connection: redis });

ensureBackupDir(cfg.backupDir);

let lastScheduledMinute = null;
let stopping = false;

async function waitForTable() {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      await pool.query('SELECT 1 FROM system_backups LIMIT 1');
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error('system_backups table not available (run migrations)');
}

async function auditBackup(action, row, { severity = AUDIT_SEVERITY.INFO, status = 'success', extra = {} } = {}) {
  const event = {
    action,
    entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
    entityId: row.id,
    entityDisplay: row.backup_id,
    severity,
    actorEmail: row.created_by_email || 'system',
    metadata: {
      backup_id: row.backup_id,
      trigger_type: row.trigger_type,
      ...extra
    }
  };
  if (status === 'failed') return audit.auditFailure(event);
  return audit.auditSuccess(event);
}

async function processBackupJob(job) {
  const backupRowId = job.data?.backupRowId;
  if (!backupRowId) {
    console.warn('[backup-worker] job missing backupRowId');
    return;
  }
  console.log(`[backup-worker] job received id=${job.id} backupRowId=${backupRowId}`);
  const before = await getBackupById(pool, backupRowId);
  if (before) {
    await auditBackup(AUDIT_ACTION.BACKUP_STARTED, before);
  }
  const result = await executeBackupJob(pool, backupRowId, { logger: console });
  if (!result) return;
  if (result.status === 'completed') {
    await auditBackup(AUDIT_ACTION.BACKUP_COMPLETED, result, {
      extra: {
        archive_size_bytes: result.archive_size_bytes,
        duration_ms: result.duration_ms,
        result: 'completed'
      }
    });
  } else if (result.status === 'failed') {
    await auditBackup(AUDIT_ACTION.BACKUP_FAILED, result, {
      status: 'failed',
      severity: AUDIT_SEVERITY.WARNING,
      extra: { error_code: result.error_code, result: 'failed' }
    });
  }
}

async function maybeEnqueueScheduled() {
  const liveCfg = getBackupConfig();
  if (!liveCfg.enabled || stopping) return;
  const now = new Date();
  if (!cronMatchesInTimezone(liveCfg.cron, now, liveCfg.timezone)) return;
  const key = minuteKeyUtc(now);
  if (lastScheduledMinute === key) return;

  const active = await countBlockingBackups(pool, liveCfg.orphanQueuedMinutes);
  if (active > 0) {
    console.log(`[backup-worker] skip scheduled run; blocking_active=${active}`);
    return;
  }

  const backupId = generateBackupId();
  const jobId = `scheduled-${key}`;
  console.log(`[backup-worker] schedule match cron=${liveCfg.cron} tz=${liveCfg.timezone} jobId=${jobId}`);

  const row = await createBackupRow(pool, {
    backupId,
    triggerType: 'scheduled',
    createdByEmail: 'system',
    encrypted: liveCfg.encryptionEnabled
  });
  console.log(`[backup-worker] backup row created backup_id=${backupId} id=${row.id}`);

  try {
    const job = await backupQueue.add(
      'backup',
      { backupRowId: row.id, backupId },
      { removeOnComplete: 50, removeOnFail: 100, attempts: 1, jobId }
    );
    await setJobId(pool, row.id, String(job.id));
    lastScheduledMinute = key;
    await auditBackup(AUDIT_ACTION.BACKUP_REQUESTED, row, {
      extra: { trigger_type: 'scheduled', bullmq_job_id: String(job.id) }
    });
    console.log(`[backup-worker] enqueue succeeded backup_id=${backupId} jobId=${job.id}`);
  } catch (err) {
    const failed = await markFailed(pool, row.id, {
      errorCode: 'ENQUEUE_FAILED',
      errorMessage: err?.message || 'Failed to enqueue scheduled backup'
    });
    await auditBackup(AUDIT_ACTION.BACKUP_FAILED, failed || row, {
      status: 'failed',
      severity: AUDIT_SEVERITY.WARNING,
      extra: { error_code: 'ENQUEUE_FAILED', result: 'failed' }
    });
    // Allow retry later in the same minute only if enqueue failed before marking lastScheduledMinute
    console.warn(`[backup-worker] enqueue failed backup_id=${backupId} err=${err?.message}`);
    throw err;
  }
}

async function reconcileStale() {
  if (stopping) return;
  const orphans = await failOrphanQueued(pool, cfg.orphanQueuedMinutes);
  for (const row of orphans) {
    console.warn(
      `[backup-worker] reconciler failed orphan queued backup_id=${row.backup_id} age_gt=${cfg.orphanQueuedMinutes}m`
    );
    await auditBackup(AUDIT_ACTION.BACKUP_FAILED, row, {
      status: 'failed',
      severity: AUDIT_SEVERITY.WARNING,
      extra: { error_code: row.error_code, result: 'stale_queued' }
    });
  }
  const interrupted = await interruptStale(pool, cfg.staleJobTimeoutMinutes);
  for (const row of interrupted) {
    console.warn(
      `[backup-worker] reconciler interrupted stale backup_id=${row.backup_id} timeout=${cfg.staleJobTimeoutMinutes}m`
    );
  }
}

async function main() {
  await waitForTable();
  const { waitUntilSetupComplete } = await import('./lib/systemTime.js');
  const { setSystemScheduleTimezoneOverride } = await import('./lib/integrationSchedule.js');
  const tz = await waitUntilSetupComplete(pool, { logPrefix: '[backup-worker]' });
  process.env.TZ = tz;
  process.env.SYSTEM_TIMEZONE = tz;
  setSystemScheduleTimezoneOverride(tz);
  const interrupted = await interruptAllActive(pool);
  if (interrupted.length) {
    console.log(`[backup-worker] marked ${interrupted.length} active backup(s) interrupted`);
  }

  const worker = new Worker(
    BACKUP_QUEUE_NAME,
    async (job) => processBackupJob(job),
    {
      connection: redis,
      concurrency: 1
    }
  );

  worker.on('failed', (job, err) => {
    console.error(`[backup-worker] job failed id=${job?.id} err=${err?.message}`);
  });

  const scheduleTimer = setInterval(() => {
    maybeEnqueueScheduled().catch((err) => {
      console.warn('[backup-worker] schedule tick failed:', err.message);
    });
  }, 30_000);

  const retentionTimer = setInterval(() => {
    runRetentionSweep(pool, audit, { logger: console }).catch((err) => {
      console.warn('[backup-worker] retention failed:', err.message);
    });
  }, 60 * 60 * 1000);

  const reconcileTimer = setInterval(() => {
    reconcileStale().catch((err) => {
      console.warn('[backup-worker] reconcile failed:', err.message);
    });
  }, 5 * 60 * 1000);

  // Initial ticks
  maybeEnqueueScheduled().catch(() => {});
  runRetentionSweep(pool, audit, { logger: console }).catch(() => {});
  reconcileStale().catch(() => {});

  console.log(
    `[backup-worker] started queue=${BACKUP_QUEUE_NAME} dir=${cfg.backupDir} cron=${cfg.cron} tz=${cfg.timezone} enabled=${cfg.enabled} stale_timeout_m=${cfg.staleJobTimeoutMinutes} orphan_queued_m=${cfg.orphanQueuedMinutes}`
  );

  const shutdown = async (signal) => {
    if (stopping) return;
    stopping = true;
    console.log(`[backup-worker] shutting down (${signal})`);
    clearInterval(scheduleTimer);
    clearInterval(retentionTimer);
    clearInterval(reconcileTimer);
    await worker.close();
    await backupQueue.close();
    redis.disconnect();
    await pool.end();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('[backup-worker] fatal:', err.message);
  process.exit(1);
});
