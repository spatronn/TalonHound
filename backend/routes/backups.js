// Admin backup HTTP routes (create / verify / download / delete / status).
// Destructive restore runs only via host CLI (scripts/restore-stack.sh).

import { createReadStream } from 'node:fs';
import fs from 'node:fs';
import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import {
  getBackupConfig,
  createStorageProvider,
  verifyBackupArchive,
  selectRetentionCandidates,
  nextBackupFireAt,
  describeBackupSchedule,
  assertCanStartBackup,
  publicErrorMessage,
  generateBackupId
} from '../lib/backup/index.js';
import { loadEncryptionKey as loadKey } from '../lib/backup/config.js';
import { isValidRowId, redactErrorMessage } from '../lib/backup/pathSafety.js';
import {
  createBackupRow,
  getBackupById,
  listBackups,
  countBackups,
  countActiveBackups,
  countBlockingBackups,
  setJobId,
  markDeleted,
  markFailed,
  markVerifyResult,
  getLastSuccessful,
  sumCompletedArchiveBytes,
  listCompletedForRetention,
  getProtectedBackupIds
} from '../lib/backup/backupStore.js';

function actorEmail(req) {
  return String(req.user?.email || req.user?.username || '').trim() || null;
}

function actorId(req) {
  const n = Number(req.user?.id);
  return Number.isFinite(n) ? n : null;
}

function serializeBackup(row) {
  if (!row) return null;
  return {
    id: row.id,
    backup_id: row.backup_id,
    trigger_type: row.trigger_type,
    status: row.status,
    started_at: row.started_at,
    completed_at: row.completed_at,
    duration_ms: row.duration_ms == null ? null : Number(row.duration_ms),
    archive_filename: row.archive_filename,
    archive_size_bytes: row.archive_size_bytes == null ? null : Number(row.archive_size_bytes),
    checksum_sha256: row.checksum_sha256,
    encrypted: Boolean(row.encrypted),
    database_size_bytes: row.database_size_bytes == null ? null : Number(row.database_size_bytes),
    files_size_bytes: row.files_size_bytes == null ? null : Number(row.files_size_bytes),
    error_code: row.error_code,
    error_message: row.error_message ? publicErrorMessage(row.error_code, row.error_message) : null,
    verified_at: row.verified_at,
    verify_status: row.verify_status,
    verify_error: row.verify_error ? redactErrorMessage(row.verify_error) : null,
    created_by_email: row.created_by_email,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

async function enqueueBackup(pool, backupQueue, {
  triggerType,
  createdById,
  createdByEmail,
  encrypted
}) {
  const cfg = getBackupConfig();
  const active = await countBlockingBackups(pool, cfg.orphanQueuedMinutes);
  assertCanStartBackup(active, cfg.maxConcurrent);

  const backupId = generateBackupId();
  const row = await createBackupRow(pool, {
    backupId,
    triggerType,
    createdById,
    createdByEmail,
    encrypted: encrypted ?? Boolean(cfg.encryptionEnabled)
  });

  if (backupQueue) {
    try {
      const job = await backupQueue.add(
        'backup',
        { backupRowId: row.id, backupId },
        { removeOnComplete: 50, removeOnFail: 100, attempts: 1 }
      );
      await setJobId(pool, row.id, String(job.id));
    } catch (err) {
      const failed = await markFailed(pool, row.id, {
        errorCode: 'ENQUEUE_FAILED',
        errorMessage: err?.message || 'Failed to enqueue backup job'
      });
      const e = new Error(err?.message || 'Failed to enqueue backup job');
      e.code = 'ENQUEUE_FAILED';
      e.status = 500;
      e.backup = failed || row;
      throw e;
    }
  }

  return row;
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {{ backupQueue: import('bullmq').Queue, auditLogService: any }} deps
 */
export function registerBackupRoutes(app, pool, { backupQueue, auditLogService }) {
  const admin = requireRole(ROLES.ADMIN);

  app.get('/api/backups/status', admin, async (_req, res) => {
    try {
      const cfg = getBackupConfig();
      const [last, total, active, storageUsed, itemsPreview] = await Promise.all([
        getLastSuccessful(pool),
        countBackups(pool),
        countActiveBackups(pool),
        sumCompletedArchiveBytes(pool),
        listBackups(pool, { limit: 20, offset: 0 })
      ]);
      const lastVerify = last
        ? { status: last.verify_status, at: last.verified_at, backup_id: last.backup_id }
        : null;
      const schedule = describeBackupSchedule(cfg.cron, cfg.timezone);
      const inFlight = itemsPreview.filter((r) => ['queued', 'running', 'verifying'].includes(r.status));
      const runningOrVerifying = inFlight.filter((r) => ['running', 'verifying'].includes(r.status));
      const queuedOnly = inFlight.filter((r) => r.status === 'queued');
      const staleQueuedMs = cfg.orphanQueuedMinutes * 60_000;
      const now = Date.now();
      const staleQueued = queuedOnly.filter((r) => {
        const t = new Date(r.created_at || r.updated_at).getTime();
        return Number.isFinite(t) && now - t >= staleQueuedMs;
      });
      return res.json({
        enabled: cfg.enabled,
        cron: cfg.cron,
        timezone: cfg.timezone,
        schedule_summary: schedule.summary,
        retention_days: cfg.retentionDays,
        encryption_enabled: cfg.encryptionEnabled,
        storage_provider: cfg.storageProvider || 'local',
        max_concurrent: cfg.maxConcurrent,
        active_backups: active,
        /** True only when a job is actually executing (not merely orphan-queued). */
        backup_running: runningOrVerifying.length > 0,
        backup_queued: queuedOnly.length > 0,
        backup_stale_queued: staleQueued.length > 0,
        orphan_queued_minutes: cfg.orphanQueuedMinutes,
        last_successful: serializeBackup(last),
        next_scheduled_at: cfg.enabled ? nextBackupFireAt(cfg.cron, new Date(), cfg.timezone) : null,
        total_stored: total,
        storage_used_bytes: storageUsed,
        last_verification: lastVerify
      });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to load backup status' });
    }
  });

  app.get('/api/backups', admin, async (req, res) => {
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const offset = Math.max(Number(req.query.offset) || 0, 0);
      const rows = await listBackups(pool, { limit, offset });
      const total = await countBackups(pool);
      return res.json({ items: rows.map(serializeBackup), total, limit, offset });
    } catch (err) {
      return res.status(500).json({ message: 'Failed to list backups' });
    }
  });

  app.post('/api/backups', admin, async (req, res) => {
    try {
      const cfg = getBackupConfig();
      const row = await enqueueBackup(pool, backupQueue, {
        triggerType: 'manual',
        createdById: actorId(req),
        createdByEmail: actorEmail(req),
        encrypted: cfg.encryptionEnabled
      });
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.BACKUP_REQUESTED,
        entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
        entityId: row.id,
        entityDisplay: row.backup_id,
        metadata: { backup_id: row.backup_id, trigger_type: 'manual' }
      });
      return res.status(202).json({ id: row.id, backup_id: row.backup_id, status: row.status });
    } catch (err) {
      if (err.code === 'CONCURRENT' || err.status === 409) {
        return res.status(409).json({ message: publicErrorMessage('CONCURRENT') });
      }
      return res.status(500).json({ message: 'Failed to start backup' });
    }
  });

  app.post('/api/backups/:id/verify', admin, async (req, res) => {
    if (!isValidRowId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid backup id' });
    }
    const row = await getBackupById(pool, req.params.id);
    if (!row || row.status === 'deleted') {
      return res.status(404).json({ message: publicErrorMessage('NOT_FOUND') });
    }
    if (row.status !== 'completed' || !row.archive_path) {
      return res.status(409).json({ message: 'Only completed backups can be verified' });
    }
    try {
      let key = null;
      if (row.encrypted) {
        try {
          key = loadKey();
        } catch (err) {
          await markVerifyResult(pool, row.id, { ok: false, error: err.message });
          return res.status(400).json({ message: publicErrorMessage('ENCRYPTION_KEY') });
        }
      }
      const result = await verifyBackupArchive(row.archive_path, { encryptionKey: key });
      const updated = await markVerifyResult(pool, row.id, {
        ok: result.ok,
        error: result.error,
        checksum: result.archiveChecksum
      });
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.BACKUP_VERIFIED,
        entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
        entityId: row.id,
        entityDisplay: row.backup_id,
        severity: result.ok ? AUDIT_SEVERITY.INFO : AUDIT_SEVERITY.WARNING,
        metadata: {
          backup_id: row.backup_id,
          result: result.ok ? 'passed' : 'failed',
          error_code: result.ok ? null : result.errorCode
        }
      });
      if (!result.ok) {
        return res.status(422).json({
          message: publicErrorMessage(result.errorCode, result.error),
          backup: serializeBackup(updated)
        });
      }
      return res.json({ ok: true, backup: serializeBackup(updated) });
    } catch (err) {
      return res.status(500).json({ message: 'Verification failed' });
    }
  });

  app.get('/api/backups/:id/download', admin, async (req, res) => {
    if (!isValidRowId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid backup id' });
    }
    const row = await getBackupById(pool, req.params.id);
    if (!row || row.status !== 'completed' || !row.archive_filename) {
      return res.status(404).json({ message: publicErrorMessage('NOT_FOUND') });
    }
    try {
      const storage = createStorageProvider(getBackupConfig().backupDir);
      // Resolve only via storageKey (filename) — never trust client path
      const abs = storage.resolveAbsolutePath(row.archive_filename);
      await fs.promises.access(abs);
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.BACKUP_DOWNLOADED,
        entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
        entityId: row.id,
        entityDisplay: row.backup_id,
        metadata: { backup_id: row.backup_id }
      });
      res.setHeader('Content-Type', 'application/gzip');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${row.archive_filename.replace(/"/g, '')}"`
      );
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');
      if (row.archive_size_bytes) {
        res.setHeader('Content-Length', String(row.archive_size_bytes));
      }
      // Hint reverse proxies not to buffer the whole archive in memory.
      res.setHeader('X-Accel-Buffering', 'no');
      const stream = createReadStream(abs);
      stream.on('error', () => {
        if (!res.headersSent) res.status(500).json({ message: 'Download failed' });
        else res.destroy();
      });
      return stream.pipe(res);
    } catch (err) {
      if (err.code === 'INVALID_FILENAME') {
        return res.status(400).json({ message: publicErrorMessage('INVALID_FILENAME') });
      }
      return res.status(404).json({ message: publicErrorMessage('ARCHIVE_MISSING') });
    }
  });

  app.delete('/api/backups/:id', admin, async (req, res) => {
    if (!isValidRowId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid backup id' });
    }
    const row = await getBackupById(pool, req.params.id);
    if (!row || row.status === 'deleted') {
      return res.status(404).json({ message: publicErrorMessage('NOT_FOUND') });
    }
    if (['queued', 'running', 'verifying'].includes(row.status)) {
      return res.status(409).json({ message: publicErrorMessage('ACTIVE') });
    }
    const protectedIds = await getProtectedBackupIds(pool);
    if (protectedIds.has(row.backup_id)) {
      return res.status(409).json({ message: publicErrorMessage('ACTIVE') });
    }
    try {
      if (row.archive_filename) {
        const storage = createStorageProvider(getBackupConfig().backupDir);
        await storage.delete(row.archive_filename);
      }
      const deleted = await markDeleted(pool, row.id);
      if (!deleted) {
        return res.status(409).json({ message: publicErrorMessage('ACTIVE') });
      }
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.BACKUP_DELETED,
        entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
        entityId: row.id,
        entityDisplay: row.backup_id,
        metadata: { backup_id: row.backup_id, result: 'deleted' }
      });
      return res.json({ ok: true, backup: serializeBackup(deleted) });
    } catch (err) {
      await auditLogService.auditFailure({
        req,
        action: AUDIT_ACTION.BACKUP_DELETED,
        entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
        entityId: row.id,
        entityDisplay: row.backup_id,
        metadata: { backup_id: row.backup_id, error_code: 'DELETE_FAILED' }
      });
      return res.status(500).json({ message: 'Failed to delete backup' });
    }
  });
}

/** Retention sweep used by worker / CLI. */
export async function runRetentionSweep(pool, auditLogService = null, { logger = console } = {}) {
  const cfg = getBackupConfig();
  const completed = await listCompletedForRetention(pool);
  const protectedIds = await getProtectedBackupIds(pool);
  const candidates = selectRetentionCandidates(completed, {
    retentionDays: cfg.retentionDays,
    protectedBackupIds: protectedIds
  });
  const storage = createStorageProvider(cfg.backupDir);
  const results = [];
  for (const row of candidates) {
    try {
      if (row.archive_filename) {
        await storage.delete(row.archive_filename);
      }
      const deleted = await markDeleted(pool, row.id);
      if (auditLogService && deleted) {
        await auditLogService.auditSuccess({
          action: AUDIT_ACTION.BACKUP_DELETED,
          entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
          entityId: row.id,
          entityDisplay: row.backup_id,
          actorEmail: 'system',
          metadata: {
            backup_id: row.backup_id,
            result: 'retention_deleted',
            retention_days: cfg.retentionDays
          }
        });
      }
      results.push({ backup_id: row.backup_id, ok: true });
    } catch (err) {
      logger.warn?.(
        `[backup] retention delete failed backup_id=${row.backup_id} err=${redactErrorMessage(err.message)}`
      );
      results.push({ backup_id: row.backup_id, ok: false, error: redactErrorMessage(err.message) });
    }
  }
  return results;
}

export { enqueueBackup, serializeBackup };
