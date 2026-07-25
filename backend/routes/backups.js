// Admin backup & restore HTTP routes.
// Restore never runs pg_restore in-process — prepare/confirm only surfaces CLI.

import { createReadStream } from 'node:fs';
import fs from 'node:fs';
import { requireRole, ROLES } from '../lib/rbac.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from '../lib/auditConstants.js';
import {
  getBackupConfig,
  createStorageProvider,
  verifyBackupArchive,
  selectRetentionCandidates,
  nextCronFireUtc,
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
  setJobId,
  markDeleted,
  markVerifyResult,
  getLastSuccessful,
  sumCompletedArchiveBytes,
  listCompletedForRetention,
  getProtectedBackupIds
} from '../lib/backup/backupStore.js';
import {
  createRestorePrepare,
  getRestoreById,
  confirmRestore,
  markRestoreFailed,
  isValidRestoreConfirmation,
  buildRestoreCliCommand
} from '../lib/backup/restoreStore.js';

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

function serializeRestore(row) {
  if (!row) return null;
  return {
    id: row.id,
    backup_id: row.backup_id,
    status: row.status,
    safety_backup_id: row.safety_backup_id,
    cli_command: row.cli_command || buildRestoreCliCommand(row.backup_id),
    prepared_by_email: row.prepared_by_email,
    confirmed_by_email: row.confirmed_by_email,
    prepared_at: row.prepared_at,
    confirmed_at: row.confirmed_at,
    error_code: row.error_code,
    error_message: row.error_message ? publicErrorMessage(row.error_code, row.error_message) : null,
    note: 'Destructive restore runs only via the host CLI after confirmation. The API does not execute pg_restore.'
  };
}

async function enqueueBackup(pool, backupQueue, {
  triggerType,
  createdById,
  createdByEmail,
  encrypted
}) {
  const cfg = getBackupConfig();
  const active = await countActiveBackups(pool);
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
    const job = await backupQueue.add(
      'backup',
      { backupRowId: row.id, backupId },
      { removeOnComplete: 50, removeOnFail: 100, attempts: 1 }
    );
    await setJobId(pool, row.id, String(job.id));
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
      const [last, total, active, storageUsed] = await Promise.all([
        getLastSuccessful(pool),
        countBackups(pool),
        countActiveBackups(pool),
        sumCompletedArchiveBytes(pool)
      ]);
      const lastVerify = last
        ? { status: last.verify_status, at: last.verified_at, backup_id: last.backup_id }
        : null;
      return res.json({
        enabled: cfg.enabled,
        cron: cfg.cron,
        retention_days: cfg.retentionDays,
        encryption_enabled: cfg.encryptionEnabled,
        max_concurrent: cfg.maxConcurrent,
        active_backups: active,
        backup_running: active > 0,
        last_successful: serializeBackup(last),
        next_scheduled_at: cfg.enabled ? nextCronFireUtc(cfg.cron) : null,
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

  app.get('/api/backups/restores/:restoreId', admin, async (req, res) => {
    if (!isValidRowId(req.params.restoreId)) {
      return res.status(400).json({ message: 'Invalid restore id' });
    }
    const row = await getRestoreById(pool, req.params.restoreId);
    if (!row) return res.status(404).json({ message: 'Restore not found' });
    return res.json(serializeRestore(row));
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
      if (row.archive_size_bytes) {
        res.setHeader('Content-Length', String(row.archive_size_bytes));
      }
      const stream = createReadStream(abs);
      stream.on('error', () => {
        if (!res.headersSent) res.status(500).json({ message: 'Download failed' });
        else res.destroy();
      });
      stream.pipe(res);
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

  app.post('/api/backups/:id/restore/prepare', admin, async (req, res) => {
    if (!isValidRowId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid backup id' });
    }
    const row = await getBackupById(pool, req.params.id);
    if (!row || row.status !== 'completed') {
      return res.status(404).json({ message: 'Completed backup required for restore' });
    }

    // Enqueue safety backup first; restore stays pending until safety completes
    // (CLI also creates safety backup; this pre-flight documents the requirement).
    let safetyRow = null;
    try {
      safetyRow = await enqueueBackup(pool, backupQueue, {
        triggerType: 'safety',
        createdById: actorId(req),
        createdByEmail: actorEmail(req)
      });
    } catch (err) {
      if (err.code === 'CONCURRENT' || err.status === 409) {
        return res.status(409).json({
          message: 'Cannot prepare restore while another backup is running. Wait and retry.'
        });
      }
      return res.status(500).json({ message: publicErrorMessage('SAFETY_FAILED') });
    }

    const restore = await createRestorePrepare(pool, {
      backupRowId: row.id,
      backupId: row.backup_id,
      confirmationPhrase: 'RESTORE',
      preparedById: actorId(req),
      preparedByEmail: actorEmail(req),
      safetyBackupId: safetyRow.backup_id,
      safetyBackupRowId: safetyRow.id
    });

    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.RESTORE_PREPARED,
      entityType: AUDIT_ENTITY.SYSTEM_RESTORE,
      entityId: restore.id,
      entityDisplay: row.backup_id,
      severity: AUDIT_SEVERITY.WARNING,
      metadata: {
        backup_id: row.backup_id,
        restore_id: restore.id,
        safety_backup_id: safetyRow.backup_id
      }
    });
    await auditLogService.auditSuccess({
      req,
      action: AUDIT_ACTION.SAFETY_BACKUP_CREATED,
      entityType: AUDIT_ENTITY.SYSTEM_BACKUP,
      entityId: safetyRow.id,
      entityDisplay: safetyRow.backup_id,
      metadata: {
        backup_id: safetyRow.backup_id,
        restore_id: restore.id,
        trigger_type: 'safety'
      }
    });

    return res.status(202).json({
      restore: serializeRestore(restore),
      safety_backup: serializeBackup(safetyRow),
      impact: {
        warning: 'Restore overwrites the live PostgreSQL database and requires downtime.',
        writers_stopped: [
          'backend',
          'integration-scheduler',
          'integration-worker',
          'ioc-expiration-worker',
          'ioc-search-export-worker',
          'backup-worker'
        ],
        redis_not_restored: true,
        confirmation_required: 'Type RESTORE or the backup_id to confirm.'
      }
    });
  });

  app.post('/api/backups/:id/restore/confirm', admin, async (req, res) => {
    if (!isValidRowId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid backup id' });
    }
    const backup = await getBackupById(pool, req.params.id);
    if (!backup || backup.status !== 'completed') {
      return res.status(404).json({ message: 'Completed backup required' });
    }
    const restoreId = String(req.body?.restore_id || '').trim();
    const confirmation = req.body?.confirmation;
    if (!isValidRowId(restoreId)) {
      return res.status(400).json({ message: 'restore_id is required' });
    }
    if (!isValidRestoreConfirmation(confirmation, backup.backup_id)) {
      await auditLogService.auditFailure({
        req,
        action: AUDIT_ACTION.RESTORE_CONFIRMED,
        entityType: AUDIT_ENTITY.SYSTEM_RESTORE,
        entityId: restoreId,
        entityDisplay: backup.backup_id,
        metadata: { backup_id: backup.backup_id, restore_id: restoreId, error_code: 'CONFIRMATION' }
      });
      return res.status(400).json({ message: publicErrorMessage('CONFIRMATION') });
    }

    const restore = await getRestoreById(pool, restoreId);
    if (!restore || restore.backup_id !== backup.backup_id) {
      return res.status(404).json({ message: 'Restore request not found' });
    }

    // Require safety backup to have completed successfully before marking ready
    if (restore.safety_backup_row_id) {
      const safety = await getBackupById(pool, restore.safety_backup_row_id);
      if (!safety || safety.status !== 'completed') {
        if (safety && ['failed', 'interrupted'].includes(safety.status)) {
          await markRestoreFailed(pool, restore.id, {
            errorCode: 'SAFETY_FAILED',
            errorMessage: 'Safety backup failed'
          });
          return res.status(409).json({ message: publicErrorMessage('SAFETY_FAILED') });
        }
        return res.status(409).json({
          message: 'Safety backup is still running. Wait until it completes, then confirm again.',
          safety_status: safety?.status || null
        });
      }
    }

    try {
      const confirmed = await confirmRestore(pool, restoreId, {
        confirmation,
        expectedBackupId: backup.backup_id,
        confirmedById: actorId(req),
        confirmedByEmail: actorEmail(req)
      });
      await auditLogService.auditSuccess({
        req,
        action: AUDIT_ACTION.RESTORE_CONFIRMED,
        entityType: AUDIT_ENTITY.SYSTEM_RESTORE,
        entityId: confirmed.id,
        entityDisplay: backup.backup_id,
        severity: AUDIT_SEVERITY.CRITICAL,
        metadata: {
          backup_id: backup.backup_id,
          restore_id: confirmed.id,
          result: 'ready'
        }
      });
      return res.json({
        restore: serializeRestore(confirmed),
        next_step: confirmed.cli_command
      });
    } catch (err) {
      if (err.status === 400) {
        return res.status(400).json({ message: publicErrorMessage('CONFIRMATION') });
      }
      if (err.status === 409) {
        return res.status(409).json({ message: err.message });
      }
      return res.status(500).json({ message: 'Failed to confirm restore' });
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
