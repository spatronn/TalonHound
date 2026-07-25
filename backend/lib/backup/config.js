// Env-driven configuration for system backup & restore operations.

import fs from 'node:fs';
import path from 'node:path';
import {
  getSystemScheduleTimezone,
  normalizeScheduleTimezone
} from '../integrationSchedule.js';

export const BACKUP_FORMAT_VERSION = 2;
export const APPLICATION_NAME = 'TalonHound';

function intFromEnv(name, fallback, { min, max } = {}) {
  const raw = Number(process.env[name]);
  let value = Number.isFinite(raw) ? Math.trunc(raw) : fallback;
  if (typeof min === 'number') value = Math.max(value, min);
  if (typeof max === 'number') value = Math.min(value, max);
  return value;
}

function boolFromEnv(name, fallback = false) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(raw).trim().toLowerCase());
}

export function getBackupConfig() {
  const encryptionEnabled = boolFromEnv('BACKUP_ENCRYPTION_ENABLED', false);
  const keyFile = String(process.env.BACKUP_ENCRYPTION_KEY_FILE || '').trim() || null;
  const timezone = normalizeScheduleTimezone(
    process.env.BACKUP_CRON_TIMEZONE || getSystemScheduleTimezone()
  );
  return {
    enabled: boolFromEnv('BACKUP_ENABLED', true),
    cron: String(process.env.BACKUP_CRON || '0 0 * * 0').trim(),
    timezone,
    retentionDays: intFromEnv('BACKUP_RETENTION_DAYS', 30, { min: 1, max: 3650 }),
    backupDir: String(process.env.BACKUP_DIR || '/data/backups'),
    encryptionEnabled,
    encryptionKeyFile: keyFile,
    storageProvider: 'local',
    maxConcurrent: intFromEnv('BACKUP_MAX_CONCURRENT', 1, { min: 1, max: 1 }),
    queueName: String(process.env.BACKUP_QUEUE_NAME || 'system-backup'),
    staleRunningMinutes: intFromEnv('BACKUP_STALE_RUNNING_MINUTES', 180, { min: 30, max: 24 * 60 }),
    pgDumpTimeoutMs: intFromEnv('BACKUP_PG_DUMP_TIMEOUT_MS', 2 * 60 * 60 * 1000, { min: 60_000 }),
    db: {
      host: String(process.env.DB_HOST || 'db'),
      port: Number(process.env.DB_PORT || 5432),
      user: String(process.env.DB_USER || 'demo'),
      password: process.env.DB_PASSWORD || '',
      database: String(process.env.DB_NAME || 'demo')
    }
  };
}

export const BACKUP_QUEUE_NAME = process.env.BACKUP_QUEUE_NAME || 'system-backup';

export const BACKUP_INCLUDED = Object.freeze([
  'postgresql'
]);

export const BACKUP_EXCLUDED = Object.freeze([
  'redis',
  'env_secrets',
  'tls_certs',
  'ioc_search_exports',
  'node_modules',
  'frontend_build',
  'docker_images',
  'application_logs',
  'repository_source',
  'clickhouse'
]);

/** Resolve a path under BACKUP_DIR; reject traversal. */
export function resolveBackupPath(backupDir, relativeOrName) {
  const base = path.resolve(backupDir);
  const resolved = path.resolve(base, relativeOrName);
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    throw new Error('Resolved backup path escapes storage directory');
  }
  return resolved;
}

export function ensureBackupDir(backupDir) {
  fs.mkdirSync(backupDir, { recursive: true });
  const tmp = path.join(backupDir, '.tmp');
  fs.mkdirSync(tmp, { recursive: true });
  return backupDir;
}

export function loadEncryptionKey(cfg = getBackupConfig()) {
  if (!cfg.encryptionEnabled) return null;
  if (!cfg.encryptionKeyFile) {
    throw new Error('BACKUP_ENCRYPTION_ENABLED requires BACKUP_ENCRYPTION_KEY_FILE');
  }
  const raw = fs.readFileSync(cfg.encryptionKeyFile);
  const key = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw).trim(), 'utf8');
  // Accept 32 raw bytes or hex-encoded 64-char key.
  if (key.length === 32) return key;
  const asText = key.toString('utf8').trim();
  if (/^[0-9a-fA-F]{64}$/.test(asText)) return Buffer.from(asText, 'hex');
  throw new Error('Encryption key must be 32 bytes or 64 hex characters');
}
