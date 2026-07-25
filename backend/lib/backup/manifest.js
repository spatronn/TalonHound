// Backup manifest build / parse (format version 2).

import {
  APPLICATION_NAME,
  BACKUP_EXCLUDED,
  BACKUP_FORMAT_VERSION,
  BACKUP_INCLUDED
} from './config.js';

/**
 * @param {object} input
 */
export function buildManifest(input) {
  const {
    backupId,
    createdAt = new Date().toISOString(),
    gitSha = null,
    appVersion = null,
    schemaVersion = null,
    postgresVersion = null,
    triggerType = 'manual',
    result = 'completed',
    encrypted = false,
    compression = 'gzip',
    components = {},
    checksums = {},
    excluded = [...BACKUP_EXCLUDED],
    included = [...BACKUP_INCLUDED]
  } = input;

  return {
    format_version: BACKUP_FORMAT_VERSION,
    backup_id: backupId,
    created_at: createdAt.endsWith('Z') ? createdAt : new Date(createdAt).toISOString(),
    application: APPLICATION_NAME,
    application_version: appVersion,
    git_sha: gitSha,
    database_schema_version: schemaVersion,
    postgres_version: postgresVersion,
    trigger_type: triggerType,
    result,
    encrypted: Boolean(encrypted),
    compression,
    included_components: included,
    excluded_components: excluded,
    components: {
      postgres: {
        file: 'database/postgres.dump',
        format: 'pg_custom',
        bytes: Number(components.postgresBytes || 0)
      },
      ...(Number(components.filesBytes || 0) > 0
        ? { files: { path: 'files/', bytes: Number(components.filesBytes) } }
        : {})
    },
    component_sizes: {
      database_bytes: Number(components.postgresBytes || 0),
      files_bytes: Number(components.filesBytes || 0),
      archive_bytes: Number(components.archiveBytes || 0)
    },
    checksums,
    restore: {
      method: 'cli',
      script: 'scripts/restore-stack.sh',
      api_restore_writes_data: false
    }
  };
}

export function parseManifest(raw) {
  const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!data || typeof data !== 'object') {
    throw new Error('Invalid manifest');
  }
  const formatVersion = Number(data.format_version ?? data.version ?? 1);
  if (!Number.isFinite(formatVersion) || formatVersion < 1 || formatVersion > BACKUP_FORMAT_VERSION) {
    throw new Error(`Unsupported backup format version: ${formatVersion}`);
  }
  const backupId = data.backup_id || data.bundle;
  if (!backupId) throw new Error('Manifest missing backup_id');
  return { ...data, format_version: formatVersion, backup_id: backupId };
}

export function isCompatibleFormatVersion(version) {
  const v = Number(version);
  return Number.isFinite(v) && v >= 1 && v <= BACKUP_FORMAT_VERSION;
}
