-- System backup & restore operation records.
--
-- Backup artifacts live on the dedicated backup_data volume (BACKUP_DIR).
-- Rows track lifecycle, verification, and restore prepare/confirm state.
-- Actual pg_restore is executed by a privileged host CLI (scripts/restore-stack.sh),
-- not by the live API process.

CREATE TABLE IF NOT EXISTS system_backups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  backup_id TEXT NOT NULL UNIQUE,
  trigger_type TEXT NOT NULL DEFAULT 'manual'
    CHECK (trigger_type IN ('manual', 'scheduled', 'safety')),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'verifying', 'completed', 'failed', 'deleted', 'interrupted')),
  started_at TIMESTAMPTZ NULL,
  completed_at TIMESTAMPTZ NULL,
  duration_ms BIGINT NULL,
  archive_path TEXT NULL,
  archive_filename TEXT NULL,
  archive_size_bytes BIGINT NULL,
  checksum_sha256 TEXT NULL,
  encrypted BOOLEAN NOT NULL DEFAULT FALSE,
  database_size_bytes BIGINT NULL,
  files_size_bytes BIGINT NULL DEFAULT 0,
  error_code TEXT NULL,
  error_message TEXT NULL,
  verified_at TIMESTAMPTZ NULL,
  verify_status TEXT NULL
    CHECK (verify_status IS NULL OR verify_status IN ('pending', 'passed', 'failed')),
  verify_error TEXT NULL,
  manifest JSONB NULL,
  job_id TEXT NULL,
  created_by_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
  created_by_email TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_backups_status_created
  ON system_backups (status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_system_backups_active
  ON system_backups (status)
  WHERE status IN ('queued', 'running', 'verifying');

CREATE INDEX IF NOT EXISTS idx_system_backups_completed_created
  ON system_backups (created_at DESC)
  WHERE status = 'completed';

CREATE TABLE IF NOT EXISTS system_restores (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  backup_row_id UUID NULL REFERENCES system_backups(id) ON DELETE SET NULL,
  backup_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending_confirmation'
    CHECK (status IN ('pending_confirmation', 'ready', 'running', 'completed', 'failed', 'cancelled')),
  confirmation_phrase TEXT NOT NULL,
  safety_backup_id TEXT NULL,
  safety_backup_row_id UUID NULL REFERENCES system_backups(id) ON DELETE SET NULL,
  cli_command TEXT NULL,
  prepared_by_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
  prepared_by_email TEXT NULL,
  confirmed_by_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
  confirmed_by_email TEXT NULL,
  error_code TEXT NULL,
  error_message TEXT NULL,
  prepared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confirmed_at TIMESTAMPTZ NULL,
  started_at TIMESTAMPTZ NULL,
  completed_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_restores_status
  ON system_restores (status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_system_restores_backup_id
  ON system_restores (backup_id);

-- DEPLOYMENT
-- Forward-only additive migration. Apply before starting backup-worker.
-- Rollback (ops only; loses backup/restore history rows, not archives on disk):
--   DROP TABLE IF EXISTS system_restores;
--   DROP TABLE IF EXISTS system_backups;
