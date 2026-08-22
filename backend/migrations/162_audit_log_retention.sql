-- Audit Log Retention / Lifecycle.
--
-- Centrally managed retention window for the audit_logs table, stored on the
-- canonical singleton system_settings row (id = 1) alongside the other
-- platform-wide configuration (see 129_system_timezone_settings.sql).
--
-- Representation:
--   audit_log_retention_days = 365   -> keep 365 days, delete older automatically
--   audit_log_retention_days = NULL  -> "Keep forever" (no deletion)
--
-- This migration ONLY establishes schema/default/config. It never deletes any
-- historical audit rows: actual retention deletion is performed after deploy by
-- the bounded, batched cleanup owned by the ioc-expiration maintenance worker,
-- so a migration can never spend a long time deleting a large audit table.
--
-- No new index is added: audit_logs already carries
-- audit_logs_created_at_desc_idx ON (created_at DESC), which serves the
-- "created_at < cutoff ORDER BY created_at" batch-delete access pattern.

-- system_settings is created in 129; guard defensively in case ordering differs.
CREATE TABLE IF NOT EXISTS system_settings (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1)
);

ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS audit_log_retention_days INTEGER DEFAULT 365,
  ADD COLUMN IF NOT EXISTS audit_log_retention_updated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS audit_log_retention_updated_by TEXT,
  ADD COLUMN IF NOT EXISTS audit_log_retention_last_run_at TIMESTAMPTZ;

-- Positive-integer-or-NULL invariant enforced server-side too; the DB is the
-- final backstop. NULL is the explicit "Keep forever" value.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'system_settings_audit_log_retention_days_check'
  ) THEN
    ALTER TABLE system_settings
      ADD CONSTRAINT system_settings_audit_log_retention_days_check
      CHECK (audit_log_retention_days IS NULL OR audit_log_retention_days >= 1);
  END IF;
END $$;

-- Ensure the singleton row exists so existing installs have a value to read.
INSERT INTO system_settings (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;

-- Existing installations end up with the 365-day default. The ADD COLUMN DEFAULT
-- above backfills new columns on the existing row, but set it explicitly so an
-- install whose row predates this column is unambiguous (only touches rows that
-- have no value yet — never overrides a deliberate NULL/"Keep forever" choice made
-- after this migration, since this runs exactly once).
UPDATE system_settings
   SET audit_log_retention_days = 365
 WHERE id = 1
   AND audit_log_retention_days IS NULL
   AND audit_log_retention_updated_at IS NULL;

COMMENT ON COLUMN system_settings.audit_log_retention_days IS
  'Audit log retention window in days. NULL = Keep forever (no automatic deletion). Rows older than the cutoff are deleted by the bounded daily cleanup job.';
COMMENT ON COLUMN system_settings.audit_log_retention_last_run_at IS
  'Last time the audit log retention cleanup job completed a run (observability + daily gate).';
