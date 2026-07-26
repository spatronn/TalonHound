-- Immutable per-job result snapshot for Job Queue Status history.
-- Aligns queue counters with integration_runs and adds result_code/summary/details.
-- No backfill: legacy rows keep NULL snapshot fields (UI: Result unavailable).

ALTER TABLE integration_queue_jobs
  ADD COLUMN IF NOT EXISTS records_unchanged INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS records_reactivated INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS records_removed INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS result_code TEXT NULL,
  ADD COLUMN IF NOT EXISTS result_summary TEXT NULL,
  ADD COLUMN IF NOT EXISTS result_details JSONB NULL,
  ADD COLUMN IF NOT EXISTS run_mode TEXT NULL;

COMMENT ON COLUMN integration_queue_jobs.records_unchanged IS
  'Rows seen again with identical content. Written once at job completion.';
COMMENT ON COLUMN integration_queue_jobs.records_reactivated IS
  'Previously inactive memberships that returned. Written once at job completion.';
COMMENT ON COLUMN integration_queue_jobs.records_removed IS
  'Memberships marked missing/inactive by full reconciliation. Written once at completion.';
COMMENT ON COLUMN integration_queue_jobs.result_code IS
  'Canonical job result code (e.g. COMPLETED_WITH_CHANGES). NULL = legacy/no snapshot.';
COMMENT ON COLUMN integration_queue_jobs.result_summary IS
  'Human-readable result summary for Job Queue Result column. NULL = legacy/no snapshot.';
COMMENT ON COLUMN integration_queue_jobs.result_details IS
  'Immutable whitelist JSON snapshot of run metrics. NULL = legacy/no snapshot.';
COMMENT ON COLUMN integration_queue_jobs.run_mode IS
  'Run mode when applicable (incremental, full_reconciliation). NULL when not set.';
