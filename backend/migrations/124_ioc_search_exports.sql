-- Asynchronous IOC search exports.
--
-- A row is created when a user requests an export of a DSL search result set. The
-- export is produced out-of-band by the ioc-search-export worker (BullMQ queue
-- "ioc-search-export"), which re-parses normalized_query and streams the result to a
-- CSV / gzip file on disk. The row tracks lifecycle, progress and the on-disk artifact.
--
-- Ownership is keyed on requested_by_email (always present) so "my exports" scoping
-- works even for sessions that carry no numeric user id. requested_by_id is stored when
-- available for auditing.

CREATE TABLE IF NOT EXISTS ioc_search_exports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  original_query TEXT NOT NULL,
  normalized_query TEXT NOT NULL,
  normalized_ast JSONB NOT NULL,
  format TEXT NOT NULL DEFAULT 'csv'
    CHECK (format IN ('csv', 'csv_gz')),
  selected_columns TEXT[] NOT NULL,
  scope TEXT NOT NULL DEFAULT 'all'
    CHECK (scope IN ('all', 'preview')),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'processing', 'ready', 'failed', 'expired', 'cancelled')),
  -- users.id is BIGSERIAL; keep the export row (audit trail) if the user is deleted.
  requested_by_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
  requested_by_email TEXT NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ NULL,
  completed_at TIMESTAMPTZ NULL,
  -- Stable export boundary (NOT a transactional snapshot): rows created after this
  -- instant are excluded so pagination does not shift while the export streams. It does
  -- not freeze mutable status/tag/classification/membership data.
  snapshot_cutoff TIMESTAMPTZ NULL,
  record_count BIGINT NULL,
  file_size BIGINT NULL,
  storage_path TEXT NULL,
  progress INTEGER NOT NULL DEFAULT 0
    CHECK (progress >= 0 AND progress <= 100),
  expires_at TIMESTAMPTZ NULL,
  failure_reason TEXT NULL,
  cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
  cancelled_at TIMESTAMPTZ NULL,
  retry_count INTEGER NOT NULL DEFAULT 0,
  job_id TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_search_exports_owner
  ON ioc_search_exports (requested_by_email, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_search_exports_status
  ON ioc_search_exports (status);

-- Active-per-user concurrency checks and expiry sweeps read these subsets.
CREATE INDEX IF NOT EXISTS idx_ioc_search_exports_active
  ON ioc_search_exports (requested_by_email)
  WHERE status IN ('queued', 'processing');

CREATE INDEX IF NOT EXISTS idx_ioc_search_exports_expiry
  ON ioc_search_exports (expires_at)
  WHERE status = 'ready' AND expires_at IS NOT NULL;

-- DEPLOYMENT / ROLLBACK
-- ---------------------
-- Forward: purely additive — creates one new table and its indexes. No existing table
-- is altered, so it is safe to apply before or during the backend/worker rollout. The
-- migrate runner wraps each file in a single transaction; every statement here is
-- transaction-safe (no CREATE INDEX CONCURRENTLY). All indexes are plain B-tree on a
-- new/empty table, so there is no long lock or table rewrite.
--
-- The ioc-search-export worker tolerates this table being absent (bounded wait +
-- graceful per-job failure), so ordering between "npm run migrate" and worker start is
-- not fragile. Recommended deploy order: apply migrations, then (re)start backend +
-- worker.
--
-- Rollback (no data loss for any other table):
--   DROP TABLE IF EXISTS ioc_search_exports;
-- On-disk export artifacts under IOC_EXPORT_STORAGE_DIR are orphaned by a rollback and
-- can be removed manually; they are never web-served except through the authenticated
-- download route.
