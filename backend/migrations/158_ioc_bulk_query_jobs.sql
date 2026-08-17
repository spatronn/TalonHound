-- Query-wide IOC bulk triage jobs (Action Center).
-- PAGE-mode explicit IDs stay on the existing /api/iocs/bulk/* routes.
-- This table holds asynchronous all_matching operations that exceed the
-- synchronous HTTP budget. Target IDs are materialized at worker start
-- so execution cannot drift to a different query.

CREATE TABLE IF NOT EXISTS ioc_bulk_query_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action TEXT NOT NULL
    CHECK (action IN ('tag', 'classification', 'suppress', 'expire')),
  original_query TEXT NOT NULL,
  normalized_query TEXT NOT NULL,
  normalized_ast JSONB NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'processing', 'completed', 'failed', 'cancelled', 'expired')),
  match_count BIGINT NULL,
  succeeded BIGINT NOT NULL DEFAULT 0,
  skipped BIGINT NOT NULL DEFAULT 0,
  failed BIGINT NOT NULL DEFAULT 0,
  progress INTEGER NOT NULL DEFAULT 0
    CHECK (progress >= 0 AND progress <= 100),
  error_sample JSONB NULL,
  requested_by_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
  requested_by_email TEXT NOT NULL,
  requested_by_public_id TEXT NULL,
  requested_by_role TEXT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ NULL,
  completed_at TIMESTAMPTZ NULL,
  snapshot_cutoff TIMESTAMPTZ NULL,
  expires_at TIMESTAMPTZ NULL,
  failure_reason TEXT NULL,
  cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
  cancelled_at TIMESTAMPTZ NULL,
  job_id TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_bulk_query_jobs_requester_created
  ON ioc_bulk_query_jobs (requested_by_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_bulk_query_jobs_status_created
  ON ioc_bulk_query_jobs (status, created_at DESC);

CREATE TABLE IF NOT EXISTS ioc_bulk_query_job_targets (
  job_id UUID NOT NULL REFERENCES ioc_bulk_query_jobs(id) ON DELETE CASCADE,
  ioc_item_id BIGINT NOT NULL,
  PRIMARY KEY (job_id, ioc_item_id)
);

CREATE INDEX IF NOT EXISTS idx_ioc_bulk_query_job_targets_job
  ON ioc_bulk_query_job_targets (job_id, ioc_item_id);

-- DEPLOYMENT / ROLLBACK
-- ---------------------
-- Forward: additive tables + indexes. Transaction-safe (no CONCURRENTLY).
-- Rollback: DROP TABLE IF EXISTS ioc_bulk_query_job_targets;
--           DROP TABLE IF EXISTS ioc_bulk_query_jobs;
