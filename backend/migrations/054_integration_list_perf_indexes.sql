-- Speed up GET /api/integrations latest run / queue lookups (DISTINCT ON per key/type).

CREATE INDEX IF NOT EXISTS idx_integration_runs_job_type_started_at
  ON integration_runs (job_type, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_integration_queue_jobs_key_latest
  ON integration_queue_jobs (integration_key, COALESCE(started_at, queued_at) DESC);

CREATE INDEX IF NOT EXISTS idx_integration_queue_jobs_queued_at_desc
  ON integration_queue_jobs (queued_at DESC);
