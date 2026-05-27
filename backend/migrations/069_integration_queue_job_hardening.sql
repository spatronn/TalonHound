ALTER TABLE integration_queue_jobs
  ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS worker_id TEXT,
  ADD COLUMN IF NOT EXISTS worker_hostname TEXT,
  ADD COLUMN IF NOT EXISTS failure_type TEXT;

CREATE INDEX IF NOT EXISTS idx_integration_queue_jobs_running_source
  ON integration_queue_jobs (integration_key, status)
  WHERE status = 'running';

CREATE INDEX IF NOT EXISTS idx_integration_queue_jobs_heartbeat_at
  ON integration_queue_jobs (heartbeat_at)
  WHERE status = 'running';
