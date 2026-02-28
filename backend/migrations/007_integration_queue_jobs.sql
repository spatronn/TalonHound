CREATE TABLE IF NOT EXISTS integration_queue_jobs (
  job_id TEXT PRIMARY KEY,
  integration_key TEXT NOT NULL,
  job_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','running','success','failed')),
  triggered_by TEXT,
  queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  records_processed INT NOT NULL DEFAULT 0,
  error_message TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_integration_queue_jobs_queued_at ON integration_queue_jobs (queued_at DESC);
CREATE INDEX IF NOT EXISTS idx_integration_queue_jobs_status ON integration_queue_jobs (status);
