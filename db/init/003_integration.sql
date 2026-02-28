CREATE TABLE IF NOT EXISTS integration_runs (
  id BIGSERIAL PRIMARY KEY,
  job_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed')),
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  records_processed INT NOT NULL DEFAULT 0,
  error_message TEXT,
  triggered_by TEXT NOT NULL DEFAULT 'scheduler',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_integration_runs_created_at ON integration_runs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integration_runs_status ON integration_runs (status);

CREATE TABLE IF NOT EXISTS integration_checkpoints (
  source_name TEXT PRIMARY KEY,
  last_cursor TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS import_dedup (
  source_name TEXT NOT NULL,
  external_id TEXT NOT NULL,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (source_name, external_id)
);
