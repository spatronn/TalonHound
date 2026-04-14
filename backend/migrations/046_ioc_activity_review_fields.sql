ALTER TABLE ioc_activity
  ADD COLUMN IF NOT EXISTS note TEXT,
  ADD COLUMN IF NOT EXISTS assigned_to TEXT,
  ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_ioc_activity_status_last_seen
  ON ioc_activity (status, last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_activity_verdict_last_seen
  ON ioc_activity (verdict, last_seen DESC);
