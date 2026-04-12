-- Extend IOC match analyst workflow: in_progress + ownership metadata.

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS assigned_to TEXT,
  ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ;

ALTER TABLE ioc_match_events
  DROP CONSTRAINT IF EXISTS chk_ioc_match_events_verdict;

ALTER TABLE ioc_match_events
  ADD CONSTRAINT chk_ioc_match_events_verdict
  CHECK (verdict IS NULL OR verdict IN ('fp', 'tp', 'suspicious', 'in_progress'));

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_assigned_to
  ON ioc_match_events (assigned_to);

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_assigned_at_desc
  ON ioc_match_events (assigned_at DESC);
