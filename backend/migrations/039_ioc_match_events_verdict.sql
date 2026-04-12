-- Analyst verdict metadata for IOC match review workflow.

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS verdict TEXT,
  ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS reviewed_by TEXT,
  ADD COLUMN IF NOT EXISTS note TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_ioc_match_events_verdict'
  ) THEN
    ALTER TABLE ioc_match_events
      ADD CONSTRAINT chk_ioc_match_events_verdict
      CHECK (verdict IS NULL OR verdict IN ('fp', 'tp', 'suspicious'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_verdict
  ON ioc_match_events (verdict);

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_reviewed_at_desc
  ON ioc_match_events (reviewed_at DESC);
