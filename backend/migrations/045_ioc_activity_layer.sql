CREATE TABLE IF NOT EXISTS ioc_activity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ioc_value TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  total_hits BIGINT NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open',
  verdict TEXT NOT NULL DEFAULT 'Unreviewed',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_ioc_activity_status CHECK (status IN ('open', 'closed')),
  CONSTRAINT chk_ioc_activity_verdict CHECK (verdict IN ('TP', 'FP', 'Suspicious', 'Unreviewed', 'In Progress'))
);

-- Same IOC can have only one open activity at a time.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_activity_one_open_per_ioc
  ON ioc_activity (ioc_value, ioc_type)
  WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_ioc_activity_ioc_status_last_seen
  ON ioc_activity (ioc_value, ioc_type, status, last_seen DESC);

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS activity_id UUID;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'fk_ioc_match_events_activity_id'
  ) THEN
    ALTER TABLE ioc_match_events
      ADD CONSTRAINT fk_ioc_match_events_activity_id
      FOREIGN KEY (activity_id)
      REFERENCES ioc_activity(id)
      ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_activity_id
  ON ioc_match_events (activity_id);
