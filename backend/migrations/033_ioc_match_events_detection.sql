-- Realtime vs retro and parser vs generic provenance for IOC match events.

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS detection_type TEXT;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS match_source TEXT;

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_detection_type
  ON ioc_match_events (detection_type);
