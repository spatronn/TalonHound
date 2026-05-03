ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS normalized_event_json JSONB,
  ADD COLUMN IF NOT EXISTS raw_log_snapshot TEXT,
  ADD COLUMN IF NOT EXISTS raw_log_hash TEXT,
  ADD COLUMN IF NOT EXISTS syslog_log_id TEXT,
  ADD COLUMN IF NOT EXISTS source_type TEXT;

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_syslog_log_id
  ON ioc_match_events (syslog_log_id);
