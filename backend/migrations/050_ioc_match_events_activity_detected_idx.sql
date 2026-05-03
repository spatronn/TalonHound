-- Speed up incident event list query
CREATE INDEX IF NOT EXISTS idx_ioc_match_events_activity_detected
  ON ioc_match_events (activity_id, COALESCE(last_seen_at, event_time, created_at) DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_activity_verdict
  ON ioc_match_events (activity_id, verdict);
