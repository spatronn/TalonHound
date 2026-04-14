-- Backfill helper index for unresolved IOC match events grouped by IOC/time.
CREATE INDEX IF NOT EXISTS idx_ioc_match_events_backfill_null_activity
  ON ioc_match_events (matched_ioc, ioc_type, COALESCE(bucket_start, first_seen_at, event_time, created_at), id)
  WHERE activity_id IS NULL;
