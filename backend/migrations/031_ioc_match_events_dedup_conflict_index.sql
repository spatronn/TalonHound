-- Ensure ON CONFLICT (dedup_key, bucket_start) has a matching unique index.
DROP INDEX IF EXISTS uq_ioc_match_events_dedup_bucket;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_match_events_dedup_bucket
ON ioc_match_events (dedup_key, bucket_start);
