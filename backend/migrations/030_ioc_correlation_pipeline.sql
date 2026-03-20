-- ClickHouse -> IOC correlation event pipeline state + dedup-friendly event schema.

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS ioc_type TEXT;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS ioc_item_id BIGINT;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS parser_source TEXT;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS source TEXT;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS match_context JSONB;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS dedup_key TEXT;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS bucket_start TIMESTAMPTZ;

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE ioc_match_events
  ADD COLUMN IF NOT EXISTS hit_count BIGINT NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_ioc_type ON ioc_match_events (ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_match_events_matched_ioc_created_at_desc ON ioc_match_events (matched_ioc, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_match_events_ioc_item_id ON ioc_match_events (ioc_item_id);
CREATE INDEX IF NOT EXISTS idx_ioc_match_events_bucket_start ON ioc_match_events (bucket_start DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_match_events_dedup_bucket
ON ioc_match_events (dedup_key, bucket_start)
WHERE dedup_key IS NOT NULL AND bucket_start IS NOT NULL;

CREATE TABLE IF NOT EXISTS ioc_correlation_state (
  worker_name TEXT PRIMARY KEY,
  last_ts TIMESTAMPTZ NOT NULL DEFAULT to_timestamp(0),
  last_row_hash NUMERIC(20,0) NOT NULL DEFAULT 0,
  batch_size INT NOT NULL DEFAULT 5000,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
