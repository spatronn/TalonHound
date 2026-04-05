-- Snapshot fields for IOC match counts sourced from ClickHouse aggregation.
ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS match_count BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS first_seen_log TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_seen_log TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS ioc_match_count_snapshot (
  observable_value TEXT PRIMARY KEY,
  match_count BIGINT NOT NULL DEFAULT 0,
  first_seen_log TIMESTAMPTZ,
  last_seen_log TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_match_count_snapshot_updated_at
  ON ioc_match_count_snapshot (updated_at DESC);
