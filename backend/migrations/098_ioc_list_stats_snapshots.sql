-- Cached IOC List header stats (global active counts). Refreshed on schedule, not on every page load.

CREATE TABLE IF NOT EXISTS ioc_list_stats_snapshots (
  id BIGSERIAL PRIMARY KEY,
  snapshot_key TEXT NOT NULL UNIQUE,
  payload JSONB NOT NULL,
  calculated_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_list_stats_snapshots_key_calculated
  ON ioc_list_stats_snapshots (snapshot_key, calculated_at DESC);
