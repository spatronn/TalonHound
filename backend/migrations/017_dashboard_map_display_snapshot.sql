CREATE TABLE IF NOT EXISTS dashboard_map_display_snapshot (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
  snapshot_time TIMESTAMPTZ NOT NULL,
  total_records BIGINT NOT NULL DEFAULT 0,
  unique_ips BIGINT NOT NULL DEFAULT 0,
  countries JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE dashboard_map_job_state
ADD COLUMN IF NOT EXISTS snapshot_last_refreshed_at TIMESTAMPTZ;
