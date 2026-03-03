CREATE TABLE IF NOT EXISTS dashboard_map_country_totals (
  country_code TEXT PRIMARY KEY,
  total BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dashboard_map_job_state (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
  last_processed_ioc_id BIGINT NOT NULL DEFAULT 0,
  full_rebuild_pending BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_run_at TIMESTAMPTZ
);

INSERT INTO dashboard_map_job_state (singleton, last_processed_ioc_id, full_rebuild_pending)
VALUES (TRUE, 0, TRUE)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS dashboard_map_pending_events (
  id BIGSERIAL PRIMARY KEY,
  event_type TEXT NOT NULL CHECK (event_type IN ('add','delete')),
  ioc_id BIGINT,
  observable TEXT NOT NULL,
  observable_type TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dashboard_map_pending_events_created_at
ON dashboard_map_pending_events (created_at ASC);

CREATE INDEX IF NOT EXISTS idx_dashboard_map_pending_events_ioc_id
ON dashboard_map_pending_events (ioc_id);
