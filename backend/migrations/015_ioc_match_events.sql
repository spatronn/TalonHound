CREATE TABLE IF NOT EXISTS ioc_match_events (
  id BIGSERIAL PRIMARY KEY,
  signal_event_id BIGINT,
  event_time TIMESTAMPTZ NOT NULL,
  host_name TEXT,
  process_name TEXT,
  destination_ip TEXT,
  destination_port INT,
  protocol TEXT,
  matched_ioc TEXT NOT NULL,
  source_name TEXT,
  confidence TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_match_events_created_at_desc ON ioc_match_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_match_events_destination_ip ON ioc_match_events (destination_ip);
