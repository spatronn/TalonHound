CREATE TABLE IF NOT EXISTS signal_sources (
  id BIGSERIAL PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS signal_events (
  id BIGSERIAL PRIMARY KEY,
  source_key TEXT NOT NULL,
  event_time TIMESTAMPTZ NOT NULL,
  host_name TEXT,
  username TEXT,
  process_name TEXT,
  process_id TEXT,
  destination_ip TEXT,
  destination_port INT,
  protocol TEXT,
  score INT NOT NULL DEFAULT 0,
  reason_codes TEXT[] NOT NULL DEFAULT '{}',
  raw JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signal_events_event_time ON signal_events (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_signal_events_source_key ON signal_events (source_key);
CREATE INDEX IF NOT EXISTS idx_signal_events_destination_ip ON signal_events (destination_ip);
