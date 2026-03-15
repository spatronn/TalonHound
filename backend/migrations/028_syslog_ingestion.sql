ALTER TABLE signal_sources
  ADD COLUMN IF NOT EXISTS source_ip TEXT,
  ADD COLUMN IF NOT EXISTS protocol TEXT,
  ADD COLUMN IF NOT EXISTS event_count BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_signal_sources_source_ip ON signal_sources (source_ip);
CREATE INDEX IF NOT EXISTS idx_signal_sources_protocol ON signal_sources (protocol);

ALTER TABLE signal_events
  ADD COLUMN IF NOT EXISTS source_ip TEXT,
  ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS raw_event TEXT;

CREATE INDEX IF NOT EXISTS idx_signal_events_received_at_desc ON signal_events (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_signal_events_source_ip ON signal_events (source_ip);
