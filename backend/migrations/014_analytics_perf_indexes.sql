CREATE INDEX IF NOT EXISTS idx_signal_events_created_at_desc ON signal_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_signal_events_destination_ip_created_at ON signal_events (destination_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_items_observable_type_observable ON ioc_items (observable_type, observable);
