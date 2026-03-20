CREATE TABLE IF NOT EXISTS ioc_correlation_ioc_state (
  ioc_key TEXT PRIMARY KEY,
  ioc_type TEXT NOT NULL,
  ioc_value TEXT NOT NULL,
  last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_correlation_ioc_state_last_checked
ON ioc_correlation_ioc_state (last_checked_at DESC);
