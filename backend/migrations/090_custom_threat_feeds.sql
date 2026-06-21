-- Custom Threat Feeds: URL-sync TI feeds linked to integration_feeds (feed_kind = custom).

CREATE TABLE IF NOT EXISTS custom_threat_feeds (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_id UUID NOT NULL UNIQUE REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  url_host TEXT NOT NULL,
  format TEXT NOT NULL DEFAULT 'auto'
    CHECK (format IN ('auto', 'txt', 'csv')),
  ioc_type_mode TEXT NOT NULL DEFAULT 'auto'
    CHECK (ioc_type_mode IN ('auto', 'fixed')),
  fixed_ioc_type TEXT NULL
    CHECK (fixed_ioc_type IS NULL OR fixed_ioc_type IN ('domain', 'ip', 'url', 'file_hash')),
  default_confidence TEXT NOT NULL DEFAULT 'medium'
    CHECK (default_confidence IN ('low', 'medium', 'high')),
  sync_interval_minutes INTEGER NOT NULL DEFAULT 60
    CHECK (sync_interval_minutes >= 5 AND sync_interval_minutes <= 10080),
  expire_missing BOOLEAN NOT NULL DEFAULT TRUE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  timeout_ms INTEGER NOT NULL DEFAULT 30000
    CHECK (timeout_ms >= 1000 AND timeout_ms <= 300000),
  description TEXT NULL,
  deactivated_at TIMESTAMPTZ NULL,
  created_by UUID NULL,
  created_by_username TEXT NULL,
  updated_by UUID NULL,
  updated_by_username TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_threat_feeds_enabled
  ON custom_threat_feeds (enabled)
  WHERE enabled = TRUE AND deactivated_at IS NULL;

CREATE TABLE IF NOT EXISTS custom_threat_feed_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_id UUID NOT NULL REFERENCES custom_threat_feeds (id) ON DELETE CASCADE,
  integration_feed_id UUID NOT NULL REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  queue_job_id TEXT NULL,
  status TEXT NOT NULL DEFAULT 'running'
    CHECK (status IN ('running', 'success', 'partial_success', 'failed')),
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ NULL,
  duration_ms INTEGER NULL,
  fetched_bytes INTEGER NULL,
  http_status INTEGER NULL,
  total_rows INTEGER NOT NULL DEFAULT 0,
  valid_rows INTEGER NOT NULL DEFAULT 0,
  invalid_rows INTEGER NOT NULL DEFAULT 0,
  inserted INTEGER NOT NULL DEFAULT 0,
  updated INTEGER NOT NULL DEFAULT 0,
  refreshed INTEGER NOT NULL DEFAULT 0,
  expired_missing INTEGER NOT NULL DEFAULT 0,
  duplicate_rows INTEGER NOT NULL DEFAULT 0,
  error_message TEXT NULL,
  invalid_samples JSONB NULL,
  triggered_by TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_threat_feed_runs_feed_started
  ON custom_threat_feed_runs (feed_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_custom_threat_feed_runs_integration_feed
  ON custom_threat_feed_runs (integration_feed_id, started_at DESC);
