-- Published threat feeds (snapshot-based export for internal security products).

CREATE TABLE IF NOT EXISTS published_feeds (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ioc_type TEXT NOT NULL,
  format TEXT NOT NULL DEFAULT 'txt',
  min_confidence INTEGER,
  include_sources JSONB,
  include_tags JSONB,
  exclude_tags JSONB,
  exclude_false_positive BOOLEAN NOT NULL DEFAULT TRUE,
  exclude_expired BOOLEAN NOT NULL DEFAULT TRUE,
  verdict_filter JSONB,
  time_window TEXT NOT NULL DEFAULT 'all',
  max_items INTEGER,
  refresh_interval_minutes INTEGER NOT NULL DEFAULT 15,
  last_generated_at TIMESTAMPTZ,
  last_status TEXT,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_published_feeds_ioc_type CHECK (ioc_type IN ('ip', 'domain', 'url', 'hash')),
  CONSTRAINT chk_published_feeds_format CHECK (format IN ('txt')),
  CONSTRAINT chk_published_feeds_time_window CHECK (time_window IN ('1d', '3d', '7d', 'all')),
  CONSTRAINT chk_published_feeds_refresh_interval CHECK (refresh_interval_minutes >= 5)
);

CREATE INDEX IF NOT EXISTS idx_published_feeds_enabled ON published_feeds (enabled);
CREATE INDEX IF NOT EXISTS idx_published_feeds_ioc_type ON published_feeds (ioc_type);

CREATE TABLE IF NOT EXISTS published_feed_access_keys (
  id BIGSERIAL PRIMARY KEY,
  feed_id BIGINT NOT NULL REFERENCES published_feeds(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  last_used_at TIMESTAMPTZ,
  last_used_ip TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  CONSTRAINT uq_published_feed_access_keys_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_published_feed_access_keys_feed_id ON published_feed_access_keys (feed_id);
CREATE INDEX IF NOT EXISTS idx_published_feed_access_keys_enabled ON published_feed_access_keys (enabled) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS published_feed_snapshots (
  id BIGSERIAL PRIMARY KEY,
  feed_id BIGINT NOT NULL REFERENCES published_feeds(id) ON DELETE CASCADE,
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  item_count INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT,
  content TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'success',
  error_message TEXT,
  params JSONB
);

CREATE INDEX IF NOT EXISTS idx_published_feed_snapshots_feed_generated
  ON published_feed_snapshots (feed_id, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_published_feed_snapshots_params_lookup
  ON published_feed_snapshots (feed_id, ((params->>'ioc_type')), ((params->>'window')), generated_at DESC)
  WHERE status = 'success';
