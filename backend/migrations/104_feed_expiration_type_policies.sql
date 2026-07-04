-- IOC-type-based expiration policy overrides for feed expiration.
-- A type override takes precedence over the feed-level default policy
-- (threat_feed_expiration_policies, observable_type = 'all').
-- Backward compatible: no existing rows are modified; feeds without a type
-- override continue to inherit the feed-level default exactly as before.

CREATE TABLE IF NOT EXISTS integration_feed_expiration_type_policies (
  id BIGSERIAL PRIMARY KEY,
  feed_id UUID NOT NULL REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  ioc_type TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('inherit', 'no_expire', 'fixed_ttl')),
  ttl_days INTEGER NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT integration_feed_expiration_type_policies_unique UNIQUE (feed_id, ioc_type),
  CONSTRAINT integration_feed_expiration_type_policies_ttl_check
    CHECK (mode <> 'fixed_ttl' OR (ttl_days IS NOT NULL AND ttl_days > 0))
);

CREATE INDEX IF NOT EXISTS idx_integration_feed_expiration_type_policies_feed
  ON integration_feed_expiration_type_policies (feed_id);
