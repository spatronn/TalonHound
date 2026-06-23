-- IOC List browse: recent active memberships ordered by last_seen_in_feed (no ioc_items parent scan).
CREATE INDEX IF NOT EXISTS idx_ioc_feed_memberships_active_last_seen
  ON ioc_feed_memberships (last_seen_in_feed DESC NULLS LAST)
  WHERE status = 'active' AND purged_at IS NULL;
