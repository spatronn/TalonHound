-- Feed lifecycle: built-in vs custom, archive, membership purge (soft).

ALTER TABLE integration_feeds
  ADD COLUMN IF NOT EXISTS feed_kind TEXT NOT NULL DEFAULT 'built_in'
    CHECK (feed_kind IN ('built_in', 'custom')),
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS archived_by UUID NULL,
  ADD COLUMN IF NOT EXISTS archived_by_username TEXT NULL;

UPDATE integration_feeds SET feed_kind = 'built_in' WHERE feed_kind IS NULL;

ALTER TABLE ioc_feed_memberships
  ADD COLUMN IF NOT EXISTS purged_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS purged_by UUID NULL,
  ADD COLUMN IF NOT EXISTS purged_by_username TEXT NULL,
  ADD COLUMN IF NOT EXISTS purge_reason TEXT NULL;

ALTER TABLE ioc_feed_memberships DROP CONSTRAINT IF EXISTS ioc_feed_memberships_status_check;
ALTER TABLE ioc_feed_memberships
  ADD CONSTRAINT ioc_feed_memberships_status_check
    CHECK (status IN ('active', 'expired', 'purged'));

CREATE INDEX IF NOT EXISTS idx_ioc_feed_memberships_feed_purged
  ON ioc_feed_memberships (feed_id, status)
  WHERE status = 'purged';

CREATE INDEX IF NOT EXISTS idx_integration_feeds_archived
  ON integration_feeds (archived_at)
  WHERE archived_at IS NOT NULL;
