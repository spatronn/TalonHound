-- Allow custom threat feed names to be reused after soft-delete/deactivate.
-- Unique names apply only to non-archived custom feeds (archived_at IS NULL).

-- Backfill: soft-deleted custom feeds should be archived so they exit the unique index.
UPDATE integration_feeds f
SET archived_at = COALESCE(f.archived_at, c.deactivated_at, NOW()),
    updated_at = NOW()
FROM custom_threat_feeds c
WHERE c.feed_id = f.integration_id
  AND f.feed_kind = 'custom'
  AND c.deactivated_at IS NOT NULL
  AND f.archived_at IS NULL;

DROP INDEX IF EXISTS idx_integration_feeds_custom_name_unique_ci;

CREATE UNIQUE INDEX IF NOT EXISTS idx_integration_feeds_custom_name_unique_ci
  ON integration_feeds (lower(trim(name)))
  WHERE feed_kind = 'custom' AND archived_at IS NULL;
