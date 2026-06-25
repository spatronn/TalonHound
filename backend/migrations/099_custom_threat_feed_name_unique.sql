-- Case-insensitive unique names for custom threat feeds (stored on integration_feeds.name).

-- Lab-safe cleanup: suffix duplicate names so unique index can be applied.
WITH ranked AS (
  SELECT f.integration_id,
         f.name,
         ROW_NUMBER() OVER (
           PARTITION BY lower(trim(f.name))
           ORDER BY c.created_at ASC, f.integration_id ASC
         ) AS rn
  FROM integration_feeds f
  INNER JOIN custom_threat_feeds c ON c.feed_id = f.integration_id
  WHERE f.feed_kind = 'custom'
)
UPDATE integration_feeds f
SET name = r.name || '-' || r.rn::text,
    updated_at = NOW()
FROM ranked r
WHERE f.integration_id = r.integration_id
  AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_integration_feeds_custom_name_unique_ci
  ON integration_feeds (lower(trim(name)))
  WHERE feed_kind = 'custom';
