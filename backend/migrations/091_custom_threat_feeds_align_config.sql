-- Align custom threat feeds with integration_feeds + threat_feed_expiration_policies.
-- Migrate duplicate config columns, then drop them from custom_threat_feeds.

-- Sync schedule to integration_feeds.schedule_cron
UPDATE integration_feeds f
SET schedule_cron = CASE
      WHEN c.sync_interval_minutes <= 5 THEN '*/5 * * * *'
      WHEN c.sync_interval_minutes <= 15 THEN '*/15 * * * *'
      WHEN c.sync_interval_minutes <= 30 THEN '*/30 * * * *'
      WHEN c.sync_interval_minutes <= 60 THEN '0 * * * *'
      WHEN c.sync_interval_minutes <= 120 THEN '0 */2 * * *'
      WHEN c.sync_interval_minutes <= 360 THEN '0 */6 * * *'
      WHEN c.sync_interval_minutes <= 720 THEN '0 */12 * * *'
      ELSE '0 0 * * *'
    END,
    default_confidence = COALESCE(f.default_confidence, c.default_confidence),
    active = COALESCE(c.enabled, f.active),
    updated_at = NOW()
FROM custom_threat_feeds c
WHERE c.feed_id = f.integration_id;

-- Map expire_missing to snapshot expiration policy (missing_from_feed_ttl, 7d grace)
INSERT INTO threat_feed_expiration_policies (
  feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days, updated_at
)
SELECT
  c.feed_id,
  'all',
  TRUE,
  'missing_from_feed_ttl',
  NULL,
  7,
  NOW()
FROM custom_threat_feeds c
WHERE c.expire_missing = TRUE
ON CONFLICT (feed_id, observable_type) DO UPDATE
SET enabled = EXCLUDED.enabled,
    expiration_mode = EXCLUDED.expiration_mode,
    grace_days = EXCLUDED.grace_days,
    updated_at = NOW();

ALTER TABLE custom_threat_feeds
  DROP COLUMN IF EXISTS default_confidence,
  DROP COLUMN IF EXISTS sync_interval_minutes,
  DROP COLUMN IF EXISTS expire_missing,
  DROP COLUMN IF EXISTS enabled;
