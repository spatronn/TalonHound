-- AlienVault / LevelBlue OTX DirectConnect feed (subscribed pulses).
-- Built-in, API-key based threat feed. Idempotent seed; backward compatible.
-- Rollback: DELETE FROM integration_feeds WHERE key = 'alienvault-otx';
--   (ON DELETE CASCADE also removes its expiration policy + memberships. Only
--    safe when no OTX IOCs must be retained.)

INSERT INTO integration_feeds (
  key, integration_id, name, source_url, schedule_cron,
  trust_level, active, feed_kind, feed_update_mode, default_confidence
)
VALUES (
  'alienvault-otx',
  gen_random_uuid(),
  'AlienVault OTX',
  'https://otx.alienvault.com/api/v1/pulses/subscribed',
  '0 * * * *',
  'orta',
  TRUE,
  'built_in',
  'incremental',
  'medium'
)
ON CONFLICT (key) DO UPDATE
SET name = EXCLUDED.name,
    source_url = EXCLUDED.source_url,
    feed_kind = 'built_in',
    feed_update_mode = 'incremental',
    updated_at = NOW();

-- Default expiration: expire OTX IOCs not re-seen for 30 days (last_seen_ttl fits
-- an incremental, cursor-based feed). DO NOTHING on re-run so admin edits stick.
INSERT INTO threat_feed_expiration_policies (
  feed_id, observable_type, enabled, expiration_mode, ttl_days, grace_days
)
SELECT f.integration_id, 'all', TRUE, 'last_seen_ttl', 30, NULL
FROM integration_feeds f
WHERE f.key = 'alienvault-otx'
ON CONFLICT (feed_id, observable_type) DO NOTHING;
