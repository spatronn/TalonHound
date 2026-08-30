-- CERT.PL / CERT Polska Dangerous Websites Warning List built-in feed.
-- Idempotent upsert for fresh installs (after 001_core) and existing upgrades.
-- No schema changes; uses the generic integration_feeds + expiration policy tables.

INSERT INTO public.integration_feeds (
  key,
  name,
  source_url,
  schedule_cron,
  trust_level,
  active,
  created_at,
  updated_at,
  integration_id,
  feed_update_mode,
  credentials,
  default_confidence,
  feed_kind,
  archived_at,
  archived_by,
  archived_by_username,
  color
) VALUES (
  'certpl-warning-list',
  'CERT.PL Dangerous Websites',
  'https://hole.cert.pl/domains/v2/domains.json',
  '*/5 * * * *',
  'trusted',
  true,
  NOW(),
  NOW(),
  'fa65f84e-da60-4aee-a2d4-249400bfe892',
  'incremental',
  '{}'::jsonb,
  'high',
  'built_in',
  NULL,
  NULL,
  NULL,
  '#c8102e'
)
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.threat_feed_expiration_policies (
  feed_id,
  observable_type,
  enabled,
  expiration_mode,
  ttl_days,
  grace_days,
  created_at,
  updated_at
)
SELECT
  f.integration_id,
  'all',
  false,
  'never',
  NULL,
  NULL,
  NOW(),
  NOW()
FROM public.integration_feeds f
WHERE f.key = 'certpl-warning-list'
  AND NOT EXISTS (
    SELECT 1
    FROM public.threat_feed_expiration_policies p
    WHERE p.feed_id = f.integration_id
      AND p.observable_type = 'all'
  );
