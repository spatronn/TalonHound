-- General-purpose API keys: scopes + IOC Management profile + system API IOC source.
--
-- Backward compatible:
--   * Existing published_feed / feed_access keys keep working.
--   * They are backfilled with scopes = ["published_feeds:read"].
--   * key_type remains the access-profile identifier; scopes are the auth source of truth.

-- 1) Scopes column (canonical authorization). -------------------------------------------
ALTER TABLE published_feed_access_keys
  ADD COLUMN IF NOT EXISTS scopes JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE published_feed_access_keys
SET scopes = '["published_feeds:read"]'::jsonb
WHERE key_type IN ('published_feed', 'feed_access')
  AND (scopes IS NULL OR scopes = '[]'::jsonb OR jsonb_array_length(scopes) = 0);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_pf_access_keys_key_type'
  ) THEN
    ALTER TABLE published_feed_access_keys DROP CONSTRAINT chk_pf_access_keys_key_type;
  END IF;
END$$;

ALTER TABLE published_feed_access_keys
  ADD CONSTRAINT chk_pf_access_keys_key_type
  CHECK (key_type IN ('feed_access', 'published_feed', 'ioc_management'));

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_pf_access_keys_scopes'
  ) THEN
    ALTER TABLE published_feed_access_keys
      ADD CONSTRAINT chk_pf_access_keys_scopes
      CHECK (
        jsonb_typeof(scopes) = 'array'
        AND jsonb_array_length(scopes) >= 1
        AND scopes <@ '["published_feeds:read","ioc:create","ioc:update"]'::jsonb
      );
  END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_pf_access_keys_scopes_gin
  ON published_feed_access_keys USING GIN (scopes);

-- 2) System IOC source used by the REST API (clients cannot choose/spoof source). -------
INSERT INTO ioc_sources (name, display_name, description, source_type, default_confidence, default_expire_policy, active)
VALUES (
  'API',
  'API',
  'System source for IOCs created through the TalonHound REST API. Not selectable in Add IOC.',
  'internal_hunting',
  'medium',
  'never',
  TRUE
)
ON CONFLICT (name) DO UPDATE
SET display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    source_type = EXCLUDED.source_type,
    active = TRUE,
    updated_at = NOW();

-- 3) Allow API-created provenance on ioc_items.created_origin. ---------------------------
ALTER TABLE ioc_items DROP CONSTRAINT IF EXISTS ioc_items_created_origin_check;

ALTER TABLE ioc_items
  ADD CONSTRAINT ioc_items_created_origin_check
  CHECK (created_origin IS NULL OR created_origin IN ('manual_add', 'api'));

CREATE INDEX IF NOT EXISTS idx_ioc_items_api_recent
  ON ioc_items (created_at DESC)
  WHERE created_origin = 'api';
