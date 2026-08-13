-- Allow IOC Read API keys (ioc:read / ioc:export) without changing existing keys.
-- Existing published_feed / ioc_management / feed_access rows keep their stored scopes.

ALTER TABLE published_feed_access_keys
  DROP CONSTRAINT IF EXISTS chk_pf_access_keys_key_type;

ALTER TABLE published_feed_access_keys
  ADD CONSTRAINT chk_pf_access_keys_key_type
  CHECK (key_type IN ('feed_access', 'published_feed', 'ioc_management', 'ioc_read'));

ALTER TABLE published_feed_access_keys
  DROP CONSTRAINT IF EXISTS chk_pf_access_keys_scopes;

ALTER TABLE published_feed_access_keys
  ADD CONSTRAINT chk_pf_access_keys_scopes
  CHECK (
    jsonb_typeof(scopes) = 'array'
    AND jsonb_array_length(scopes) >= 1
    AND scopes <@ '["published_feeds:read","ioc:create","ioc:update","ioc:read","ioc:export"]'::jsonb
  );
