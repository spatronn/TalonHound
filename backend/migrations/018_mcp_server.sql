-- MCP Server support: scopes, access profiles, accountable owner on API keys.
-- Forward-only; safe on upgrade. Does not alter IOC domain tables.

ALTER TABLE public.published_feed_access_keys
  ADD COLUMN IF NOT EXISTS owner_user_id bigint;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'published_feed_access_keys_owner_user_id_fkey'
  ) THEN
    ALTER TABLE public.published_feed_access_keys
      ADD CONSTRAINT published_feed_access_keys_owner_user_id_fkey
      FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE RESTRICT;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_pf_access_keys_owner_user_id
  ON public.published_feed_access_keys (owner_user_id)
  WHERE owner_user_id IS NOT NULL AND deleted_at IS NULL;

ALTER TABLE public.published_feed_access_keys
  DROP CONSTRAINT IF EXISTS chk_pf_access_keys_key_type;

ALTER TABLE public.published_feed_access_keys
  ADD CONSTRAINT chk_pf_access_keys_key_type CHECK (
    key_type = ANY (ARRAY[
      'feed_access'::text,
      'published_feed'::text,
      'ioc_management'::text,
      'ioc_read'::text,
      'mcp_read'::text,
      'mcp_analyst'::text
    ])
  );

ALTER TABLE public.published_feed_access_keys
  DROP CONSTRAINT IF EXISTS chk_pf_access_keys_scopes;

ALTER TABLE public.published_feed_access_keys
  ADD CONSTRAINT chk_pf_access_keys_scopes CHECK (
    (jsonb_typeof(scopes) = 'array'::text)
    AND (jsonb_array_length(scopes) >= 1)
    AND (scopes <@ '[
      "published_feeds:read",
      "ioc:create",
      "ioc:update",
      "ioc:read",
      "ioc:export",
      "mcp:ioc:read",
      "mcp:ioc:create",
      "mcp:enrichment:read",
      "mcp:sources:read"
    ]'::jsonb)
  );
