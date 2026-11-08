-- 055_published_feed_curated_and_mcp_scopes.sql
--
-- Published Feed curated membership mode + MCP Published Feed scopes.
--
-- 1) Widen published_feeds.filter_mode CHECK to admit 'curated'
--    (constraint name from 001_core: chk_published_feeds_filter_mode).
-- 2) Create published_feed_curated_iocs for explicit IOC public_id membership.
-- 3) Widen published_feed_access_keys scopes CHECK (last set by 048) to admit
--    mcp:published_feeds:read and mcp:published_feeds:write.
-- 4) Backfill mcp:published_feeds:read onto live mcp_read + mcp_analyst keys.
-- 5) Backfill mcp:published_feeds:write onto live mcp_analyst keys so existing
--    analyst-profile admin owners keep working after upgrade.
--
-- WRITE SCOPE POLICY (documented):
--   mcp:published_feeds:write is bundled into the MCP Analyst profile so keys
--   created after this migration carry it. authorizeMcpTool STILL requires the
--   owner user's role to be ADMIN for create/update/regenerate tools — non-admin
--   owners are RBAC-denied even when the token carries write scope. Do NOT
--   auto-grant write to mcp_read keys.
--
-- Idempotent. Additive only.

-- ---------------------------------------------------------------------------
-- 1. filter_mode admits curated
-- ---------------------------------------------------------------------------
ALTER TABLE public.published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_filter_mode;

ALTER TABLE public.published_feeds
  ADD CONSTRAINT chk_published_feeds_filter_mode CHECK (
    filter_mode = ANY (ARRAY['basic'::text, 'query'::text, 'curated'::text])
  );

-- ---------------------------------------------------------------------------
-- 2. curated membership table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.published_feed_curated_iocs (
  feed_id bigint NOT NULL REFERENCES public.published_feeds(id) ON DELETE CASCADE,
  ioc_public_id uuid NOT NULL,
  reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES public.users(public_id) ON DELETE SET NULL,
  PRIMARY KEY (feed_id, ioc_public_id)
);

CREATE INDEX IF NOT EXISTS idx_pf_curated_iocs_public_id
  ON public.published_feed_curated_iocs (ioc_public_id);

-- ---------------------------------------------------------------------------
-- 3. MCP scopes CHECK
-- ---------------------------------------------------------------------------
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
      "mcp:enrichment:write",
      "mcp:sources:read",
      "mcp:tags:write",
      "mcp:threat_library:import",
      "mcp:threat_library:write",
      "mcp:published_feeds:read",
      "mcp:published_feeds:write"
    ]'::jsonb)
  );

-- ---------------------------------------------------------------------------
-- 4. Backfill READ onto mcp_read + mcp_analyst (not deleted)
-- ---------------------------------------------------------------------------
UPDATE public.published_feed_access_keys
   SET scopes = scopes || '["mcp:published_feeds:read"]'::jsonb
 WHERE key_type IN ('mcp_read', 'mcp_analyst')
   AND deleted_at IS NULL
   AND jsonb_typeof(scopes) = 'array'
   AND NOT (scopes ? 'mcp:published_feeds:read');

-- ---------------------------------------------------------------------------
-- 5. Backfill WRITE onto mcp_analyst only (admin RBAC still gates tools)
-- ---------------------------------------------------------------------------
UPDATE public.published_feed_access_keys
   SET scopes = scopes || '["mcp:published_feeds:write"]'::jsonb
 WHERE key_type = 'mcp_analyst'
   AND deleted_at IS NULL
   AND jsonb_typeof(scopes) = 'array'
   AND NOT (scopes ? 'mcp:published_feeds:write');
