-- 038_mcp_enrichment_access_profile.sql
--
-- MCP Enrichment access profile (lib/apiKeyProfiles.js): key_type
-- 'mcp_enrichment' with the new 'mcp:enrichment:write' scope (MCP enrich_ioc /
-- bulk_enrich_iocs). Widens the two published_feed_access_keys CHECK
-- constraints set by 018_mcp_server.sql. Constraint-only: existing keys keep
-- their stored scopes and are NOT granted the new scope.

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
      'mcp_analyst'::text,
      'mcp_enrichment'::text
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
      "mcp:enrichment:write",
      "mcp:sources:read"
    ]'::jsonb)
  );
