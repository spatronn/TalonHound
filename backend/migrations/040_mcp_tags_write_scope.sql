-- 040_mcp_tags_write_scope.sql
--
-- MCP tag tools (add_ioc_tags / remove_ioc_tags) authorize on the new scope
-- 'mcp:tags:write' (lib/apiKeyProfiles.js), bundled into the MCP Analyst
-- profile. Widens the published_feed_access_keys scope CHECK constraint
-- (last set by 038) and backfills the scope onto live MCP Analyst keys, since
-- scopes are snapshotted per key at creation. Only key_type = 'mcp_analyst'
-- rows that are not deleted are touched; MCP Read and non-MCP keys are never
-- granted the scope. Idempotent.

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
      "mcp:tags:write"
    ]'::jsonb)
  );

UPDATE public.published_feed_access_keys
   SET scopes = scopes || '["mcp:tags:write"]'::jsonb
 WHERE key_type = 'mcp_analyst'
   AND deleted_at IS NULL
   AND jsonb_typeof(scopes) = 'array'
   AND NOT (scopes ? 'mcp:tags:write');
