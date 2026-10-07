-- 039_mcp_analyst_enrichment_scope.sql
--
-- Access-profile simplification: MCP Analyst is the trusted AI-analyst bundle
-- and now includes enrichment (mcp:enrichment:write) alongside its import and
-- read scopes. The separate "MCP Enrichment" profile is no longer offered.
--
-- Scopes are snapshotted on each key at creation (published_feed_access_keys
-- .scopes, read as-is by MCP authentication), so existing MCP Analyst keys are
-- backfilled here. Only key_type = 'mcp_analyst' rows that are not deleted are
-- touched; MCP Read, IOC Read/Management and published-feed keys are never
-- granted the scope. Idempotent (skips keys that already carry it).
--
-- The historical key_type 'mcp_enrichment' stays admitted by
-- chk_pf_access_keys_key_type (038) because revoked/deleted rows of that type
-- exist; the application no longer offers or creates it.

UPDATE public.published_feed_access_keys
   SET scopes = scopes || '["mcp:enrichment:read"]'::jsonb
 WHERE key_type = 'mcp_analyst'
   AND deleted_at IS NULL
   AND jsonb_typeof(scopes) = 'array'
   AND NOT (scopes ? 'mcp:enrichment:read');

UPDATE public.published_feed_access_keys
   SET scopes = scopes || '["mcp:enrichment:write"]'::jsonb
 WHERE key_type = 'mcp_analyst'
   AND deleted_at IS NULL
   AND jsonb_typeof(scopes) = 'array'
   AND NOT (scopes ? 'mcp:enrichment:write');
