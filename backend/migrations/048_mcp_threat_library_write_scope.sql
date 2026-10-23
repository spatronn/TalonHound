-- 048_mcp_threat_library_write_scope.sql
--
-- MCP tools for Threat Library post-import analyst workflow
-- (threat_library_review_iocs / threat_library_create_iocs /
-- threat_library_finalize_report / threat_library_review_ioc_source)
-- authorize on the new scope 'mcp:threat_library:write'
-- (lib/apiKeyProfiles.js), bundled into the MCP Analyst profile. Widens the
-- published_feed_access_keys scope CHECK constraint (last set by 046) and
-- backfills the scope onto live MCP Analyst keys, since scopes are snapshotted
-- per key at creation. Only key_type = 'mcp_analyst' rows that are not deleted
-- are touched; MCP Read and non-MCP keys are never granted the scope.
-- Idempotent. No Threat Library table changes: the tools reuse reviewService /
-- finalizeReport / linked IOC Source transitions.

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
      "mcp:threat_library:write"
    ]'::jsonb)
  );

UPDATE public.published_feed_access_keys
   SET scopes = scopes || '["mcp:threat_library:write"]'::jsonb
 WHERE key_type = 'mcp_analyst'
   AND deleted_at IS NULL
   AND jsonb_typeof(scopes) = 'array'
   AND NOT (scopes ? 'mcp:threat_library:write');
