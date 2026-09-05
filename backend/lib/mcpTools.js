/**
 * MCP tool registration for McpServer (Zod-validated inputs).
 */

import { z } from 'zod';
import { authorizeMcpTool } from './mcpPermissions.js';
import {
  mcpLookupIoc,
  mcpSearchIocs,
  mcpGetIocContext,
  mcpBulkLookupIocs,
  mcpListIocSources,
  mcpImportIocs,
  mcpActorAuditFields
} from './mcpIocService.js';
import { getMcpConfig } from './mcpConfig.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY, AUDIT_STATUS } from './auditConstants.js';

function toolText(obj) {
  return {
    content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }],
    structuredContent: obj
  };
}

function toolError(message, code = 'ERROR') {
  return {
    isError: true,
    content: [{ type: 'text', text: JSON.stringify({ error: { code, message } }) }],
    structuredContent: { error: { code, message } }
  };
}

async function withAuth(toolName, ctx, handler) {
  const auth = ctx.mcpAuth || {
    scopes: ctx.req?.mcpAuth?.scopes || ctx.req?.apiKey?.scopes || [],
    ownerRole: ctx.req?.mcpAuth?.ownerRole || ctx.req?.user?.role
  };
  const gate = authorizeMcpTool(toolName, auth);
  if (!gate.ok) {
    return toolError(gate.message, gate.code);
  }
  try {
    const outcome = await handler();
    if (outcome?.error) {
      return toolError(outcome.error.message, outcome.error.code || 'ERROR');
    }
    if (ctx.audit?.auditSuccess && ctx.req && toolName !== 'import_iocs') {
      const actor = mcpActorAuditFields(ctx.mcpAuth || ctx.req.mcpAuth, ctx.req.user);
      await ctx.audit.auditSuccess({
        req: ctx.req,
        action: AUDIT_ACTION.MCP_TOOL_CALL,
        entityType: AUDIT_ENTITY.IOC,
        entityId: null,
        entityDisplay: toolName,
        severity: AUDIT_SEVERITY.INFO,
        actorUsername: actor.actorUsername,
        actorEmail: actor.actorEmail,
        actorRole: actor.actorRole,
        actorPublicId: actor.actorPublicId,
        source: 'mcp',
        metadata: {
          ...actor.metadataExtras,
          tool: toolName,
          status: 'success'
        }
      }).catch(() => {});
    }
    return toolText(outcome.body);
  } catch (err) {
    if (ctx.audit?.auditFailure && ctx.req) {
      const actor = mcpActorAuditFields(ctx.mcpAuth || ctx.req.mcpAuth, ctx.req.user);
      await ctx.audit.auditFailure({
        req: ctx.req,
        action: AUDIT_ACTION.MCP_TOOL_CALL,
        entityType: AUDIT_ENTITY.IOC,
        entityDisplay: toolName,
        severity: AUDIT_SEVERITY.WARNING,
        status: AUDIT_STATUS.FAILED,
        actorUsername: actor.actorUsername,
        actorEmail: actor.actorEmail,
        actorRole: actor.actorRole,
        actorPublicId: actor.actorPublicId,
        source: 'mcp',
        metadata: {
          ...actor.metadataExtras,
          tool: toolName,
          error: 'internal_error'
        }
      }).catch(() => {});
    }
    return toolError('Temporary backend error', 'INTERNAL_ERROR');
  }
}

/**
 * @param {import('@modelcontextprotocol/sdk/server/mcp.js').McpServer} server
 * @param {{ pool: import('pg').Pool, audit?: object, getRequestContext: () => object }} deps
 */
export function registerMcpTools(server, deps) {
  const config = getMcpConfig();

  const ctxFrom = () => {
    const c = deps.getRequestContext() || {};
    return {
      pool: deps.pool,
      audit: deps.audit,
      req: c.req,
      user: c.req?.user,
      mcpAuth: c.req?.mcpAuth,
      config
    };
  };

  server.registerTool(
    'lookup_ioc',
    {
      title: 'Lookup IOC',
      description:
        'Exact lookup of a single observable in TalonHound. Provide the raw value; type is optional because TalonHound detects and normalizes it. '
        + 'Returns found/not found with identity, status, confidence, sources, and the IOC\'s TalonHound classifications (slugs) and tags (names) as shown on the IOC Details page — tags include source-integration/feed tags, not only analyst-added ones. '
        + 'An empty classifications/tags array means TalonHound holds none for this IOC. For per-source provenance and stored enrichment, call get_ioc_context.',
      inputSchema: {
        value: z.string().min(1).max(config.valueMaxChars).describe('IOC value (IP, domain, URL, or hash)'),
        type: z.enum(['ip', 'domain', 'url', 'hash']).optional().describe('Optional explicit IOC type')
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => withAuth('lookup_ioc', ctxFrom(), () => mcpLookupIoc(deps.pool, args, ctxFrom()))
  );

  server.registerTool(
    'search_iocs',
    {
      title: 'Search IOCs',
      description:
        'Search the TalonHound IOC inventory. Provide `query` and/or the structured filters '
        + '`type`/`classification`/`source` (combined with AND); at least one is required. '
        + '`query` accepts either TalonHound Search DSL — `field operator "value"` with AND/OR/NOT, '
        + 'e.g. `ioc contains "evil.com"`, `type equals "domain" AND confidence equals "high"` '
        + '(fields: ioc, type, source, tag, threat_actor, classification, status, confidence, '
        + 'first_seen, created_at; operators: contains, equals, not_equals, starts_with, ends_with, '
        + 'in, not_in) — or plain text, which is treated as a bounded IOC-value contains-search. '
        + 'Results are bounded (server-enforced max page size); use `cursor` for pagination. '
        + 'Not for unbounded export.',
      inputSchema: {
        query: z.string().min(1).max(config.valueMaxChars).optional()
          .describe('Search DSL (e.g. type equals "domain") or plain text (bounded IOC value search)'),
        type: z.enum(['ip', 'domain', 'url', 'hash']).optional().describe('Filter by IOC type'),
        classification: z.string().max(128).optional().describe('Filter by threat classification (slug or label)'),
        source: z.string().max(128).optional().describe('Filter by IOC Source name'),
        limit: z.number().int().min(1).max(config.searchPageMax).optional(),
        cursor: z.string().max(512).optional()
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => withAuth('search_iocs', ctxFrom(), () => mcpSearchIocs(deps.pool, args, ctxFrom()))
  );

  server.registerTool(
    'get_ioc_context',
    {
      title: 'Get IOC context',
      description:
        'Return analyst-facing TalonHound context for one IOC. Includes native TalonHound classifications and tags (with tags_detail carrying per-tag origin: analyst `manual` vs source `integration`/`feed`), sources, and — kept separate under `source_intelligence` so provenance is never ambiguous — the source/feed-provided feed_tags, feed_classifications, and parsed malware/family/threat_type labels. Also returns stored enrichment when the credential has mcp:enrichment:read. Does not trigger paid/external enrichment.',
      inputSchema: {
        value: z.string().min(1).max(config.valueMaxChars).optional(),
        type: z.enum(['ip', 'domain', 'url', 'hash']).optional(),
        id: z.union([z.string(), z.number()]).optional().describe('IOC id or public_id')
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => withAuth('get_ioc_context', ctxFrom(), () => mcpGetIocContext(deps.pool, args, ctxFrom()))
  );

  server.registerTool(
    'bulk_lookup_iocs',
    {
      title: 'Bulk lookup IOCs',
      description:
        `Check a batch of extracted IOCs efficiently. Returns existing, missing, and invalid buckets. Maximum ${config.bulkLookupMax} items per request. Uses batched database lookup (not N+1).`,
      inputSchema: {
        iocs: z.array(
          z.union([
            z.string().min(1).max(config.valueMaxChars),
            z.object({
              value: z.string().min(1).max(config.valueMaxChars),
              type: z.enum(['ip', 'domain', 'url', 'hash']).optional()
            })
          ])
        ).min(1).max(config.bulkLookupMax)
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => withAuth('bulk_lookup_iocs', ctxFrom(), () => mcpBulkLookupIocs(deps.pool, args, ctxFrom()))
  );

  server.registerTool(
    'list_ioc_sources',
    {
      title: 'List IOC Sources',
      description:
        'List active IOC Sources the authenticated owner may use for import_iocs. Does not expose deleted, archived, inactive, or internal system sources.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => withAuth('list_ioc_sources', ctxFrom(), () => mcpListIocSources(deps.pool, args, ctxFrom()))
  );

  server.registerTool(
    'import_iocs',
    {
      title: 'Import IOCs',
      description:
        `Import IOCs into an existing TalonHound IOC Source using the same manual ingestion path as the GUI. Requires source_id from list_ioc_sources. Set dry_run=true to validate without writing. Maximum ${config.importMax} IOCs. Does not create a special MCP/AI source — use a real IOC Source such as "Threat Hunting".`,
      inputSchema: {
        source_id: z.number().int().positive().describe('Existing IOC Source id'),
        iocs: z.array(
          z.union([
            z.string().min(1).max(config.valueMaxChars),
            z.object({
              value: z.string().min(1).max(config.valueMaxChars),
              type: z.enum(['ip', 'domain', 'url', 'hash']).optional()
            })
          ])
        ).min(1).max(config.importMax),
        dry_run: z.boolean().optional().describe('When true, validate and resolve without committing'),
        note: z.string().max(2000).optional().describe('Optional note applied to newly created IOCs')
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false }
    },
    async (args) => {
      const ctx = ctxFrom();
      return withAuth('import_iocs', ctx, async () => {
        const outcome = await mcpImportIocs(deps.pool, args, ctx);
        if (!outcome.error && ctx.audit?.auditSuccess && ctx.req) {
          const actor = mcpActorAuditFields(ctx.mcpAuth, ctx.req.user);
          const body = outcome.body || {};
          await ctx.audit.auditSuccess({
            req: ctx.req,
            action: AUDIT_ACTION.MCP_IOC_IMPORT,
            entityType: AUDIT_ENTITY.IOC_SOURCE,
            entityId: String(body.source?.id || args.source_id),
            entityDisplay: body.source?.name || String(args.source_id),
            severity: AUDIT_SEVERITY.INFO,
            actorUsername: actor.actorUsername,
            actorEmail: actor.actorEmail,
            actorRole: actor.actorRole,
            actorPublicId: actor.actorPublicId,
            source: 'mcp',
            metadata: {
              ...actor.metadataExtras,
              tool: 'import_iocs',
              dry_run: Boolean(args.dry_run),
              source_id: body.source?.id ?? args.source_id,
              source_name: body.source?.name || null,
              submitted: body.submitted,
              created: body.created ?? body.would_create ?? 0,
              already_existing: body.already_existing,
              source_membership_added: body.source_membership_added ?? body.source_membership_would_add ?? 0,
              invalid: body.invalid,
              failed: body.failed ?? 0
            }
          }).catch(() => {});
        }
        return outcome;
      });
    }
  );
}
