/**
 * MCP tool registration for McpServer (Zod-validated inputs).
 */

import { z } from 'zod';
import { authorizeMcpTool } from './mcpPermissions.js';
import {
  mcpLookupIoc,
  mcpSearchIocs,
  mcpGetIocContext,
  mcpGetThreatReport,
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
        'Return analyst-facing TalonHound context for one IOC. Includes native TalonHound classifications and tags (with tags_detail carrying per-tag origin: analyst `manual` vs source `integration`/`feed`), sources, and — kept separate under `source_intelligence` so provenance is never ambiguous — the source/feed-provided feed_tags, feed_classifications, and parsed malware/family/threat_type labels. When the credential has mcp:enrichment:read, `enrichment` carries every stored *direct* enrichment result applicable to the IOC type (VirusTotal, and for IP IOCs also IPinfo/AbuseIPDB/Spamhaus DROP; for domain/URL also RDAP when stored). For URL IOCs, VirusTotal `summary.web_analysis` adds normalized web signals when present (targeted_brand, behavior_tags, http, content_sha256, redirection_chain, bounded outgoing_links, categories) — derived from stored enrichment only, never a live VirusTotal call. For URL IOCs whose host is an IP literal, `derived_infrastructure` mirrors the UI Derived Infrastructure panel: extracted_host plus stored IPinfo/AbuseIPDB/Spamhaus for that host — without treating the host as a registered IOC. A provider appears only when a stored result exists. Does not trigger paid/external enrichment. `threat_context` (always present) carries the Threat Library Threat Context shown on IOC Details: `claims` (role, assessment, confidence, evidence_text, section, page_number, occurrence_count, occurrences[≤5: zone, section_heading, page, form, surrounding_text — where THIS IOC appears in the report, in document order], report {id, title, published_at, tlp, tlp_display, source_name, source_type, summary, entities[≤20: id, entity_type, name, description]}) and `relationships` from persisted, non-deleted threat reports linked to this IOC — read from stored Threat Library data only, never re-fetched or re-analyzed. Empty arrays mean no linked report. Evidence precedence, strongest first: explicit relationship > IOC-specific claim > IOC-specific occurrence > report summary > report-level entity. Report-level entities are co-mentioned in the same report and do not imply a direct relationship with this IOC unless supported by an explicit claim, relationship, or IOC-specific occurrence evidence; a report title or entity name alone never attributes the IOC to an actor, malware, or C2 role.',
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
    'get_threat_report',
    {
      title: 'Get threat report',
      description:
        'Return one persisted Threat Library report by id (take it from get_ioc_context.threat_context.claims[].report.id) for same-report drill-down: report metadata (title, source_name, source_type, source_url, published_at, language, tlp, tlp_display, tlp_source, import_status, review_phase), `summary`, `counts`, a paged `indicators` roster in document order (items: id, value, original_value, type, is_ioc, assessment, role, confidence, section, page_number, evidence_text, occurrence_count, review_status, match_state, ioc_id, ioc_type; default 100, max 500 per call, use indicator_offset to page), `entities` (≤50 report-level co-mentions: id, entity_type, name, description) and `relationships` (≤100 explicit links, same shape as threat_context.relationships). Each indicator carries its OWN role/assessment — use those, not the report title or entity list, to say what a given IOC is in this report. Entities are co-mentioned in the report and do not imply a direct relationship with any indicator unless an explicit relationship or the claim/occurrence evidence of that indicator supports it. Never returns the report body, artifacts or parser internals; reads stored data only, never re-fetches, re-parses or analyzes the report.',
      inputSchema: {
        id: z.string().min(36).max(36).describe('Threat Library report id (uuid)'),
        indicator_limit: z.number().int().min(1).max(500).optional().describe('Indicators per call (default 100, max 500)'),
        indicator_offset: z.number().int().min(0).optional().describe('Indicator offset for paging (default 0)')
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => withAuth('get_threat_report', ctxFrom(), () => mcpGetThreatReport(deps.pool, args))
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
