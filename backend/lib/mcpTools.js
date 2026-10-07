/**
 * MCP tool registration for McpServer (Zod-validated inputs).
 */

import { z } from 'zod';
import { authorizeMcpTool, MCP_ENRICHMENT_ACTION_TOOLS, MCP_TAG_ACTION_TOOLS } from './mcpPermissions.js';
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
import { mcpListEnrichmentProviders, mcpEnrichIocs, mcpGetEnrichmentJob } from './mcpEnrichmentService.js';
import { mcpListTags, mcpAddIocTags, mcpRemoveIocTags } from './mcpTagService.js';
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
    // import_iocs, the enrichment action tools and the tag tools write their own dedicated audit events.
    if (ctx.audit?.auditSuccess && ctx.req && toolName !== 'import_iocs'
      && !MCP_ENRICHMENT_ACTION_TOOLS.includes(toolName) && !MCP_TAG_ACTION_TOOLS.includes(toolName)) {
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
        + 'Returns found/not found with identity, status, confidence, sources, and the IOC\'s TalonHound classifications (slugs) and tags (names) as shown on the IOC Details page. '
        + '`classifications` is the canonical effective set: classifications proposed by source feeds (controlled vocabulary) minus analyst suppressions, plus analyst classifications; `classification_context` lists who asserts each (`feed` source_name and/or `analyst`). '
        + '`tags` are IOC-level tags: the IOC\'s own tags (analyst-added and source-integration/feed) plus a Threat Library report tag only when the IOC\'s own evidence in that report names it. `tag_context` explains every tag: sources of type `direct` (origin manual/integration) and/or `threat_library` (report_id, title, tlp, basis `ioc_evidence`). `report_context_tags` lists the tags of linked reports — report-level context (campaign, sector, theme), NOT assertions about this IOC unless `ioc_evidence` is true. Report tags never change classifications. '
        + '`sources` = the IOC\'s source memberships (feeds and IOC Sources), one per provider, each with its OWN status/first_seen/last_changed_at — never merge them into one timeline; `historical_sources` = expired/removed memberships; `evidence_sources` = deduplicated providers with intelligence on this IOC (sources plus `Threat Library` when an active report lists it as an indicator). Different providers naming the same thing differently (e.g. malware family names) is normal provider disagreement, not a data error. '
        + 'An empty classifications/tags array means TalonHound holds none for this IOC. For per-source provenance and stored enrichment, call get_ioc_context. '
        + 'File hashes (md5/sha1/sha256) also match through proven file-artifact aliases of the same file (same identity search_iocs uses): `matched_via` is `exact` or `file_artifact_alias`, `queried` is what you asked for and `record` is the stored IOC returned (e.g. queried sha256, record md5); alias hits list every IOC of that file in `artifact_memberships` (primary first: active, strongest hash, oldest).'
        + ' Read-only: returns persisted TalonHound data and never triggers external/paid enrichment.',
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
        + '`tag` matches IOC-level tags: tags assigned to the IOC, or a linked Threat Library report\'s tag when the IOC\'s own evidence in that report names it '
        + '(report-only context tags do not match). Result items carry tags plus `tag_context` provenance. '
        + 'Results are bounded (server-enforced max page size); use `cursor` for pagination. '
        + 'Not for unbounded export. Read-only: returns persisted TalonHound data and never triggers external/paid enrichment.',
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
        'Return analyst-facing TalonHound context for one IOC. Includes TalonHound classifications (canonical effective set + `classification_context`) and tags (with tags_detail carrying per-tag origin: analyst `manual` vs source `integration`/`feed` vs `threat_library` report evidence; `report_context_tags` = report-level context, not IOC tags), sources / historical_sources / evidence_sources (same semantics as lookup_ioc), and — kept separate under `source_intelligence` so provenance is never ambiguous — the source/feed-provided feed_tags, feed_classifications, and parsed malware/family/threat_type labels. When the credential has mcp:enrichment:read, `enrichment` carries every stored *direct* enrichment result applicable to the IOC type (VirusTotal, and for IP IOCs also IPinfo/AbuseIPDB/Spamhaus DROP; for domain/URL also RDAP when stored). For URL IOCs, VirusTotal `summary.web_analysis` adds normalized web signals when present (targeted_brand, behavior_tags, http, content_sha256, redirection_chain, bounded outgoing_links, categories) — derived from stored enrichment only, never a live VirusTotal call. For URL IOCs whose host is an IP literal, `derived_infrastructure` mirrors the UI Derived Infrastructure panel: extracted_host plus stored IPinfo/AbuseIPDB/Spamhaus for that host — without treating the host as a registered IOC. A provider appears only when a stored result exists. Returns previously persisted enrichment only — it NEVER triggers external/paid enrichment; to refresh, call enrich_ioc explicitly (requires mcp:enrichment:write) and read this again once the job finishes. `threat_context` (always present) carries the Threat Library Threat Context shown on IOC Details: `claims` (role, assessment, confidence, evidence_text, section, page_number, occurrence_count, occurrences[≤5: zone, section_heading, page, form, surrounding_text — where THIS IOC appears in the report, in document order], report {id, title, published_at, published_date, published_at_precision, published_at_source, created_at, tlp, tlp_display, source_name, source_type, summary, entities[≤20: id, entity_type, name, description]}) — published_at/published_date = when the ORIGINAL source was published (published_date is the calendar day the source stated; precision `date` means no time is known, so never treat 00:00 as a real time), created_at = when TalonHound imported it; claims are ordered by publication date (newest first, unknown last) then import date and `relationships` from persisted, non-deleted threat reports linked to this IOC — read from stored Threat Library data only, never re-fetched or re-analyzed. Empty arrays mean no linked report. Evidence precedence, strongest first: explicit relationship > IOC-specific claim > IOC-specific occurrence > report summary > report-level entity. Report-level entities are co-mentioned in the same report and do not imply a direct relationship with this IOC unless supported by an explicit claim, relationship, or IOC-specific occurrence evidence; a report title or entity name alone never attributes the IOC to an actor, malware, or C2 role.',
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
        'Return one persisted Threat Library report by id (take it from get_ioc_context.threat_context.claims[].report.id) for same-report drill-down: report metadata (title, source_name, source_type, source_url, published_at + published_date + published_at_precision + published_at_source = original publication date and how it was extracted, never the import date; created_at = import date, language, tlp, tlp_display, tlp_source, import_status, review_phase), `summary`, `counts` ({ all, indicators, context_only, entities, relationships } — `indicators` is the report Indicator membership count matching the UI Indicators tab; `all` is the full candidate roster size; use `indicators.total` for roster paging), a paged `indicators` roster of ALL candidates in document order (items: id, value, original_value, type, is_ioc, assessment, role, confidence, section, page_number, evidence_text, occurrence_count, review_status, match_state, ioc_id, ioc_type; default 100, max 500 per call, use indicator_offset to page), `entities` (≤50 report-level co-mentions: id, entity_type, name, description) and `relationships` (≤100 explicit links, same shape as threat_context.relationships). Each roster row carries its OWN role/assessment — use those, not the report title or entity list, to say what a given IOC is in this report. Entities are co-mentioned in the report and do not imply a direct relationship with any indicator unless an explicit relationship or the claim/occurrence evidence of that indicator supports it. Never returns the report body, artifacts or parser internals; reads stored data only, never re-fetches, re-parses or analyzes the report. Read-only: returns persisted TalonHound data and never triggers external/paid enrichment.',
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
        `Check a batch of extracted IOCs efficiently. Returns existing, missing, and invalid buckets. Maximum ${config.bulkLookupMax} items per request. Uses batched database lookup (not N+1). `
        + 'Existing items carry confidence, classifications (+ `classification_context`), tags, `tag_context`, `report_context_tags` and note with the same semantics as lookup_ioc, plus `matched_via` (`exact` | `file_artifact_alias`), `queried` and `record` — a file hash with no IOC row of its own is found via a proven alias of the same file. Read-only: returns persisted TalonHound data and never triggers external/paid enrichment.',
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
        'List active IOC Sources the authenticated owner may use for import_iocs. Does not expose deleted, archived, inactive, or internal system sources. Read-only: returns persisted TalonHound data and never triggers external/paid enrichment.',
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

  // ---------------------------------------------------------------------------
  // Enrichment: discovery + job status (read) and explicit triggers (action).
  // ---------------------------------------------------------------------------

  const providerIdsSchema = z.union([
    z.literal('all'),
    z.array(z.string().min(1).max(64)).min(1).max(20)
  ]);

  server.registerTool(
    'list_enrichment_providers',
    {
      title: 'List enrichment providers',
      description:
        'List the enrichment providers TalonHound actually supports, from its provider registry: id (use in enrich_ioc `providers`), name, supported_observable_types '
        + '(url coverage for IP/domain providers means the URL host — Derived Infrastructure), external (outbound third-party call that may consume API quota), '
        + 'enabled / configured / triggerable / available, and the automation rate budget. Never exposes API keys or provider configuration. '
        + 'Read-only: never triggers enrichment.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async () => withAuth('list_enrichment_providers', ctxFrom(), () => mcpListEnrichmentProviders(deps.pool))
  );

  server.registerTool(
    'enrich_ioc',
    {
      title: 'Enrich IOC (triggers providers)',
      description:
        'ACTION: triggers external enrichment for ONE existing IOC and may consume provider API quota. Requires mcp:enrichment:write and an analyst/admin owner. '
        + '`ioc_id` is the IOC public_id (UUID) from lookup_ioc / search_iocs / get_ioc_context (numeric id also accepted); TalonHound resolves the stored observable and type — '
        + 'callers never pass values, URLs or provider endpoints. `providers` = "all" (every enabled provider applicable to the IOC type, incl. URL-host Derived Infrastructure) '
        + 'or provider ids from list_enrichment_providers. Without force_refresh a provider whose stored result is still fresh is skipped (`skipped_fresh`, no external call); '
        + 'force_refresh=true refreshes anyway but never bypasses provider rate limits, cooldowns or role rules (some providers allow forced refresh for admin owners only → `forbidden`). '
        + 'Runs as a background job: returns job_id + per-provider status (queued, running, completed, skipped_fresh, deduplicated = joined an identical in-flight request, '
        + 'unsupported, provider_unavailable, rate_limited, forbidden, failed); optional wait_seconds blocks briefly for completion. Job status: completed / partially_completed / failed. '
        + 'Results are persisted through the normal TalonHound pipeline — read them with get_ioc_context. Every trigger is audited with MCP provenance.',
      inputSchema: {
        ioc_id: z.union([z.string().min(1).max(64), z.number().int().positive()]).describe('IOC public_id (UUID) or numeric id'),
        providers: providerIdsSchema.optional().describe('"all" (default) or provider ids from list_enrichment_providers'),
        force_refresh: z.boolean().optional().describe('Refresh even when a fresh stored result exists (default false)'),
        wait_seconds: z.number().int().min(0).max(config.enrichWaitMaxSeconds).optional()
          .describe(`Wait up to this many seconds for the job to finish (default 0, max ${config.enrichWaitMaxSeconds})`)
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
    },
    async (args) => {
      const ctx = ctxFrom();
      return withAuth('enrich_ioc', ctx, () => mcpEnrichIocs(deps.pool, args, ctx, { bulk: false }));
    }
  );

  server.registerTool(
    'bulk_enrich_iocs',
    {
      title: 'Bulk enrich IOCs (triggers providers)',
      description:
        `ACTION: triggers external enrichment for up to ${config.enrichBulkMax} existing IOCs in one background job and may consume provider API quota. `
        + 'Requires mcp:enrichment:write and an analyst/admin owner. Same semantics as enrich_ioc (TalonHound-resolved IOC types, freshness skip, force_refresh rules, '
        + `deduplication, per-provider status). Hard limits: ${config.enrichBulkMax} IOCs and ${config.enrichMaxOperations} provider operations (IOCs × providers that would actually run) per call — `
        + 'larger sets must be chunked deliberately; never use this to enrich the whole inventory. Provider calls are paced by per-provider automation budgets, so large jobs take minutes: '
        + 'poll get_enrichment_job, then read results with get_ioc_context.',
      inputSchema: {
        ioc_ids: z.array(z.union([z.string().min(1).max(64), z.number().int().positive()]))
          .min(1).max(config.enrichBulkMax).describe('IOC public_ids (UUID) or numeric ids'),
        providers: providerIdsSchema.optional().describe('"all" (default) or provider ids from list_enrichment_providers'),
        force_refresh: z.boolean().optional().describe('Refresh even when fresh stored results exist (default false)'),
        wait_seconds: z.number().int().min(0).max(config.enrichWaitMaxSeconds).optional()
          .describe(`Wait up to this many seconds for the job to finish (default 0, max ${config.enrichWaitMaxSeconds})`)
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
    },
    async (args) => {
      const ctx = ctxFrom();
      return withAuth('bulk_enrich_iocs', ctx, () => mcpEnrichIocs(deps.pool, args, ctx, { bulk: true }));
    }
  );

  server.registerTool(
    'get_enrichment_job',
    {
      title: 'Get enrichment job',
      description:
        'Status of an enrichment job created by enrich_ioc / bulk_enrich_iocs (same owner only): job status (queued, running, completed, partially_completed, failed), '
        + 'per-IOC, per-provider status with error_code / message / last_enriched_at, and a status summary. Deduplicated items show the status of the in-flight request they joined. '
        + 'Read-only: never triggers enrichment. Read the enrichment itself with get_ioc_context.',
      inputSchema: {
        job_id: z.string().min(36).max(36).describe('Enrichment job id (uuid)')
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => {
      const ctx = ctxFrom();
      return withAuth('get_enrichment_job', ctx, () => mcpGetEnrichmentJob(deps.pool, args, ctx));
    }
  );

  // ---------------------------------------------------------------------------
  // Tags: catalog (read) and analyst tag assignments (action).
  // ---------------------------------------------------------------------------

  const tagNamesSchema = z.array(z.string().min(1).max(100)).min(1).max(config.tagWriteMax);

  server.registerTool(
    'list_tags',
    {
      title: 'List tags',
      description:
        'List the enabled TalonHound tag catalog — the tags an analyst can assign on IOC Details (name, category, description). '
        + 'add_ioc_tags only accepts names from this catalog. Optional `query` = case-insensitive name contains filter. '
        + `Bounded (max ${config.tagListMax}); \`truncated\` = more tags match, narrow the query. Requires an analyst/admin owner. `
        + 'Read-only: never changes tags and never triggers external/paid enrichment.',
      inputSchema: {
        query: z.string().max(100).optional().describe('Tag name contains filter (case-insensitive)'),
        limit: z.number().int().min(1).max(config.tagListMax).optional()
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
    },
    async (args) => {
      const ctx = ctxFrom();
      return withAuth('list_tags', ctx, () => mcpListTags(deps.pool, args, ctx));
    }
  );

  server.registerTool(
    'add_ioc_tags',
    {
      title: 'Add IOC tags',
      description:
        'ACTION: add analyst tags to ONE existing IOC — the same write as adding a tag on IOC Details (origin `manual`). '
        + 'Requires mcp:tags:write and an analyst/admin owner. `ioc_id` = IOC public_id (UUID) from lookup_ioc / search_iocs / get_ioc_context (numeric id also accepted). '
        + `\`tags\` = 1-${config.tagWriteMax} existing, enabled tag names from list_tags (matched case-insensitively). All-or-nothing: if any name is unknown or disabled, `
        + 'nothing is changed (error TAG_NOT_ALLOWED) — MCP never creates catalog tags or re-enables disabled ones. Idempotent: tags already assigned by an analyst are reported in `already_present`. '
        + 'Returns `added`, `already_present` and the resulting effective IOC `tags` / `tags_detail`. Each added tag is audited (ioc.tag.added) with MCP provenance.',
      inputSchema: {
        ioc_id: z.union([z.string().min(1).max(64), z.number().int().positive()]).describe('IOC public_id (UUID) or numeric id'),
        tags: tagNamesSchema.describe('Tag names from list_tags')
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
    },
    async (args) => {
      const ctx = ctxFrom();
      return withAuth('add_ioc_tags', ctx, () => mcpAddIocTags(deps.pool, args, ctx));
    }
  );

  server.registerTool(
    'remove_ioc_tags',
    {
      title: 'Remove IOC tags',
      description:
        'ACTION: remove analyst tags (origin `manual`) from ONE existing IOC — the same rule as removing a tag on IOC Details. '
        + 'Requires mcp:tags:write and an analyst/admin owner. Source/feed (integration) tags and Threat Library report tags are never removed: they are reported in '
        + '`not_removable` with their origins; names the IOC does not carry are in `not_assigned`. Returns `removed` and the resulting effective IOC `tags` / `tags_detail`. '
        + 'Each removed tag is audited (ioc.tag.removed) with MCP provenance.',
      inputSchema: {
        ioc_id: z.union([z.string().min(1).max(64), z.number().int().positive()]).describe('IOC public_id (UUID) or numeric id'),
        tags: tagNamesSchema.describe('Tag names to remove')
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false }
    },
    async (args) => {
      const ctx = ctxFrom();
      return withAuth('remove_ioc_tags', ctx, () => mcpRemoveIocTags(deps.pool, args, ctx));
    }
  );
}
