/**
 * Factory for a per-request MCP server instance (stateless Streamable HTTP).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerMcpTools } from './mcpTools.js';
import { readCanonicalVersion } from './productVersion.js';

/**
 * @param {{
 *   pool: import('pg').Pool,
 *   audit?: object,
 *   getRequestContext: () => { req?: import('express').Request },
 *   threatLibraryQueue?: import('bullmq').Queue|null
 * }} deps
 */
export function createTalonHoundMcpServer(deps) {
  let version = '0.0.0';
  try {
    version = readCanonicalVersion() || version;
  } catch {
    /* ignore */
  }

  const server = new McpServer(
    {
      name: 'talonhound',
      version
    },
    {
      capabilities: {
        tools: {}
      },
      instructions:
        'TalonHound MCP Server. Use lookup_ioc / search_iocs / get_ioc_context / bulk_lookup_iocs / get_threat_report for reads. '
        + 'get_ioc_context may include derived_infrastructure for URL IOCs with an IP host (UI Derived Infrastructure) '
        + 'without registering that host as an IOC. '
        + 'get_ioc_context.threat_context carries Threat Library claims/relationships (IOC Details Threat Context), '
        + 'with per-claim IOC occurrences and report summary/entities; report-level entities are co-mentions, not IOC relationships. '
        + 'IOC `sources` are per-provider memberships with their own lifecycle; `evidence_sources` is the deduplicated provider list (incl. Threat Library). '
        + '`report_context_tags` are report-level context, not assertions about the IOC. '
        + 'get_threat_report drills into one report by threat_context.claims[].report.id: counts.all / counts.indicators / counts.context_only (Indicators = publisher-membership set, not the raw roster), paged indicators roster (All / document order) with per-row role/assessment, entities, explicit relationships. '
        + 'Use list_ioc_sources then import_iocs to add missing IOCs into an existing IOC Source. '
        + 'Never invent a special MCP/AI source — always use a real IOC Source. '
        + 'import_iocs supports dry_run. There are no IOC delete or admin tools. '
        + 'Side effects: every read tool (lookup/search/context/bulk lookup/report/sources/list_enrichment_providers/get_enrichment_job/list_tags/list_malware_families/list_iocs_by_malware_family) returns persisted data only and never triggers external enrichment. '
        + 'get_ioc_context includes threat_actors and malware_families (analyst ∪ source-reported with provenance); discover the catalog with list_malware_families and the IOCs of a family (analyst + current source-reported, deduplicated, Pulse context ≠ proof of sample) with list_iocs_by_malware_family. '
        + 'enrich_ioc / bulk_enrich_iocs are explicit ACTION tools (require mcp:enrichment:write): they run TalonHound enrichment providers on existing IOCs, may consume provider API quota, '
        + 'skip providers whose stored result is fresh unless force_refresh=true, and return a job_id — poll get_enrichment_job, then read results with get_ioc_context. '
        + 'Use list_enrichment_providers to discover provider ids; never enrich unbounded IOC sets (chunk deliberately). '
        + 'add_ioc_tags / remove_ioc_tags are ACTION tools (require mcp:tags:write) that change analyst tags on one IOC: only existing, enabled catalog tags (find them with list_tags) — '
        + 'MCP never creates tags; source/feed and Threat Library tags are never removed. '
        + 'threat_library_import_url is an ACTION tool (requires mcp:threat_library:import) = Threat Library Import Intelligence → URL: '
        + 'it queues a public report URL for the normal background fetch/extraction/analysis (duplicates return outcome already_exists with the existing report_id); '
        + 'poll get_threat_library_import_status until ingestion_complete or ingestion_failed, then read it with get_threat_report or threat_library_get_review. '
        + 'Importing a report never auto-approves IOC candidates or creates IOCs. '
        + 'Post-import lifecycle (requires mcp:threat_library:write): threat_library_get_review / threat_library_get_workflow_status (read), '
        + 'threat_library_review_iocs (explicit approve|context_only|ignore — never auto-approve all extracted), '
        + 'threat_library_create_iocs (same Create IOCs as the UI; confirm=true to commit), '
        + 'threat_library_finalize_report, threat_library_review_ioc_source (approve/dismiss linked packs). '
        + 'All mutations reuse the UI application services and audit events.'
    }
  );

  registerMcpTools(server, deps);
  return server;
}
