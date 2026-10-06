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
 *   getRequestContext: () => { req?: import('express').Request }
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
        + 'import_iocs supports dry_run. There are no delete or admin tools.'
    }
  );

  registerMcpTools(server, deps);
  return server;
}
