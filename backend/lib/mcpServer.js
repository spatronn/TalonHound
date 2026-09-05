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
        'TalonHound MCP Server. Use lookup_ioc / search_iocs / get_ioc_context / bulk_lookup_iocs for reads. '
        + 'Use list_ioc_sources then import_iocs to add missing IOCs into an existing IOC Source. '
        + 'Never invent a special MCP/AI source — always use a real IOC Source. '
        + 'import_iocs supports dry_run. There are no delete or admin tools.'
    }
  );

  registerMcpTools(server, deps);
  return server;
}
