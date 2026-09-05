/**
 * MCP effective permissions = token scopes ∩ owner TalonHound RBAC ∩ tool policy.
 * An MCP token never elevates the owner user's privileges.
 */

import { hasApiScope, API_SCOPE } from './apiKeyProfiles.js';
import { isReadOnlyRole, normalizeAppRole, ROLES } from './rbac.js';

export const MCP_TOOL_SCOPES = Object.freeze({
  lookup_ioc: [API_SCOPE.MCP_IOC_READ],
  search_iocs: [API_SCOPE.MCP_IOC_READ],
  get_ioc_context: [API_SCOPE.MCP_IOC_READ],
  bulk_lookup_iocs: [API_SCOPE.MCP_IOC_READ],
  list_ioc_sources: [API_SCOPE.MCP_SOURCES_READ],
  import_iocs: [API_SCOPE.MCP_IOC_CREATE]
});

export function mcpHasScope(scopes, required) {
  return hasApiScope(scopes, required);
}

/** Owner may read IOC inventory through MCP when they have any app role. */
export function ownerCanMcpRead(role) {
  return Boolean(normalizeAppRole(role));
}

/**
 * Owner may create/import IOCs through MCP only when they could do so in the GUI
 * (analyst/admin). Readonly owners never get write rights, even with create scope.
 */
export function ownerCanMcpCreate(role) {
  const r = normalizeAppRole(role);
  return r === ROLES.ADMIN || r === ROLES.ANALYST;
}

export function effectiveMcpCapabilities({ scopes, ownerRole } = {}) {
  const scopeList = Array.isArray(scopes) ? scopes : [];
  const canReadOwner = ownerCanMcpRead(ownerRole);
  const canCreateOwner = ownerCanMcpCreate(ownerRole);
  return Object.freeze({
    ioc_read: canReadOwner && mcpHasScope(scopeList, API_SCOPE.MCP_IOC_READ),
    ioc_create: canCreateOwner && mcpHasScope(scopeList, API_SCOPE.MCP_IOC_CREATE),
    sources_read: canReadOwner && mcpHasScope(scopeList, API_SCOPE.MCP_SOURCES_READ),
    enrichment_read: canReadOwner && mcpHasScope(scopeList, API_SCOPE.MCP_ENRICHMENT_READ),
    owner_role: normalizeAppRole(ownerRole),
    owner_readonly: isReadOnlyRole(ownerRole)
  });
}

/**
 * @param {string} toolName
 * @param {{ scopes?: string[], ownerRole?: string }} auth
 * @returns {{ ok: true } | { ok: false, code: string, message: string }}
 */
export function authorizeMcpTool(toolName, auth = {}) {
  const name = String(toolName || '').trim();
  const required = MCP_TOOL_SCOPES[name];
  if (!required) {
    return { ok: false, code: 'UNKNOWN_TOOL', message: `Unknown MCP tool: ${name}` };
  }
  const caps = effectiveMcpCapabilities(auth);
  for (const scope of required) {
    if (!mcpHasScope(auth.scopes, scope)) {
      return {
        ok: false,
        code: 'MISSING_SCOPE',
        message: `MCP credential lacks required scope: ${scope}`
      };
    }
  }
  if (name === 'import_iocs') {
    if (!caps.ioc_create) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to create IOCs'
      };
    }
  } else if (name === 'list_ioc_sources') {
    if (!caps.sources_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to list IOC Sources'
      };
    }
  } else if (!caps.ioc_read && name !== 'list_ioc_sources') {
    return {
      ok: false,
      code: 'RBAC_DENIED',
      message: 'Owner user is not permitted to read IOCs'
    };
  }
  return { ok: true };
}
