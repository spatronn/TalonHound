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
  get_threat_report: [API_SCOPE.MCP_IOC_READ],
  bulk_lookup_iocs: [API_SCOPE.MCP_IOC_READ],
  list_ioc_sources: [API_SCOPE.MCP_SOURCES_READ],
  import_iocs: [API_SCOPE.MCP_IOC_CREATE],
  list_enrichment_providers: [API_SCOPE.MCP_ENRICHMENT_READ],
  get_enrichment_job: [API_SCOPE.MCP_ENRICHMENT_READ],
  // Action tools: trigger external (possibly paid) providers. Separate scope —
  // never implied by mcp:ioc:read, mcp:enrichment:read or mcp:ioc:create.
  enrich_ioc: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_ENRICHMENT_WRITE],
  bulk_enrich_iocs: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_ENRICHMENT_WRITE],
  // Tag catalog = the IOC Details tag picker (GET /api/tags, analyst/admin).
  list_tags: [API_SCOPE.MCP_IOC_READ],
  // Malware Families catalog discovery (active catalog for IOC picker / MCP).
  list_malware_families: [API_SCOPE.MCP_IOC_READ],
  // Malware Family → IOC discovery (read-only reverse lookup).
  list_iocs_by_malware_family: [API_SCOPE.MCP_IOC_READ],
  // Analyst (manual) IOC tag writes. Separate scope — never implied by read,
  // import or enrichment scopes.
  add_ioc_tags: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_TAGS_WRITE],
  remove_ioc_tags: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_TAGS_WRITE],
  // Threat Library URL import = Import Intelligence → URL (fetch + analysis run
  // in the worker). Separate scope — never implied by read, IOC import, enrichment
  // or tag scopes.
  threat_library_import_url: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_IMPORT],
  // Processing state of one report (persisted status only).
  get_threat_library_import_status: [API_SCOPE.MCP_IOC_READ],
  // Post-import Threat Library review surface (persisted candidates + gates).
  threat_library_get_review: [API_SCOPE.MCP_IOC_READ],
  threat_library_get_workflow_status: [API_SCOPE.MCP_IOC_READ],
  // Analyst mutations — same requireRole(admin, analyst) gate as the UI review /
  // Create IOCs / finalize / linked-source routes. Separate write scope.
  threat_library_review_iocs: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_WRITE],
  threat_library_create_iocs: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_WRITE],
  threat_library_finalize_report: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_WRITE],
  threat_library_review_ioc_source: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_WRITE]
});

/** Tools that trigger external enrichment (side effects + provider quota). */
export const MCP_ENRICHMENT_ACTION_TOOLS = Object.freeze(['enrich_ioc', 'bulk_enrich_iocs']);

/** Tools that change an IOC's analyst tags (write their own ioc.tag.* audit events). */
export const MCP_TAG_ACTION_TOOLS = Object.freeze(['add_ioc_tags', 'remove_ioc_tags']);

/** Tools that import Threat Library reports (write the GUI's threat_library.report.* import audit events). */
export const MCP_THREAT_LIBRARY_IMPORT_ACTION_TOOLS = Object.freeze(['threat_library_import_url']);

/**
 * Tools that mutate Threat Library review / Create IOCs / finalize / linked
 * IOC Source state (write the GUI's threat_library.* review audit events).
 */
export const MCP_THREAT_LIBRARY_WRITE_ACTION_TOOLS = Object.freeze([
  'threat_library_review_iocs',
  'threat_library_create_iocs',
  'threat_library_finalize_report',
  'threat_library_review_ioc_source'
]);

/** @deprecated Use MCP_THREAT_LIBRARY_IMPORT_ACTION_TOOLS — kept for older imports. */
export const MCP_THREAT_LIBRARY_ACTION_TOOLS = MCP_THREAT_LIBRARY_IMPORT_ACTION_TOOLS;

export function mcpHasScope(scopes, required) {
  return hasApiScope(scopes, required);
}

/** Owner may read IOC inventory through MCP when they have any app role. */
export function ownerCanMcpRead(role) {
  return Boolean(normalizeAppRole(role));
}

/**
 * Owner may trigger enrichment through MCP only when they could press the
 * IOC Details refresh buttons in the GUI (analyst/admin; readonly is blocked by
 * rbacHttpPolicy). Force refresh additionally follows each provider's own rule
 * (admin-only where the GUI requires it), enforced inside the shared refresh code.
 */
export function ownerCanMcpEnrich(role) {
  const r = normalizeAppRole(role);
  return r === ROLES.ADMIN || r === ROLES.ANALYST;
}

/**
 * Owner may use the tag catalog and add/remove analyst tags through MCP only
 * when they could in the GUI: GET /api/tags and POST/DELETE /api/ioc/:id/tags
 * are analyst/admin (readonly is blocked by rbacHttpPolicy).
 */
export function ownerCanMcpTag(role) {
  const r = normalizeAppRole(role);
  return r === ROLES.ADMIN || r === ROLES.ANALYST;
}

/**
 * Owner may create/import IOCs through MCP only when they could do so in the GUI
 * (analyst/admin). Readonly owners never get write rights, even with create scope.
 */
export function ownerCanMcpCreate(role) {
  const r = normalizeAppRole(role);
  return r === ROLES.ADMIN || r === ROLES.ANALYST;
}

/**
 * Owner may import Threat Library reports through MCP only when they could press
 * Import Intelligence → Start Import in the GUI: POST /api/threat-library/import/url
 * is requireRole(admin, analyst).
 */
export function ownerCanMcpImportReport(role) {
  const r = normalizeAppRole(role);
  return r === ROLES.ADMIN || r === ROLES.ANALYST;
}

/**
 * Owner may review / Create IOCs / finalize Threat Library reports through MCP
 * only when they could in the GUI: POST …/review, …/finalize and linked IOC
 * Source approve/dismiss are requireRole(admin, analyst).
 */
export function ownerCanMcpThreatLibraryWrite(role) {
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
    enrichment_write: ownerCanMcpEnrich(ownerRole) && mcpHasScope(scopeList, API_SCOPE.MCP_ENRICHMENT_WRITE),
    tags_read: ownerCanMcpTag(ownerRole) && mcpHasScope(scopeList, API_SCOPE.MCP_IOC_READ),
    tags_write: ownerCanMcpTag(ownerRole) && mcpHasScope(scopeList, API_SCOPE.MCP_TAGS_WRITE),
    // Same owner gate as tags: catalog discovery for analyst/admin pickers.
    malware_families_read: ownerCanMcpTag(ownerRole) && mcpHasScope(scopeList, API_SCOPE.MCP_IOC_READ),
    threat_library_import: ownerCanMcpImportReport(ownerRole) && mcpHasScope(scopeList, API_SCOPE.MCP_THREAT_LIBRARY_IMPORT),
    threat_library_write: ownerCanMcpThreatLibraryWrite(ownerRole) && mcpHasScope(scopeList, API_SCOPE.MCP_THREAT_LIBRARY_WRITE),
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
  } else if (MCP_ENRICHMENT_ACTION_TOOLS.includes(name)) {
    if (!caps.enrichment_write || !caps.ioc_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to trigger enrichment'
      };
    }
  } else if (MCP_TAG_ACTION_TOOLS.includes(name)) {
    if (!caps.tags_write || !caps.ioc_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to change IOC tags'
      };
    }
  } else if (MCP_THREAT_LIBRARY_IMPORT_ACTION_TOOLS.includes(name)) {
    if (!caps.threat_library_import || !caps.ioc_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to import Threat Library reports'
      };
    }
  } else if (MCP_THREAT_LIBRARY_WRITE_ACTION_TOOLS.includes(name)) {
    if (!caps.threat_library_write || !caps.ioc_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to review or finalize Threat Library reports'
      };
    }
  } else if (name === 'list_tags') {
    if (!caps.tags_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to read the tag catalog'
      };
    }
  } else if (name === 'list_malware_families' || name === 'list_iocs_by_malware_family') {
    if (!caps.malware_families_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to read the malware family catalog'
      };
    }
  } else if (name === 'list_enrichment_providers' || name === 'get_enrichment_job') {
    if (!caps.enrichment_read) {
      return {
        ok: false,
        code: 'RBAC_DENIED',
        message: 'Owner user is not permitted to read enrichment'
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
