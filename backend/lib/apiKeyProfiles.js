/**
 * Access profiles → scopes. Profiles are fixed presets; scopes authorize.
 */

export const API_SCOPE = Object.freeze({
  PUBLISHED_FEEDS_READ: 'published_feeds:read',
  IOC_CREATE: 'ioc:create',
  IOC_UPDATE: 'ioc:update',
  IOC_READ: 'ioc:read',
  IOC_EXPORT: 'ioc:export',
  MCP_IOC_READ: 'mcp:ioc:read',
  MCP_IOC_CREATE: 'mcp:ioc:create',
  MCP_ENRICHMENT_READ: 'mcp:enrichment:read',
  MCP_SOURCES_READ: 'mcp:sources:read'
});

export const ALL_API_SCOPES = Object.freeze([
  API_SCOPE.PUBLISHED_FEEDS_READ,
  API_SCOPE.IOC_CREATE,
  API_SCOPE.IOC_UPDATE,
  API_SCOPE.IOC_READ,
  API_SCOPE.IOC_EXPORT,
  API_SCOPE.MCP_IOC_READ,
  API_SCOPE.MCP_IOC_CREATE,
  API_SCOPE.MCP_ENRICHMENT_READ,
  API_SCOPE.MCP_SOURCES_READ
]);

export const ACCESS_PROFILE = Object.freeze({
  PUBLISHED_FEED: 'published_feed',
  IOC_MANAGEMENT: 'ioc_management',
  IOC_READ: 'ioc_read',
  MCP_READ: 'mcp_read',
  MCP_ANALYST: 'mcp_analyst',
  /** Legacy hash-only per-feed keys — still mapped to feed-read scope. */
  FEED_ACCESS: 'feed_access'
});

export const LEGACY_FEED_ACCESS_KEY_TYPE = ACCESS_PROFILE.FEED_ACCESS;

const PROFILE_DEFS = Object.freeze({
  [ACCESS_PROFILE.PUBLISHED_FEED]: Object.freeze({
    id: ACCESS_PROFILE.PUBLISHED_FEED,
    label: 'Published Feed',
    description: 'Read published threat feeds only.',
    permission_summary: 'Read feeds',
    key_prefix: 'th_pf_',
    scopes: Object.freeze([API_SCOPE.PUBLISHED_FEEDS_READ]),
    creatable: true,
    requiresOwner: false
  }),
  [ACCESS_PROFILE.IOC_MANAGEMENT]: Object.freeze({
    id: ACCESS_PROFILE.IOC_MANAGEMENT,
    label: 'IOC Management',
    description: 'Create and update IOCs through the API. Cannot delete IOCs or access administrative APIs.',
    permission_summary: 'Create + Update IOCs',
    key_prefix: 'th_ioc_',
    scopes: Object.freeze([API_SCOPE.IOC_CREATE, API_SCOPE.IOC_UPDATE]),
    creatable: true,
    requiresOwner: false
  }),
  [ACCESS_PROFILE.IOC_READ]: Object.freeze({
    id: ACCESS_PROFILE.IOC_READ,
    label: 'IOC Read',
    description: 'Read, search, and export IOC data. Cannot create, update, or delete IOCs.',
    permission_summary: 'Read + Search + Export IOCs',
    key_prefix: 'th_read_',
    scopes: Object.freeze([API_SCOPE.IOC_READ, API_SCOPE.IOC_EXPORT]),
    creatable: true,
    requiresOwner: false
  }),
  [ACCESS_PROFILE.MCP_READ]: Object.freeze({
    id: ACCESS_PROFILE.MCP_READ,
    label: 'MCP Read',
    description: 'Read-only MCP access for AI clients: lookup, search, context, bulk lookup, and list IOC Sources. Bound to an owner user; cannot import IOCs.',
    permission_summary: 'MCP read + sources + enrichment',
    key_prefix: 'th_mcp_',
    scopes: Object.freeze([
      API_SCOPE.MCP_IOC_READ,
      API_SCOPE.MCP_SOURCES_READ,
      API_SCOPE.MCP_ENRICHMENT_READ
    ]),
    creatable: true,
    requiresOwner: true
  }),
  [ACCESS_PROFILE.MCP_ANALYST]: Object.freeze({
    id: ACCESS_PROFILE.MCP_ANALYST,
    label: 'MCP Analyst',
    description: 'MCP access for AI clients with controlled IOC import into existing IOC Sources. Bound to an owner user; effective rights are the intersection of token scopes and the owner role.',
    permission_summary: 'MCP read + import into IOC Sources',
    key_prefix: 'th_mcp_',
    scopes: Object.freeze([
      API_SCOPE.MCP_IOC_READ,
      API_SCOPE.MCP_IOC_CREATE,
      API_SCOPE.MCP_SOURCES_READ,
      API_SCOPE.MCP_ENRICHMENT_READ
    ]),
    creatable: true,
    requiresOwner: true
  }),
  [ACCESS_PROFILE.FEED_ACCESS]: Object.freeze({
    id: ACCESS_PROFILE.FEED_ACCESS,
    label: 'Feed Access (legacy)',
    description: 'Legacy feed-bound access token.',
    permission_summary: 'Read feeds',
    key_prefix: '',
    scopes: Object.freeze([API_SCOPE.PUBLISHED_FEEDS_READ]),
    creatable: false,
    requiresOwner: false
  })
});

export function listCreatableAccessProfiles() {
  return Object.values(PROFILE_DEFS).filter((p) => p.creatable);
}

export function getAccessProfile(profileId) {
  const id = String(profileId || '').trim().toLowerCase();
  return PROFILE_DEFS[id] || null;
}

/** Stable scopes for a profile. Returns a fresh mutable copy for DB insert. */
export function scopesForAccessProfile(profileId) {
  const profile = getAccessProfile(profileId);
  return profile ? [...profile.scopes] : [];
}

export function normalizeScopes(raw) {
  if (Array.isArray(raw)) {
    return raw.map((s) => String(s || '').trim()).filter(Boolean);
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? normalizeScopes(parsed) : [];
    } catch {
      return [];
    }
  }
  return [];
}

export function hasApiScope(scopes, requiredScope) {
  const required = String(requiredScope || '').trim();
  if (!required) return false;
  return normalizeScopes(scopes).includes(required);
}

export function profileRequiresOwner(profileId) {
  return Boolean(getAccessProfile(profileId)?.requiresOwner);
}

export function isMcpAccessProfile(profileId) {
  const id = String(profileId || '').trim().toLowerCase();
  return id === ACCESS_PROFILE.MCP_READ || id === ACCESS_PROFILE.MCP_ANALYST;
}

export function profileLabel(profileId) {
  return getAccessProfile(profileId)?.label || String(profileId || 'Unknown');
}

export function profilePermissionSummary(profileId) {
  return getAccessProfile(profileId)?.permission_summary || '';
}
