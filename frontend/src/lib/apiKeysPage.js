/**
 * Pure helpers for the Administration › API Keys page (testable without React).
 */

export const API_KEYS_PAGE_DESCRIPTION =
  'Create and manage credentials for programmatic access to TalonHound. Each API key is restricted to its assigned access profile and permissions.';

export const ACCESS_PROFILE_OPTIONS = Object.freeze([
  Object.freeze({
    id: 'published_feed',
    label: 'Published Feed',
    description: 'Read published threat feeds only.',
    permission_summary: 'Read feeds'
  }),
  Object.freeze({
    id: 'ioc_management',
    label: 'IOC Management',
    description: 'Create and update IOCs through the API. Cannot delete IOCs or access administrative APIs.',
    permission_summary: 'Create + Update IOCs'
  }),
  Object.freeze({
    id: 'ioc_read',
    label: 'IOC Read',
    description: 'Read, search, and export IOC data. Cannot create, update, or delete IOCs.',
    permission_summary: 'Read + Search + Export IOCs'
  }),
  Object.freeze({
    id: 'mcp_read',
    label: 'MCP Read',
    description:
      'Read-only MCP (/mcp) access for AI clients. Bound to an owner user; effective rights are the intersection of token scopes and the owner role. Cannot import IOCs.',
    permission_summary: 'MCP read + sources + enrichment'
  }),
  Object.freeze({
    id: 'mcp_analyst',
    label: 'MCP Analyst',
    description:
      'MCP (/mcp) access for AI clients with controlled IOC import into existing IOC Sources. Bound to an owner user; import requires both mcp:ioc:create on the token and an analyst/admin owner role.',
    permission_summary: 'MCP read + import into IOC Sources'
  })
]);

const MCP_OWNER_PROFILES = new Set(['mcp_read', 'mcp_analyst']);

export function apiKeyCreatePayload({
  name,
  accessProfile,
  enabled = true,
  ownerUserId,
  ownerPublicId
} = {}) {
  const trimmed = String(name || '').trim();
  const profile = String(accessProfile || '').trim().toLowerCase();
  const errors = [];
  const known = ACCESS_PROFILE_OPTIONS.some((o) => o.id === profile);
  if (!trimmed) errors.push('name');
  if (!known) errors.push('access_profile');

  const needsOwner = MCP_OWNER_PROFILES.has(profile);
  const hasOwnerUserId = ownerUserId != null && String(ownerUserId).trim() !== '';
  const hasOwnerPublicId = ownerPublicId != null && String(ownerPublicId).trim() !== '';
  if (needsOwner && !hasOwnerUserId && !hasOwnerPublicId) {
    errors.push('owner');
  }

  if (errors.length) {
    return { ok: false, errors };
  }

  const body = {
    name: trimmed,
    access_profile: profile,
    key_type: profile,
    enabled: Boolean(enabled)
  };
  if (needsOwner) {
    if (hasOwnerUserId) body.owner_user_id = Number(ownerUserId);
    if (hasOwnerPublicId) body.owner_public_id = String(ownerPublicId).trim();
  }
  return { ok: true, body };
}

export function accessProfilePermissionSummary(keyType) {
  const opt = ACCESS_PROFILE_OPTIONS.find((o) => o.id === keyType);
  if (opt) return opt.permission_summary;
  if (keyType === 'feed_access') return 'Read feeds';
  return '';
}

export function accessProfileLabel(keyType, fallbackLabel) {
  const opt = ACCESS_PROFILE_OPTIONS.find((o) => o.id === keyType);
  if (opt) return opt.label;
  return fallbackLabel || keyType || 'Unknown';
}

export const API_DOCS_PATH = '/api/docs';

/** Streamable HTTP MCP endpoint (Bearer MCP API key). */
export const MCP_ENDPOINT_PATH = '/mcp';

export const MCP_HELP_TEXT =
  'MCP credentials authenticate at /mcp. Bind each key to an owner user; rights are token scopes ∩ owner role.';
