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

const OWNER_PUBLIC_ID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * GET /api/users returns the stable public UUID as `id` (see backend toPublicUser).
 * Prefer `id`; accept `public_id` only as a defensive fallback.
 */
export function ownerPublicIdFromUser(user) {
  const fromId = String(user?.id || '').trim();
  if (OWNER_PUBLIC_ID_RE.test(fromId)) return fromId;
  const fromPublic = String(user?.public_id || '').trim();
  if (OWNER_PUBLIC_ID_RE.test(fromPublic)) return fromPublic;
  return '';
}

export function ownerOptionLabel(user) {
  const username = String(user?.username || '').trim() || 'unknown';
  const role = String(user?.role || '').trim();
  return role ? `${username} (${role})` : username;
}

/**
 * Build <select> options so the visible label never becomes the submitted value.
 * @returns {{ value: string, label: string, status: string }[]}
 */
export function buildOwnerSelectOptions(users) {
  const list = Array.isArray(users) ? users : [];
  const out = [];
  const seen = new Set();
  for (const user of list) {
    const value = ownerPublicIdFromUser(user);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push({
      value,
      label: ownerOptionLabel(user),
      status: String(user?.status || 'active').trim().toLowerCase() || 'active'
    });
  }
  return out;
}

export function accessProfileRequiresOwner(accessProfile) {
  return MCP_OWNER_PROFILES.has(String(accessProfile || '').trim().toLowerCase());
}

/**
 * Keep form.owner_public_id aligned with the selected MCP profile and available options.
 * Clears owner when leaving MCP profiles; preserves a still-valid selection across MCP switches.
 */
export function nextOwnerPublicIdForProfileChange(previousOwnerPublicId, nextAccessProfile, ownerOptions) {
  if (!accessProfileRequiresOwner(nextAccessProfile)) return '';
  const prev = String(previousOwnerPublicId || '').trim();
  const options = Array.isArray(ownerOptions) ? ownerOptions : [];
  if (prev && options.some((o) => o.value === prev)) return prev;
  return '';
}

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
