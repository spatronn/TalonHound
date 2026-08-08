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
  })
]);

export function apiKeyCreatePayload({ name, accessProfile, enabled = true } = {}) {
  const trimmed = String(name || '').trim();
  const profile = String(accessProfile || '').trim().toLowerCase();
  const errors = [];
  if (!trimmed) errors.push('name');
  if (profile !== 'published_feed' && profile !== 'ioc_management') errors.push('access_profile');
  if (errors.length) {
    return { ok: false, errors };
  }
  return {
    ok: true,
    body: {
      name: trimmed,
      access_profile: profile,
      key_type: profile,
      enabled: Boolean(enabled)
    }
  };
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
