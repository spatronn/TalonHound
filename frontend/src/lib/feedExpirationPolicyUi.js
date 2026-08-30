/**
 * Feed expiration policy UI helpers.
 *
 * Canonical modes (internal values unchanged):
 *   never | fixed_ttl | missing_from_feed_ttl
 *
 * Legacy last_seen_ttl is coerced to fixed_ttl for display/edit so existing
 * feed records do not crash the select. It is not offered as a new option.
 */

export const EXPIRATION_MODE_NEVER = 'never';
export const EXPIRATION_MODE_FIXED_TTL = 'fixed_ttl';
export const EXPIRATION_MODE_MISSING_FROM_FEED = 'missing_from_feed_ttl';
export const LEGACY_EXPIRATION_MODE_LAST_SEEN_TTL = 'last_seen_ttl';

export const EXPIRATION_MODE_OPTIONS = Object.freeze([
  { id: EXPIRATION_MODE_NEVER, label: 'Never' },
  { id: EXPIRATION_MODE_FIXED_TTL, label: 'Fixed TTL (from first seen in feed)' },
  {
    id: EXPIRATION_MODE_MISSING_FROM_FEED,
    label: 'Expire when removed from source'
  }
]);

export const MISSING_FROM_FEED_HELP =
  'Available only for feeds that provide a complete snapshot. IOCs no longer present in the source are marked as expired.';

export const MISSING_FROM_FEED_DISABLED_HELP =
  'This policy is only available for feeds that provide a complete snapshot.';

export const EXPIRATION_OVERRIDE_IOC_TYPES = Object.freeze(['domain', 'ip', 'url', 'file_hash']);

export const EXPIRATION_TYPE_OVERRIDE_TYPES = Object.freeze([
  { id: 'domain', label: 'Domain' },
  { id: 'ip', label: 'IP' },
  { id: 'url', label: 'URL' },
  { id: 'file_hash', label: 'Hash' }
]);

export const EXPIRATION_OVERRIDE_MODES = Object.freeze(['inherit', 'no_expire', 'fixed_ttl']);

export const EXPIRATION_TYPE_OVERRIDE_MODES = Object.freeze([
  { id: 'inherit', label: 'Inherit' },
  { id: 'no_expire', label: 'No expire' },
  { id: 'fixed_ttl', label: 'Fixed TTL' }
]);

export function isSnapshotFeedUpdateMode(feedUpdateMode) {
  return String(feedUpdateMode || '') === 'snapshot';
}

export function coerceExpirationModeForUi(mode) {
  const m = String(mode || EXPIRATION_MODE_NEVER).trim();
  if (m === LEGACY_EXPIRATION_MODE_LAST_SEEN_TTL) return EXPIRATION_MODE_FIXED_TTL;
  return m || EXPIRATION_MODE_NEVER;
}

export function expirationModeOptionDisabled(modeId, feedUpdateMode) {
  if (modeId !== EXPIRATION_MODE_MISSING_FROM_FEED) return false;
  if (feedUpdateMode == null || feedUpdateMode === '') return false;
  return !isSnapshotFeedUpdateMode(feedUpdateMode);
}

export function expirationPolicyModeHint(selectedMode, feedUpdateMode) {
  if (feedUpdateMode != null && feedUpdateMode !== '' && !isSnapshotFeedUpdateMode(feedUpdateMode)) {
    return MISSING_FROM_FEED_DISABLED_HELP;
  }
  if (coerceExpirationModeForUi(selectedMode) === EXPIRATION_MODE_MISSING_FROM_FEED) {
    return MISSING_FROM_FEED_HELP;
  }
  return null;
}

export function defaultTypeOverridesDraft(typePolicies) {
  const byType = {};
  for (const entry of Array.isArray(typePolicies) ? typePolicies : []) {
    if (entry?.ioc_type) byType[entry.ioc_type] = entry;
  }
  const draft = {};
  for (const t of EXPIRATION_TYPE_OVERRIDE_TYPES) {
    const p = byType[t.id];
    const mode = EXPIRATION_OVERRIDE_MODES.includes(p?.mode) ? p.mode : 'inherit';
    draft[t.id] = {
      mode,
      ttl_days: p?.ttl_days ?? ''
    };
  }
  return draft;
}

export function defaultExpirationDraft(policy, typePolicies) {
  const p = policy || {};
  return {
    enabled: Boolean(p.enabled),
    expiration_mode: coerceExpirationModeForUi(p.expiration_mode),
    ttl_days: p.ttl_days ?? '',
    grace_days: p.grace_days ?? '',
    type_overrides: defaultTypeOverridesDraft(typePolicies)
  };
}

export function buildExpirationPatchPayload(exp) {
  const enabled = Boolean(exp?.enabled);
  const mode = enabled ? coerceExpirationModeForUi(exp?.expiration_mode) : EXPIRATION_MODE_NEVER;
  const payload = {
    observable_type: 'all',
    enabled,
    expiration_mode: mode,
    ttl_days: null,
    grace_days: null
  };
  if (!enabled) return payload;

  if (mode === EXPIRATION_MODE_FIXED_TTL) {
    const raw = exp?.ttl_days;
    if (raw !== '' && raw != null) {
      const n = parseInt(String(raw), 10);
      if (Number.isFinite(n) && n > 0) payload.ttl_days = n;
    }
  }
  if (mode === EXPIRATION_MODE_MISSING_FROM_FEED) {
    const raw = exp?.grace_days !== '' && exp?.grace_days != null ? exp.grace_days : exp?.ttl_days;
    if (raw !== '' && raw != null) {
      const n = parseInt(String(raw), 10);
      if (Number.isFinite(n) && n > 0) payload.grace_days = n;
    }
  }
  return payload;
}

export function buildExpirationTypePoliciesPayload(overrides) {
  const out = [];
  const src = overrides || {};
  for (const iocType of EXPIRATION_OVERRIDE_IOC_TYPES) {
    const o = src[iocType] || {};
    const mode = EXPIRATION_OVERRIDE_MODES.includes(o.mode) ? o.mode : 'inherit';
    const entry = { ioc_type: iocType, mode, ttl_days: null };
    if (mode === EXPIRATION_MODE_FIXED_TTL) {
      const raw = o.ttl_days;
      const n = raw === '' || raw == null ? NaN : parseInt(String(raw), 10);
      if (Number.isFinite(n) && n > 0) entry.ttl_days = n;
    }
    out.push(entry);
  }
  return out;
}

export function buildExpirationFullPatchPayload(exp) {
  return {
    ...buildExpirationPatchPayload(exp),
    expiration_type_policies: buildExpirationTypePoliciesPayload(exp?.type_overrides)
  };
}

export function formatTypeOverridePreview(label, override, feedExp) {
  const mode = override?.mode || 'inherit';
  if (mode === 'no_expire') return `${label}: No expire`;
  if (mode === EXPIRATION_MODE_FIXED_TTL) {
    const n = parseInt(String(override?.ttl_days), 10);
    return Number.isFinite(n) && n > 0 ? `${label}: Fixed TTL ${n} days` : `${label}: Fixed TTL (set days)`;
  }
  if (!feedExp?.enabled || coerceExpirationModeForUi(feedExp?.expiration_mode) === EXPIRATION_MODE_NEVER) {
    return `${label}: Inherits default (no expiration)`;
  }
  const days = parseInt(String(feedExp?.ttl_days ?? feedExp?.grace_days), 10);
  return Number.isFinite(days) && days > 0
    ? `${label}: Inherits default ${days} days`
    : `${label}: Inherits default`;
}

export function expirationShowsTtlDays(exp) {
  return Boolean(exp?.enabled) && coerceExpirationModeForUi(exp?.expiration_mode) === EXPIRATION_MODE_FIXED_TTL;
}

export function expirationShowsGraceDays(exp) {
  return Boolean(exp?.enabled)
    && coerceExpirationModeForUi(exp?.expiration_mode) === EXPIRATION_MODE_MISSING_FROM_FEED;
}
