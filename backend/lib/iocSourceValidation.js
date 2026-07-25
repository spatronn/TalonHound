export const IOC_SOURCE_TYPES = Object.freeze([
  'manual',
  'internal_hunting',
  'external_report',
  'feed',
  'test'
]);

export const MANUAL_EXPIRE_POLICIES = Object.freeze([
  'never',
  'expire_after_days',
  'custom_date'
]);

import { validateThreatClassificationSlug } from './threatClassification.js';
import { validateIocThreatClassificationSlugs } from './iocThreatClassifications.js';

export async function validatePrimaryThreatClassification(pool, value) {
  if (value == null || value === '') return { ok: true, value: 'unknown' };
  return validateThreatClassificationSlug(pool, value, { requireActive: true });
}

export async function validateThreatClassifications(pool, value) {
  return validateIocThreatClassificationSlugs(pool, value, { requireActive: true });
}

const NAME_PATTERN = /^[A-Za-z0-9_-]{3,64}$/;

export function normalizeSourceNameInput(raw) {
  let name = String(raw || '').trim();
  name = name.replace(/\s+/g, '_');
  name = name.replace(/[^A-Za-z0-9_-]/g, '');
  if (name.length > 64) name = name.slice(0, 64);
  return name;
}

export function validateSourceName(name) {
  const n = String(name || '').trim();
  if (!n) return { ok: false, error: 'name is required' };
  if (!NAME_PATTERN.test(n)) {
    return { ok: false, error: 'name must be 3–64 characters: letters, numbers, underscore, hyphen' };
  }
  return { ok: true, value: n };
}

export function validateSourceType(value) {
  const t = String(value || 'manual').trim();
  if (!IOC_SOURCE_TYPES.includes(t)) {
    return { ok: false, error: `source_type must be one of: ${IOC_SOURCE_TYPES.join(', ')}` };
  }
  return { ok: true, value: t };
}

export function validateDefaultConfidence(value) {
  if (value == null || value === '') return { ok: true, value: null };
  const c = String(value).trim().toLowerCase();
  if (!['low', 'medium', 'high'].includes(c)) {
    return { ok: false, error: 'default_confidence must be low, medium, or high' };
  }
  return { ok: true, value: c };
}

export function validateDefaultExpirePolicy(value) {
  if (value == null || value === '') return { ok: true, value: null };
  const p = String(value).trim();
  if (!MANUAL_EXPIRE_POLICIES.includes(p)) {
    return { ok: false, error: `default_expire_policy must be one of: ${MANUAL_EXPIRE_POLICIES.join(', ')}` };
  }
  return { ok: true, value: p };
}

export function validateExpireDays(value, required = false) {
  if (value == null || value === '') {
    if (required) return { ok: false, error: 'expire_days is required' };
    return { ok: true, value: null };
  }
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0 || n > 3650) {
    return { ok: false, error: 'expire_days must be a positive integer up to 3650' };
  }
  return { ok: true, value: n };
}

/**
 * @param {object} body
 * @param {{ now?: Date }} [opts]
 */
export function parseManualExpirationInput(body, opts = {}) {
  const now = opts.now instanceof Date ? opts.now : new Date();
  const policy = String(body?.expiration_policy || body?.expire_policy || 'never').trim();

  if (!MANUAL_EXPIRE_POLICIES.includes(policy)) {
    return { ok: false, error: `expiration_policy must be one of: ${MANUAL_EXPIRE_POLICIES.join(', ')}` };
  }

  if (policy === 'never') {
    return {
      ok: true,
      policy,
      manual_expires_at: null,
      manual_override_reason: 'manual_never_expire'
    };
  }

  if (policy === 'expire_after_days') {
    const daysCheck = validateExpireDays(body?.expire_days, true);
    if (!daysCheck.ok) return daysCheck;
    const expires = new Date(now.getTime());
    expires.setUTCDate(expires.getUTCDate() + daysCheck.value);
    return {
      ok: true,
      policy,
      expire_days: daysCheck.value,
      manual_expires_at: expires.toISOString(),
      manual_override_reason: 'manual_custom_expire'
    };
  }

  const rawDate = body?.expires_at || body?.custom_expires_at;
  if (!rawDate) {
    return { ok: false, error: 'expires_at is required for custom_date expiration policy' };
  }
  const d = new Date(rawDate);
  if (Number.isNaN(d.getTime())) {
    return { ok: false, error: 'expires_at must be a valid ISO date/time' };
  }
  if (d.getTime() <= now.getTime()) {
    return { ok: false, error: 'expires_at must be in the future' };
  }
  return {
    ok: true,
    policy,
    manual_expires_at: d.toISOString(),
    manual_override_reason: 'manual_custom_expire'
  };
}

export function serializeIocSourceRow(row) {
  if (!row) return null;
  const archivedAt = row.archived_at || null;
  const active = row.active !== false && !archivedAt;
  let state = 'active';
  if (archivedAt) state = 'archived';
  else if (row.active === false) state = 'disabled';
  const iocCount = row.ioc_count != null
    ? Number(row.ioc_count)
    : (row.usage_count != null ? Number(row.usage_count) : undefined);

  return {
    id: Number(row.id),
    name: row.name,
    description: row.description || null,
    default_confidence: row.default_confidence || null,
    default_threat_classification: row.default_threat_classification || null,
    default_expire_policy: row.default_expire_policy || null,
    default_expire_days: row.default_expire_days != null ? Number(row.default_expire_days) : null,
    color: row.color || null,
    active,
    state,
    archived_at: archivedAt,
    ioc_count: iocCount,
    usage_count: iocCount,
    created_by: row.created_by || null,
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}
