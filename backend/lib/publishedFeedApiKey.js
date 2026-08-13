// Helpers for TalonHound API keys (th_pf_ / th_ioc_ / th_read_).

import crypto from 'node:crypto';
import { hashFeedAccessToken } from './feedAccessToken.js';
import {
  ACCESS_PROFILE,
  LEGACY_FEED_ACCESS_KEY_TYPE,
  getAccessProfile
} from './apiKeyProfiles.js';

export { ACCESS_PROFILE, LEGACY_FEED_ACCESS_KEY_TYPE };

export const PUBLISHED_FEED_KEY_TYPE = ACCESS_PROFILE.PUBLISHED_FEED;
export const IOC_MANAGEMENT_KEY_TYPE = ACCESS_PROFILE.IOC_MANAGEMENT;
export const IOC_READ_KEY_TYPE = ACCESS_PROFILE.IOC_READ;
export const PUBLISHED_FEED_KEY_PREFIX = 'th_pf_';
export const IOC_MANAGEMENT_KEY_PREFIX = 'th_ioc_';
export const IOC_READ_KEY_PREFIX = 'th_read_';

const SECRET_BYTES = 32;
const MASK_BODY = '•'.repeat(12);

/** @deprecated Use ACCESS_PROFILE / generateApiKeyForProfile */
export function generatePublishedFeedApiKey() {
  return generateApiKeyForProfile(PUBLISHED_FEED_KEY_TYPE);
}

/** Generate a plaintext API key for a creatable access profile. */
export function generateApiKeyForProfile(profileId) {
  const profile = getAccessProfile(profileId);
  if (!profile?.creatable || !profile.key_prefix) {
    throw Object.assign(new Error('Cannot generate key for this access profile'), {
      code: 'INVALID_ACCESS_PROFILE'
    });
  }
  return profile.key_prefix + crypto.randomBytes(SECRET_BYTES).toString('base64url');
}

/** SHA-256 hex hash used for lookup/verification (shared with legacy tokens). */
export function hashApiKey(rawKey) {
  return hashFeedAccessToken(rawKey);
}

/** Last 4 characters of a raw key, for masked display + copy verification. */
export function lastFourOf(rawKey) {
  const s = String(rawKey || '');
  return s.slice(-4);
}

/**
 * Masked display value, e.g. `th_pf_••••••••••••abcd` or `th_ioc_••••••••••••abcd`.
 * @param {{ key_prefix?: string, last_four?: string, key_type?: string }} row
 */
export function maskApiKey(row) {
  const profile = getAccessProfile(row?.key_type);
  const prefix = row?.key_prefix || profile?.key_prefix || PUBLISHED_FEED_KEY_PREFIX;
  const lastFour = row?.last_four || '';
  return `${prefix}${MASK_BODY}${lastFour}`;
}

/**
 * Constant-time comparison of two SHA-256 hex hashes. Returns false on any
 * length/format mismatch without leaking timing about where they differ.
 */
export function timingSafeHashEqual(aHex, bHex) {
  try {
    const a = Buffer.from(String(aHex), 'hex');
    const b = Buffer.from(String(bHex), 'hex');
    if (a.length === 0 || a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Redact API key material in strings (URLs, log lines, error messages).
 * @param {string} text
 */
export function redactApiKeyInText(text) {
  if (text == null) return text;
  return String(text)
    .replace(/([?&](?:api_key|apikey|key|token)=)[^&\s"']+/gi, '$1[REDACTED]')
    .replace(/th_pf_[A-Za-z0-9_-]+/g, 'th_pf_[REDACTED]')
    .replace(/th_ioc_[A-Za-z0-9_-]+/g, 'th_ioc_[REDACTED]')
    .replace(/th_read_[A-Za-z0-9_-]+/g, 'th_read_[REDACTED]')
    .replace(/(Bearer\s+)\S+/gi, '$1[REDACTED]');
}

/** A stored key is revealable only if it carries an encrypted secret and is a modern profile. */
export function isRevealableKeyRow(row) {
  const profile = getAccessProfile(row?.key_type);
  return Boolean(row?.secret_ciphertext)
    && Boolean(profile?.creatable && profile.key_prefix);
}

/**
 * Derive UI status from a key row.
 * Soft-deleted keys (and any legacy revoked rows) are reported as `deleted`; such
 * keys are hidden from the list and rejected by every auth path.
 * @returns {'deleted'|'expired'|'disabled'|'active'}
 */
export function keyStatus(row, now = new Date()) {
  if (row?.deleted_at || row?.revoked_at) return 'deleted';
  if (row?.expires_at && new Date(row.expires_at).getTime() <= now.getTime()) return 'expired';
  if (!row?.enabled) return 'disabled';
  return 'active';
}
