// Helpers for Published Feed API keys (the `th_pf_` type used by the
// /api/published-feeds/{slug}?api_key=... pull endpoint).

import crypto from 'node:crypto';
import { hashFeedAccessToken } from './feedAccessToken.js';

export const PUBLISHED_FEED_KEY_TYPE = 'published_feed';
export const LEGACY_FEED_ACCESS_KEY_TYPE = 'feed_access';
export const PUBLISHED_FEED_KEY_PREFIX = 'th_pf_';

const SECRET_BYTES = 32;
const MASK_BODY = '•'.repeat(12);

/** Generate a new plaintext Published Feed key, e.g. `th_pf_AbC123…`. */
export function generatePublishedFeedApiKey() {
  return PUBLISHED_FEED_KEY_PREFIX + crypto.randomBytes(SECRET_BYTES).toString('base64url');
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
 * Masked display value, e.g. `th_pf_••••••••••••abcd`.
 * @param {{ key_prefix?: string, last_four?: string }} row
 */
export function maskApiKey(row) {
  const prefix = row?.key_prefix || PUBLISHED_FEED_KEY_PREFIX;
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
 * Redact any `api_key` query value in a string (URLs, log lines, error messages)
 * so a plaintext key never lands in logs/tracing. Also redacts bare `th_pf_…` tokens.
 * @param {string} text
 */
export function redactApiKeyInText(text) {
  if (text == null) return text;
  return String(text)
    .replace(/([?&](?:api_key|apikey|key|token)=)[^&\s"']+/gi, '$1[REDACTED]')
    .replace(/th_pf_[A-Za-z0-9_-]+/g, 'th_pf_[REDACTED]');
}

/** A stored key is revealable only if it carries an encrypted secret. */
export function isRevealableKeyRow(row) {
  return Boolean(row?.secret_ciphertext) && row?.key_type === PUBLISHED_FEED_KEY_TYPE;
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
