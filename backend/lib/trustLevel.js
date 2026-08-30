/**
 * Canonical integration-feed trust levels.
 * Persisted in integration_feeds.trust_level and enforced by DB CHECK + API validation.
 */

export const TRUST_LEVEL_TRUSTED = 'trusted';
export const TRUST_LEVEL_MEDIUM = 'medium';
export const TRUST_LEVEL_NOT_CATEGORIZED = 'not_categorized';

/** @type {ReadonlySet<string>} */
export const TRUST_LEVELS = Object.freeze(new Set([
  TRUST_LEVEL_TRUSTED,
  TRUST_LEVEL_MEDIUM,
  TRUST_LEVEL_NOT_CATEGORIZED
]));

/** @type {readonly string[]} */
export const TRUST_LEVEL_VALUES = Object.freeze([
  TRUST_LEVEL_TRUSTED,
  TRUST_LEVEL_MEDIUM,
  TRUST_LEVEL_NOT_CATEGORIZED
]);

export function isValidTrustLevel(value) {
  return TRUST_LEVELS.has(String(value || '').trim());
}
