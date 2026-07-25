/**
 * Shared validation for managed source badge colors.
 * Colors are persisted as lowercase 7-char hex strings (#rrggbb). The frontend
 * derives readable text + border tones from this single value.
 */

const HEX_COLOR_PATTERN = /^#[0-9a-fA-F]{6}$/;

/**
 * Common default color for freshly created sources/feeds that have no explicit
 * color yet. Kept in sync with the frontend fallback (lib/sourceBadge.js).
 */
export const DEFAULT_SOURCE_COLOR = '#475569';

/**
 * Normalize + validate a hex color.
 *
 * Empty string / null / undefined are treated as "clear the color" and resolve
 * to `{ ok: true, value: null }`, so blank input falls back to the default.
 *
 * @param {unknown} raw
 * @returns {{ ok: true, value: string|null } | { ok: false, error: string }}
 */
export function validateHexColor(raw) {
  if (raw == null) return { ok: true, value: null };
  const s = String(raw).trim();
  if (s === '') return { ok: true, value: null };
  if (!HEX_COLOR_PATTERN.test(s)) {
    return { ok: false, error: 'color must be a hex value in #rrggbb format' };
  }
  return { ok: true, value: s.toLowerCase() };
}

/** @param {unknown} raw */
export function isValidHexColor(raw) {
  return typeof raw === 'string' && HEX_COLOR_PATTERN.test(raw.trim());
}
