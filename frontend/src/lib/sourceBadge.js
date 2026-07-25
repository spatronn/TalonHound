/**
 * Shared source badge color resolution.
 *
 * Managed colors are stored per source as a #rrggbb hex on the backend. This
 * module turns a resolved background hex into a full, readable badge style
 * (background + luminance-aware text + derived border) and provides a lookup
 * index keyed by source name so every screen paints the same source the same
 * way. There is no source-name -> color mapping baked in here: unknown sources
 * fall back to a single neutral default.
 */

const HEX_PATTERN = /^#[0-9a-fA-F]{6}$/;

/** Common fallback when a source has no managed color. Mirrors backend DEFAULT_SOURCE_COLOR. */
export const DEFAULT_SOURCE_COLOR = '#475569';

/** @param {unknown} value */
export function isValidHexColor(value) {
  return typeof value === 'string' && HEX_PATTERN.test(value.trim());
}

/**
 * @param {unknown} value
 * @returns {string|null} lowercased #rrggbb or null when invalid/empty
 */
export function normalizeHexColor(value) {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  return HEX_PATTERN.test(s) ? s.toLowerCase() : null;
}

/** @param {string} hex #rrggbb */
function toRgb(hex) {
  const s = hex.replace('#', '');
  return {
    r: parseInt(s.slice(0, 2), 16),
    g: parseInt(s.slice(2, 4), 16),
    b: parseInt(s.slice(4, 6), 16)
  };
}

function channelToLinear(c) {
  const v = c / 255;
  return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
}

/**
 * WCAG relative luminance (0 = black, 1 = white).
 * @param {string} hex
 */
export function relativeLuminance(hex) {
  const norm = normalizeHexColor(hex) || DEFAULT_SOURCE_COLOR;
  const { r, g, b } = toRgb(norm);
  return 0.2126 * channelToLinear(r) + 0.7152 * channelToLinear(g) + 0.0722 * channelToLinear(b);
}

/**
 * Pick a readable text color for a given background.
 * @param {string} hex background hex
 * @returns {string} dark or light text hex
 */
export function readableTextColor(hex) {
  return relativeLuminance(hex) > 0.4 ? '#0b1220' : '#f8fafc';
}

/**
 * Blend a hex toward black (amount<0) or white (amount>0).
 * @param {string} hex
 * @param {number} amount -1..1
 */
export function shadeHexColor(hex, amount) {
  const norm = normalizeHexColor(hex) || DEFAULT_SOURCE_COLOR;
  const { r, g, b } = toRgb(norm);
  const target = amount < 0 ? 0 : 255;
  const t = Math.min(Math.abs(amount), 1);
  const mix = (c) => Math.round(c + (target - c) * t);
  const toHex = (c) => c.toString(16).padStart(2, '0');
  return `#${toHex(mix(r))}${toHex(mix(g))}${toHex(mix(b))}`;
}

/**
 * Full inline badge style for a given background hex.
 * Border is a slightly darker/lighter tone of the background so it stays
 * coordinated with whatever color the operator picked.
 * @param {string} hex
 */
export function sourceBadgeStyle(hex) {
  const bg = normalizeHexColor(hex) || DEFAULT_SOURCE_COLOR;
  const border = relativeLuminance(bg) > 0.4 ? shadeHexColor(bg, -0.25) : shadeHexColor(bg, 0.25);
  return {
    background: bg,
    color: readableTextColor(bg),
    border: `1px solid ${border}`
  };
}

/** @param {string} name */
function normalizeName(name) {
  return String(name == null ? '' : name).trim().toLowerCase();
}

/**
 * Precedence for conflicting names: a feed color wins over a source color when
 * the same display name exists in both catalogs. Lower number wins.
 * @param {string|undefined} type
 */
function typePriority(type) {
  return type === 'feed' ? 0 : 1;
}

/**
 * Build a lookup index from a source-color catalog.
 *
 * Deterministic even if the backend returns rows in an arbitrary order: for a
 * given name a feed entry always beats a source entry, and among equal-priority
 * entries the first one wins (the backend also orders deterministically, so the
 * "first" is stable across requests).
 *
 * @param {Array<{ name?: string, color?: string, type?: string }>} entries
 * @returns {Map<string, string>} normalized name -> normalized color
 */
export function buildSourceColorIndex(entries) {
  const index = new Map();
  const priorities = new Map();
  for (const entry of entries || []) {
    const key = normalizeName(entry?.name);
    const color = normalizeHexColor(entry?.color);
    if (!key || !color) continue;
    const priority = typePriority(entry?.type);
    if (!index.has(key)) {
      index.set(key, color);
      priorities.set(key, priority);
    } else if (priority < priorities.get(key)) {
      // A higher-precedence entry (feed) overrides a source seen earlier.
      index.set(key, color);
      priorities.set(key, priority);
    }
  }
  return index;
}

/**
 * Resolve a managed color for a label, or null when unknown.
 * @param {Map<string, string>|null|undefined} index
 * @param {string} label
 */
export function resolveSourceColor(index, label) {
  if (!index || typeof index.get !== 'function') return null;
  return index.get(normalizeName(label)) || null;
}

/**
 * Resolve a full badge style for a label using the catalog, falling back to the
 * neutral default when the source has no managed color.
 * @param {Map<string, string>|null|undefined} index
 * @param {string} label
 */
export function resolveSourceBadgeStyle(index, label) {
  return sourceBadgeStyle(resolveSourceColor(index, label) || DEFAULT_SOURCE_COLOR);
}
