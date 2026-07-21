export const TAG_CATEGORIES = Object.freeze([
  'behavior',
  'campaign',
  'theme',
  'targeting',
  'source-context',
  'review-state',
  'vulnerability',
  'custom'
]);

/** Legacy categories kept for display of inactive migrated tags. */
export const LEGACY_TAG_CATEGORIES = Object.freeze([
  'malware',
  'actor',
  'source'
]);

export const MAX_TAG_NAME_LENGTH = 100;

const LEGACY_TAG_TYPES = new Set(['threat', 'actor', 'technique', 'context']);

/**
 * Canonical tag name normalization used by all create/assign/ingest paths.
 * Does not convert -, _, or space into each other.
 */
export function normalizeTagName(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

/**
 * @returns {{ ok: true, name: string } | { ok: false, error: 'empty' | 'too_long' }}
 */
export function parseNormalizedTagName(value) {
  const name = normalizeTagName(value);
  if (!name) return { ok: false, error: 'empty' };
  if (name.length > MAX_TAG_NAME_LENGTH) return { ok: false, error: 'too_long' };
  return { ok: true, name };
}

export function normalizeTagSlug(value) {
  return normalizeTagName(value).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

export function categoryToLegacyType(category) {
  const c = String(category || '').trim().toLowerCase();
  if (c === 'behavior') return 'technique';
  if (c === 'campaign') return 'threat';
  return 'context';
}

export function legacyTypeToCategory(type) {
  const t = String(type || '').trim().toLowerCase();
  if (t === 'actor') return 'custom';
  if (t === 'technique') return 'behavior';
  if (t === 'threat') return 'campaign';
  return 'custom';
}

export function isValidCategory(value) {
  return TAG_CATEGORIES.includes(String(value || '').trim().toLowerCase());
}

export function isValidLegacyType(value) {
  return LEGACY_TAG_TYPES.has(String(value || '').trim().toLowerCase());
}

export function parsePositiveInt(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) return null;
  return n;
}

export function parseTagListLimit(value, defaultLimit = 5, maxLimit = 50) {
  const parsed = parsePositiveInt(value);
  if (!parsed) return defaultLimit;
  return Math.min(parsed, maxLimit);
}

export function normalizeTagSearch(value) {
  return String(value || '').trim().slice(0, 100);
}

export function parseExcludeTagIds(value) {
  if (value == null || value === '') return [];
  const raw = Array.isArray(value) ? value : String(value).split(',');
  const ids = raw.map((part) => parsePositiveInt(part)).filter(Boolean);
  return [...new Set(ids)];
}

export function toPublicTag(row, { sources = null } = {}) {
  if (!row) return null;
  const tag = {
    id: Number(row.id),
    name: row.name,
    slug: row.slug || row.name,
    description: row.description || null,
    color: row.color || null,
    category: row.category || legacyTypeToCategory(row.type),
    type: row.type,
    is_active: Boolean(row.enabled),
    enabled: Boolean(row.enabled),
    created_origin: row.created_origin || 'manual',
    created_at: row.created_at,
    updated_at: row.updated_at || row.created_at
  };
  if (sources != null) tag.sources = sources;
  return tag;
}

export function tagAuditSnapshot(row) {
  return toPublicTag(row);
}

/** Format Tag Manager Source cell labels (Manual first, then feed names sorted). */
export function formatTagSourceLabels(sources = []) {
  const list = Array.isArray(sources) ? sources.filter(Boolean).map(String) : [];
  const hasManual = list.some((s) => s === 'Manual');
  const feeds = [...new Set(list.filter((s) => s !== 'Manual'))].sort((a, b) => a.localeCompare(b));
  const out = [];
  if (hasManual) out.push('Manual');
  out.push(...feeds);
  return out;
}
