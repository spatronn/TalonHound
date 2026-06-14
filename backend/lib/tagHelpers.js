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

const LEGACY_TAG_TYPES = new Set(['threat', 'actor', 'technique', 'context']);

export function normalizeTagName(value) {
  return String(value || '').trim().toLowerCase();
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

export function toPublicTag(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    name: row.name,
    slug: row.slug || row.name,
    description: row.description || null,
    color: row.color || null,
    category: row.category || legacyTypeToCategory(row.type),
    type: row.type,
    is_active: Boolean(row.enabled),
    enabled: Boolean(row.enabled),
    created_at: row.created_at,
    updated_at: row.updated_at || row.created_at
  };
}

export function tagAuditSnapshot(row) {
  return toPublicTag(row);
}
