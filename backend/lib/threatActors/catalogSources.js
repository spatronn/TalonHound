import { LEGACY_CANONICAL_MATCHES, isUnknownSentinelActor } from './normalization.js';

export const CATALOG_SOURCE_MANUAL = 'manual';
export const CATALOG_SOURCE_BUNDLED = 'bundled';
export const CATALOG_SOURCE_LEGACY_SEED = 'legacy-seed';
export const CATALOG_SOURCE_SYSTEM = 'system';
/** Legacy marker migrated to bundled_catalog_collision_pending; not a real membership. */
export const CATALOG_SOURCE_BUNDLED_COLLISION = 'bundled-collision';

export const LEGACY_SEED_ACTOR_IDS = Object.freeze(new Set([
  '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
  '92e08e97-5e84-4d29-920f-df0428d35dc7',
  '364117ec-9e72-4531-956a-ba7f013f1b45'
]));

export const BUNDLED_IMPORT_OPERATORS = Object.freeze(new Set([
  'bundled-seed',
  'malpedia-bootstrap',
  'system-seed'
]));

const SOURCE_ORDER = Object.freeze([
  CATALOG_SOURCE_SYSTEM,
  CATALOG_SOURCE_LEGACY_SEED,
  CATALOG_SOURCE_MANUAL,
  CATALOG_SOURCE_BUNDLED
]);

export function normalizeCatalogSources(raw) {
  const values = Array.isArray(raw) ? raw : [];
  const seen = new Set();
  const normalized = [];
  for (const value of values) {
    const trimmed = String(value || '').trim();
    if (!trimmed || trimmed === CATALOG_SOURCE_BUNDLED_COLLISION) continue;
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    normalized.push(trimmed);
  }
  normalized.sort((a, b) => {
    const ai = SOURCE_ORDER.indexOf(a);
    const bi = SOURCE_ORDER.indexOf(b);
    return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi) || a.localeCompare(b);
  });
  return normalized;
}

export function resolveCatalogSources(row) {
  const stored = normalizeCatalogSources(row?.catalog_sources);
  if (stored.length) return stored;

  if (isUnknownSentinelActor(row)) return [CATALOG_SOURCE_SYSTEM];
  if (LEGACY_SEED_ACTOR_IDS.has(String(row?.id || ''))) {
    return [CATALOG_SOURCE_LEGACY_SEED, CATALOG_SOURCE_BUNDLED];
  }
  const createdBy = String(row?.created_by || '').trim();
  const updatedBy = String(row?.updated_by || '').trim();
  if (BUNDLED_IMPORT_OPERATORS.has(createdBy) || BUNDLED_IMPORT_OPERATORS.has(updatedBy)) {
    return [CATALOG_SOURCE_BUNDLED];
  }
  if (createdBy) return [CATALOG_SOURCE_MANUAL];
  return [];
}

export function hasCatalogSource(row, source) {
  return resolveCatalogSources(row).includes(source);
}

export function isLegacyCanonicalReviewedMatch(record) {
  return Boolean(LEGACY_CANONICAL_MATCHES[String(record?.canonicalName || '').toLowerCase()]);
}

export function isCatalogBundledEquivalent(existing, record) {
  const sources = resolveCatalogSources(existing);
  if (sources.includes(CATALOG_SOURCE_BUNDLED) || sources.includes(CATALOG_SOURCE_LEGACY_SEED)) {
    return true;
  }
  return isLegacyCanonicalReviewedMatch(record);
}

export function isManualOnlyActor(existing) {
  if (existing?.bundled_catalog_collision_pending === true) return true;
  if (Array.isArray(existing?.catalog_sources) && existing.catalog_sources.includes(CATALOG_SOURCE_BUNDLED_COLLISION)) {
    return true;
  }
  const sources = resolveCatalogSources(existing);
  return sources.includes(CATALOG_SOURCE_MANUAL)
    && !sources.includes(CATALOG_SOURCE_BUNDLED)
    && !sources.includes(CATALOG_SOURCE_LEGACY_SEED);
}

export function mergeCatalogSources(existingSources = [], additions = []) {
  return normalizeCatalogSources([...(existingSources || []), ...(additions || [])]);
}

export function confirmBundledCatalogEquivalence(existingSources = []) {
  return mergeCatalogSources(existingSources, [CATALOG_SOURCE_BUNDLED]);
}

export function canConfirmBundledCatalogIdentity(row) {
  if (isUnknownSentinelActor(row)) {
    return { ok: false, reason: 'unknown_sentinel' };
  }
  const sources = resolveCatalogSources(row);
  if (!row?.bundled_catalog_collision_pending) {
    if (sources.includes(CATALOG_SOURCE_BUNDLED)) {
      return { ok: false, reason: 'already_confirmed' };
    }
    return { ok: false, reason: 'no_pending_collision' };
  }
  return { ok: true };
}

export function resolveReconciledActiveState(existing, incomingActive = true) {
  if (existing?.active === false) return false;
  if (existing?.active === true) return true;
  return incomingActive !== false;
}

export function buildManualBundledCollision(existing, record) {
  return {
    type: 'manual_bundled_canonical_collision',
    existingId: existing.id,
    existingName: existing.name,
    existingSlug: existing.slug,
    bundledCanonicalName: record.canonicalName,
    bundledSlug: record.slug
  };
}
