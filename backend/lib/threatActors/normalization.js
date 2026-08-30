import { MAX_TAG_NAME_LENGTH, normalizeTagSlug } from '../tagHelpers.js';

export const LEGACY_SEED_DESCRIPTION = 'Legacy tag migration seed';
export const UNKNOWN_SENTINEL_NAME = 'unknown';
export const UNKNOWN_SENTINEL_SLUG = 'unknown';

/** Malpedia canonical names that map to legacy TalonHound seed rows by slug/name. */
export const LEGACY_CANONICAL_MATCHES = Object.freeze({
  'lazarus group': Object.freeze({ slug: 'lazarus', name: 'Lazarus' })
});

export function trimThreatActorText(value) {
  return String(value || '').trim();
}

export function validateThreatActorName(name) {
  const trimmed = trimThreatActorText(name);
  if (!trimmed) return { ok: false, reason: 'empty_name' };
  if (trimmed.length > MAX_TAG_NAME_LENGTH) return { ok: false, reason: 'name_too_long' };
  return { ok: true, name: trimmed };
}

export function normalizeThreatActorSlug(name) {
  return normalizeTagSlug(name);
}

/**
 * @param {string} canonicalName
 * @param {string[]} existingAliases
 * @param {string[]} incomingAliases
 * @returns {string[]}
 */
export function mergeThreatActorAliases(canonicalName, existingAliases = [], incomingAliases = []) {
  const canonicalLower = trimThreatActorText(canonicalName).toLowerCase();
  const seen = new Set();
  const merged = [];

  const add = (raw) => {
    const trimmed = trimThreatActorText(raw);
    if (!trimmed) return;
    if (trimmed.length > MAX_TAG_NAME_LENGTH) return;
    if (trimmed.toLowerCase() === canonicalLower) return;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    merged.push(trimmed);
  };

  for (const alias of existingAliases || []) add(alias);
  for (const alias of incomingAliases || []) add(alias);
  return merged;
}

export function mergeThreatActorDescription(existingDescription, incomingDescription) {
  const incoming = trimThreatActorText(incomingDescription);
  const existing = trimThreatActorText(existingDescription);
  if (!incoming) return existing || null;
  if (!existing || existing === LEGACY_SEED_DESCRIPTION) return incoming;
  return existing;
}

function normalizeAliasKeys(aliases = []) {
  return [...aliases]
    .map((alias) => trimThreatActorText(alias).toLowerCase())
    .filter(Boolean)
    .sort();
}

export function threatActorAliasesEqual(existingAliases = [], nextAliases = []) {
  const left = normalizeAliasKeys(existingAliases);
  const right = normalizeAliasKeys(nextAliases);
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function threatActorUpdateIsNoOp(existing, update) {
  const existingActive = existing?.active !== false;
  const nextActive = update?.active !== false;
  const existingDescription = trimThreatActorText(existing?.description) || null;
  const nextDescription = trimThreatActorText(update?.description) || null;

  return (
    String(existing?.name || '') === String(update?.name || '')
    && String(existing?.slug || '') === String(update?.slug || '')
    && existingActive === nextActive
    && existingDescription === nextDescription
    && threatActorAliasesEqual(existing?.aliases, update?.aliases)
  );
}

export function isUnknownSentinelActor(row) {
  const name = String(row?.name || '').trim().toLowerCase();
  const slug = String(row?.slug || '').trim().toLowerCase();
  return name === UNKNOWN_SENTINEL_NAME || slug === UNKNOWN_SENTINEL_SLUG;
}

export function resolveUpdatedPrimaryName(existing, record) {
  if (isUnknownSentinelActor(existing)) return existing.name;
  const legacy = LEGACY_CANONICAL_MATCHES[record.canonicalName.toLowerCase()];
  if (legacy) return existing.name;
  return existing.name;
}

export function resolveUpdatedSlug(existing, record) {
  if (isUnknownSentinelActor(existing)) return existing.slug;
  const legacy = LEGACY_CANONICAL_MATCHES[record.canonicalName.toLowerCase()];
  if (legacy) return existing.slug;
  return existing.slug;
}

/**
 * @param {Array<{ canonicalName: string, slug: string, aliases: string[], description: string|null, active?: boolean }>} records
 */
export function validateNormalizedActorRecords(records) {
  const nameKeys = new Set();
  const slugs = new Set();
  const conflicts = [];

  for (const record of records) {
    const nameKey = record.canonicalName.toLowerCase();
    if (nameKeys.has(nameKey)) {
      conflicts.push({ type: 'duplicate_name', name: record.canonicalName, slug: record.slug });
    }
    nameKeys.add(nameKey);

    if (slugs.has(record.slug)) {
      conflicts.push({ type: 'duplicate_slug', name: record.canonicalName, slug: record.slug });
    }
    slugs.add(record.slug);
  }

  return {
    ok: conflicts.length === 0,
    conflicts,
    actorCount: records.length
  };
}

/**
 * Convert normalized records to bundled snapshot actor rows (deterministic ordering).
 * @param {Array<{ canonicalName: string, slug: string, aliases: string[], description: string|null, active?: boolean }>} records
 */
export function recordsToSnapshotActors(records) {
  return [...records]
    .sort((a, b) => a.slug.localeCompare(b.slug) || a.canonicalName.localeCompare(b.canonicalName))
    .map((record) => ({
      name: record.canonicalName,
      slug: record.slug,
      aliases: [...(record.aliases || [])],
      description: record.description || null,
      active: record.active !== false
    }));
}

/**
 * @param {Array<{ name: string, slug: string, aliases?: string[], description?: string|null, active?: boolean }>} actors
 */
export function snapshotActorsToRecords(actors) {
  return actors.map((actor) => ({
    canonicalName: actor.name,
    slug: actor.slug,
    aliases: Array.isArray(actor.aliases) ? actor.aliases : [],
    description: actor.description || null,
    active: actor.active !== false
  }));
}
