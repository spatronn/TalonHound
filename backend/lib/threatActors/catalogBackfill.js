import {
  BUNDLED_IMPORT_OPERATORS,
  CATALOG_SOURCE_BUNDLED,
  CATALOG_SOURCE_BUNDLED_COLLISION,
  CATALOG_SOURCE_LEGACY_SEED,
  CATALOG_SOURCE_MANUAL,
  CATALOG_SOURCE_SYSTEM,
  LEGACY_SEED_ACTOR_IDS,
  normalizeCatalogSources
} from './catalogSources.js';
import { isUnknownSentinelActor } from './normalization.js';
import { DEFAULT_BUNDLED_SNAPSHOT_PATH, loadBundledSnapshot } from './snapshot.js';

function cleanStoredSources(raw) {
  return normalizeCatalogSources(
    (raw || []).filter((source) => source !== CATALOG_SOURCE_BUNDLED_COLLISION)
  );
}

/**
 * Deterministically infer catalog memberships for one actor row.
 * @param {{ id?: string, name?: string, slug?: string, created_by?: string|null, updated_by?: string|null, catalog_sources?: string[]|null }} row
 * @param {Set<string>} bundledSlugSet
 */
export function inferCatalogSourcesForRow(row, bundledSlugSet) {
  const stored = cleanStoredSources(row?.catalog_sources);
  const createdBy = String(row?.created_by || '').trim();
  const updatedBy = String(row?.updated_by || '').trim();
  const clearlyAdminCreated = Boolean(createdBy) && !BUNDLED_IMPORT_OPERATORS.has(createdBy);
  const inBundledSnapshot = bundledSlugSet.has(String(row?.slug || ''));

  if (isUnknownSentinelActor(row)) return [CATALOG_SOURCE_SYSTEM];
  if (LEGACY_SEED_ACTOR_IDS.has(String(row?.id || ''))) {
    return [CATALOG_SOURCE_LEGACY_SEED, CATALOG_SOURCE_BUNDLED];
  }

  if (BUNDLED_IMPORT_OPERATORS.has(createdBy) || BUNDLED_IMPORT_OPERATORS.has(updatedBy)) {
    if (clearlyAdminCreated && stored.includes(CATALOG_SOURCE_MANUAL) && !stored.includes(CATALOG_SOURCE_BUNDLED)) {
      return [CATALOG_SOURCE_MANUAL];
    }
    return [CATALOG_SOURCE_BUNDLED];
  }

  if (inBundledSnapshot && !clearlyAdminCreated) {
    return [CATALOG_SOURCE_BUNDLED];
  }

  if (clearlyAdminCreated || stored.includes(CATALOG_SOURCE_MANUAL)) {
    if (stored.includes(CATALOG_SOURCE_BUNDLED)) {
      return [CATALOG_SOURCE_MANUAL, CATALOG_SOURCE_BUNDLED];
    }
    return [CATALOG_SOURCE_MANUAL];
  }

  if (stored.length) return stored;
  return [];
}

export function resolveStoredCollisionPending(row) {
  if (row?.bundled_catalog_collision_pending === true) return true;
  return Array.isArray(row?.catalog_sources)
    && row.catalog_sources.includes(CATALOG_SOURCE_BUNDLED_COLLISION);
}

/**
 * Backfill catalog_sources from bundled snapshot membership and known legacy rules.
 */
export async function backfillThreatActorCatalogSources(client, {
  snapshotPath = DEFAULT_BUNDLED_SNAPSHOT_PATH,
  dryRun = false,
  operator = 'bundled-seed'
} = {}) {
  const bundled = await loadBundledSnapshot(snapshotPath);
  const bundledSlugSet = new Set(bundled.records.map((record) => record.slug));
  const { rows } = await client.query('SELECT * FROM threat_actors ORDER BY name ASC');

  let updated = 0;
  for (const row of rows) {
    const nextSources = inferCatalogSourcesForRow(row, bundledSlugSet);
    const prevSources = cleanStoredSources(row.catalog_sources);
    const prevPending = resolveStoredCollisionPending(row);
    const hadLegacyMarker = Array.isArray(row.catalog_sources)
      && row.catalog_sources.includes(CATALOG_SOURCE_BUNDLED_COLLISION);
    const nextPending = prevPending || hadLegacyMarker;

    const sourcesChanged = JSON.stringify(prevSources) !== JSON.stringify(nextSources);
    const pendingChanged = Boolean(row.bundled_catalog_collision_pending) !== nextPending;
    if (!sourcesChanged && !pendingChanged) continue;

    if (!dryRun) {
      await client.query(
        `UPDATE threat_actors
         SET catalog_sources = $2,
             bundled_catalog_collision_pending = $3,
             updated_by = $4,
             updated_at = NOW()
         WHERE id = $1::uuid`,
        [row.id, nextSources.length ? nextSources : null, nextPending, operator]
      );
    }
    updated += 1;
  }

  return {
    total: rows.length,
    updated,
    bundledSnapshotCount: bundledSlugSet.size
  };
}

const VALID_SOURCE_SET = new Set([
  CATALOG_SOURCE_MANUAL,
  CATALOG_SOURCE_BUNDLED,
  CATALOG_SOURCE_LEGACY_SEED,
  CATALOG_SOURCE_SYSTEM
]);

/**
 * Summarize provenance distribution for validation reporting.
 * @param {Array<{ catalog_sources?: string[]|null, bundled_catalog_collision_pending?: boolean, slug?: string, active?: boolean }>} rows
 */
export function summarizeThreatActorProvenance(rows = []) {
  const summary = {
    total: rows.length,
    bundledOnly: 0,
    manualOnly: 0,
    manualAndBundled: 0,
    legacySeedBundled: 0,
    pendingCollisions: 0,
    unknown: 0,
    unclassified: 0,
    invalidSources: 0
  };

  for (const row of rows) {
    const sources = cleanStoredSources(row.catalog_sources);
    const pending = resolveStoredCollisionPending(row);
    const hasManual = sources.includes(CATALOG_SOURCE_MANUAL);
    const hasBundled = sources.includes(CATALOG_SOURCE_BUNDLED);
    const hasLegacy = sources.includes(CATALOG_SOURCE_LEGACY_SEED);
    const hasSystem = sources.includes(CATALOG_SOURCE_SYSTEM);

    if (sources.some((source) => !VALID_SOURCE_SET.has(source))) summary.invalidSources += 1;
    if (pending) summary.pendingCollisions += 1;
    if (hasSystem || row.slug === 'unknown') {
      summary.unknown += 1;
      continue;
    }
    if (!sources.length) {
      summary.unclassified += 1;
      continue;
    }
    if (hasLegacy && hasBundled) summary.legacySeedBundled += 1;
    if (hasManual && hasBundled) summary.manualAndBundled += 1;
    else if (hasManual) summary.manualOnly += 1;
    else if (hasBundled) summary.bundledOnly += 1;
  }

  return summary;
}
