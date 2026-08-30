import {
  LEGACY_CANONICAL_MATCHES,
  isUnknownSentinelActor,
  mergeThreatActorAliases,
  mergeThreatActorDescription,
  resolveUpdatedPrimaryName,
  resolveUpdatedSlug,
  threatActorUpdateIsNoOp
} from './normalization.js';
import {
  CATALOG_SOURCE_BUNDLED,
  buildManualBundledCollision,
  isCatalogBundledEquivalent,
  isManualOnlyActor,
  mergeCatalogSources,
  resolveCatalogSources,
  resolveReconciledActiveState
} from './catalogSources.js';

export const IMPORT_OPERATOR_MALPEDIA = 'malpedia-bootstrap';
export const IMPORT_OPERATOR_BUNDLED = 'bundled-seed';

const INSERT_BATCH_SIZE = 100;
const UPDATE_BATCH_SIZE = 100;

export function buildExistingActorIndex(existingRows = []) {
  const byNameLower = new Map();
  const bySlug = new Map();
  for (const row of existingRows) {
    if (!row?.id) continue;
    byNameLower.set(String(row.name || '').toLowerCase(), row);
    if (row.slug) bySlug.set(String(row.slug), row);
  }
  return { byNameLower, bySlug, rows: existingRows };
}

export function findExistingActorMatch(record, index) {
  const nameKey = record.canonicalName.toLowerCase();
  if (index.byNameLower.has(nameKey)) return index.byNameLower.get(nameKey);
  if (index.bySlug.has(record.slug)) return index.bySlug.get(record.slug);

  const legacy = LEGACY_CANONICAL_MATCHES[nameKey];
  if (legacy?.slug && index.bySlug.has(legacy.slug)) return index.bySlug.get(legacy.slug);
  if (legacy?.name && index.byNameLower.has(legacy.name.toLowerCase())) {
    return index.byNameLower.get(legacy.name.toLowerCase());
  }
  return null;
}

/**
 * @param {Array<{ canonicalName: string, slug: string, aliases: string[], description: string|null, active?: boolean }>} sourceRecords
 * @param {Array<{ id: string, name: string, slug: string, aliases?: string[]|null, description?: string|null, active?: boolean }>} existingRows
 */
export function buildThreatActorImportPlan(sourceRecords, existingRows = []) {
  const index = buildExistingActorIndex(existingRows);
  const matchedIds = new Set();

  const plan = {
    fetched: sourceRecords.length,
    valid: sourceRecords.length,
    inserts: [],
    updates: [],
    catalogSourceUpdates: [],
    collisionPendingUpdates: [],
    skippedInvalid: 0,
    skippedUnknownSentinel: 0,
    aliasAdditions: 0,
    conflicts: [],
    manualCanonicalCollisions: [],
    preserved: {
      unknown: null,
      lazarus: null,
      apt28: null,
      apt29: null
    }
  };

  for (const record of sourceRecords) {
    const existing = findExistingActorMatch(record, index);
    if (!existing) {
      plan.inserts.push({
        name: record.canonicalName,
        slug: record.slug,
        aliases: record.aliases,
        description: record.description,
        active: record.active !== false,
        catalog_sources: [CATALOG_SOURCE_BUNDLED]
      });
      continue;
    }

    if (matchedIds.has(existing.id)) {
      plan.conflicts.push({
        type: 'duplicate_match',
        canonicalName: record.canonicalName,
        existingId: existing.id,
        existingName: existing.name
      });
      continue;
    }
    matchedIds.add(existing.id);

    if (isUnknownSentinelActor(existing)) {
      plan.skippedUnknownSentinel += 1;
      plan.preserved.unknown = { id: existing.id, name: existing.name, action: 'preserved' };
      continue;
    }

    if (isManualOnlyActor(existing) && !isCatalogBundledEquivalent(existing, record)) {
      const collision = buildManualBundledCollision(existing, record);
      plan.manualCanonicalCollisions.push(collision);
      if (!existing.bundled_catalog_collision_pending
        && !(existing.catalog_sources || []).includes('bundled-collision')) {
        plan.collisionPendingUpdates.push({ id: existing.id, bundled_catalog_collision_pending: true });
      }
      continue;
    }

    const mergedAliases = mergeThreatActorAliases(
      resolveUpdatedPrimaryName(existing, record),
      existing.aliases || [],
      record.aliases
    );
    const aliasAdditions = mergedAliases.filter(
      (alias) => !(existing.aliases || []).some((prev) => prev.toLowerCase() === alias.toLowerCase())
    ).length;

    const update = {
      id: existing.id,
      name: resolveUpdatedPrimaryName(existing, record),
      slug: resolveUpdatedSlug(existing, record),
      aliases: mergedAliases,
      description: mergeThreatActorDescription(existing.description, record.description),
      active: resolveReconciledActiveState(existing, record.active),
      aliasAdditions,
      malpediaCanonical: record.canonicalName,
      catalog_sources: mergeCatalogSources(resolveCatalogSources(existing), [CATALOG_SOURCE_BUNDLED])
    };

    const lowerName = String(existing.name || '').toLowerCase();
    if (lowerName === 'apt28') plan.preserved.apt28 = { id: existing.id, name: update.name, aliases: update.aliases.length };
    if (lowerName === 'apt29') plan.preserved.apt29 = { id: existing.id, name: update.name, aliases: update.aliases.length };
    if (existing.slug === 'lazarus' || lowerName === 'lazarus') {
      plan.preserved.lazarus = {
        id: existing.id,
        name: update.name,
        malpediaCanonical: record.canonicalName,
        decision: 'preserve_primary_name_and_slug'
      };
    }

    if (threatActorUpdateIsNoOp(existing, update)) {
      continue;
    }

    plan.updates.push(update);
    plan.aliasAdditions += aliasAdditions;
  }

  return plan;
}

export function summarizeImportPlan(plan) {
  return {
    malpediaActorsFetched: plan.fetched,
    validActors: plan.valid,
    newActors: plan.inserts.length,
    existingExactMatches: plan.updates.length,
    existingActorsEnriched: plan.updates.filter((u) => u.aliasAdditions > 0 || u.description).length,
    aliasAdditions: plan.aliasAdditions,
    skippedInvalidRecords: plan.skippedInvalid,
    potentialConflicts: plan.conflicts.length,
    skippedUnknownSentinel: plan.skippedUnknownSentinel,
    manualCanonicalCollisions: plan.manualCanonicalCollisions?.length || 0,
    catalogSourceUpdates: plan.catalogSourceUpdates?.length || 0,
    collisionPendingUpdates: plan.collisionPendingUpdates?.length || 0
  };
}

export function printImportSummary(plan, { dryRun, sourceLabel = 'Malpedia' } = {}) {
  const summary = summarizeImportPlan(plan);
  console.log(`${sourceLabel} actors fetched:  ${summary.malpediaActorsFetched}`);
  console.log(`Valid actors:              ${summary.validActors}`);
  console.log(`New actors:                ${summary.newActors}`);
  console.log(`Existing exact matches:    ${summary.existingExactMatches}`);
  console.log(`Existing actors enriched:  ${summary.existingActorsEnriched}`);
  console.log(`Alias additions:           ${summary.aliasAdditions}`);
  console.log(`Skipped invalid records:   ${summary.skippedInvalidRecords}`);
  console.log(`Potential conflicts:       ${summary.potentialConflicts}`);
  if (summary.skippedUnknownSentinel) {
    console.log(`Unknown sentinel preserved: ${summary.skippedUnknownSentinel}`);
  }
  if (summary.manualCanonicalCollisions) {
    console.log(`Manual/bundled collisions:     ${summary.manualCanonicalCollisions}`);
  }
  if (plan.manualCanonicalCollisions?.length) {
    console.log('\nManual/bundled collisions requiring review:');
    for (const collision of plan.manualCanonicalCollisions.slice(0, 20)) {
      console.log(`  - ${collision.existingName} (${collision.existingSlug})`);
    }
    if (plan.manualCanonicalCollisions.length > 20) {
      console.log(`  ... and ${plan.manualCanonicalCollisions.length - 20} more`);
    }
  }
  if (plan.preserved.lazarus) {
    console.log(`Lazarus decision: preserve ID ${plan.preserved.lazarus.id}, primary name "${plan.preserved.lazarus.name}" (Malpedia canonical "${plan.preserved.lazarus.malpediaCanonical}")`);
  }
  if (plan.conflicts.length) {
    console.log('\nConflicts:');
    for (const conflict of plan.conflicts.slice(0, 20)) {
      console.log(`  - ${conflict.type}: ${conflict.canonicalName} -> ${conflict.existingName} (${conflict.existingId})`);
    }
    if (plan.conflicts.length > 20) {
      console.log(`  ... and ${plan.conflicts.length - 20} more`);
    }
  }
  console.log(`\nDatabase changes: ${dryRun ? 'NONE (--dry-run)' : 'APPLIED (--apply)'}`);
}

export async function applyThreatActorImportPlan(
  client,
  plan,
  { operator = IMPORT_OPERATOR_MALPEDIA } = {}
) {
  let inserted = 0;
  let updated = 0;
  let catalogSourcesUpdated = 0;
  let collisionPendingUpdated = 0;

  await client.query('BEGIN');
  try {
    for (let i = 0; i < plan.inserts.length; i += INSERT_BATCH_SIZE) {
      const batch = plan.inserts.slice(i, i + INSERT_BATCH_SIZE);
      for (const row of batch) {
        await client.query(
          `INSERT INTO threat_actors (name, slug, aliases, description, active, catalog_sources, created_by, updated_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
          [
            row.name,
            row.slug,
            Array.isArray(row.aliases) ? row.aliases : [],
            row.description,
            row.active !== false,
            Array.isArray(row.catalog_sources) ? row.catalog_sources : [CATALOG_SOURCE_BUNDLED],
            operator
          ]
        );
        inserted += 1;
      }
    }

    for (let i = 0; i < plan.updates.length; i += UPDATE_BATCH_SIZE) {
      const batch = plan.updates.slice(i, i + UPDATE_BATCH_SIZE);
      for (const row of batch) {
        await client.query(
          `UPDATE threat_actors
           SET name = $2,
               slug = $3,
               aliases = $4,
               description = $5,
               active = $6,
               catalog_sources = $7,
               updated_by = $8,
               updated_at = NOW()
           WHERE id = $1::uuid`,
          [
            row.id,
            row.name,
            row.slug,
            Array.isArray(row.aliases) ? row.aliases : [],
            row.description,
            row.active !== false,
            Array.isArray(row.catalog_sources) ? row.catalog_sources : null,
            operator
          ]
        );
        updated += 1;
      }
    }

    for (const row of plan.catalogSourceUpdates || []) {
      await client.query(
        `UPDATE threat_actors
         SET catalog_sources = $2,
             updated_by = $3,
             updated_at = NOW()
         WHERE id = $1::uuid`,
        [row.id, row.catalog_sources, operator]
      );
      catalogSourcesUpdated += 1;
    }

    for (const row of plan.collisionPendingUpdates || []) {
      await client.query(
        `UPDATE threat_actors
         SET bundled_catalog_collision_pending = $2,
             updated_by = $3,
             updated_at = NOW()
         WHERE id = $1::uuid`,
        [row.id, Boolean(row.bundled_catalog_collision_pending), operator]
      );
      collisionPendingUpdated += 1;
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  }

  return { inserted, updated, catalogSourcesUpdated, collisionPendingUpdated };
}
