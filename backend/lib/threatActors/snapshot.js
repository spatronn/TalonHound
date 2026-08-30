import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  recordsToSnapshotActors,
  snapshotActorsToRecords,
  validateNormalizedActorRecords
} from './normalization.js';

export const SNAPSHOT_SCHEMA_VERSION = 1;
export const BUNDLED_SNAPSHOT_ATTRIBUTION = {
  name: 'malpedia',
  endpoint: 'https://malpedia.caad.fkie.fraunhofer.de/api/get/actors',
  note: 'Threat Actor data is based on the Malpedia catalog and its underlying MISP Galaxy threat-actor dataset.'
};

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
export const DEFAULT_BUNDLED_SNAPSHOT_PATH = path.resolve(moduleDir, '../../seeds/threat-actors.json');

export function resolveBundledSnapshotPath(customPath) {
  if (customPath) return path.resolve(customPath);
  return DEFAULT_BUNDLED_SNAPSHOT_PATH;
}

/**
 * @param {Array<{ canonicalName: string, slug: string, aliases: string[], description: string|null, active?: boolean }>} records
 * @param {{ generatedAt?: string, sourceActorCount?: number }} meta
 */
export function buildBundledSnapshotDocument(records, {
  generatedAt = new Date().toISOString(),
  sourceActorCount = records.length
} = {}) {
  const validation = validateNormalizedActorRecords(records);
  if (!validation.ok) {
    const err = new Error('Snapshot identity validation failed');
    err.code = 'SNAPSHOT_IDENTITY_CONFLICT';
    err.conflicts = validation.conflicts;
    throw err;
  }

  return {
    schema_version: SNAPSHOT_SCHEMA_VERSION,
    source: BUNDLED_SNAPSHOT_ATTRIBUTION,
    generated_at: generatedAt,
    source_actor_count: sourceActorCount,
    actor_count: records.length,
    actors: recordsToSnapshotActors(records)
  };
}

export async function loadBundledSnapshot(filePath = DEFAULT_BUNDLED_SNAPSHOT_PATH) {
  const resolved = resolveBundledSnapshotPath(filePath);
  let raw;
  try {
    raw = JSON.parse(await readFile(resolved, 'utf8'));
  } catch (err) {
    const error = new Error(`Failed to read bundled snapshot: ${resolved}`);
    error.cause = err;
    throw error;
  }

  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.actors)) {
    throw new Error('Invalid bundled snapshot shape: expected { actors: [] }');
  }

  if (raw.actors.length === 0) {
    throw new Error('Bundled snapshot is empty');
  }

  const records = snapshotActorsToRecords(raw.actors);
  for (const record of records) {
    if (!record.canonicalName || !record.slug) {
      throw new Error('Bundled snapshot contains an actor with empty name or slug');
    }
  }

  const validation = validateNormalizedActorRecords(records);
  if (!validation.ok) {
    const err = new Error('Bundled snapshot contains duplicate canonical names or slugs');
    err.code = 'SNAPSHOT_IDENTITY_CONFLICT';
    err.conflicts = validation.conflicts;
    throw err;
  }

  return {
    path: resolved,
    document: raw,
    records
  };
}

export async function writeBundledSnapshot(filePath, records, meta = {}) {
  const document = buildBundledSnapshotDocument(records, meta);
  const resolved = resolveBundledSnapshotPath(filePath);
  await mkdir(path.dirname(resolved), { recursive: true });
  await writeFile(resolved, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  return { path: resolved, document };
}

function indexSnapshotActors(actors) {
  const bySlug = new Map();
  for (const actor of actors) {
    bySlug.set(actor.slug, actor);
  }
  return bySlug;
}

function actorSignature(actor) {
  return JSON.stringify({
    name: actor.name,
    slug: actor.slug,
    aliases: [...(actor.aliases || [])],
    description: actor.description || null,
    active: actor.active !== false
  });
}

/**
 * Compare two bundled snapshot actor lists.
 * @param {Array<{ name: string, slug: string, aliases?: string[], description?: string|null, active?: boolean }>} previousActors
 * @param {Array<{ name: string, slug: string, aliases?: string[], description?: string|null, active?: boolean }>} nextActors
 */
export function diffBundledSnapshots(previousActors = [], nextActors = []) {
  const prevBySlug = indexSnapshotActors(previousActors);
  const nextBySlug = indexSnapshotActors(nextActors);

  const newActors = [];
  const changedActors = [];
  const removedUpstream = [];
  let aliasAdditions = 0;
  let aliasRemovals = 0;

  for (const [slug, nextActor] of nextBySlug.entries()) {
    const prevActor = prevBySlug.get(slug);
    if (!prevActor) {
      newActors.push(nextActor.name);
      continue;
    }

    if (actorSignature(prevActor) !== actorSignature(nextActor)) {
      changedActors.push(nextActor.name);
    }

    const prevAliasKeys = new Set((prevActor.aliases || []).map((a) => String(a).toLowerCase()));
    const nextAliasKeys = new Set((nextActor.aliases || []).map((a) => String(a).toLowerCase()));
    for (const alias of nextAliasKeys) {
      if (!prevAliasKeys.has(alias)) aliasAdditions += 1;
    }
    for (const alias of prevAliasKeys) {
      if (!nextAliasKeys.has(alias)) aliasRemovals += 1;
    }
  }

  for (const [slug, prevActor] of prevBySlug.entries()) {
    if (!nextBySlug.has(slug)) {
      removedUpstream.push(prevActor.name);
    }
  }

  return {
    previousCount: previousActors.length,
    nextCount: nextActors.length,
    newActors,
    changedActors,
    removedUpstream,
    aliasAdditions,
    aliasRemovals
  };
}

export function printSnapshotDiffSummary(diff, { identityConflicts = 0, sourceActorCount = null } = {}) {
  console.log(`Previous bundled actors:     ${diff.previousCount}`);
  if (sourceActorCount != null) console.log(`Fetched from Malpedia:       ${sourceActorCount}`);
  console.log(`Normalized actors:           ${diff.nextCount}`);
  console.log(`New actors:                  ${diff.newActors.length}`);
  console.log(`Changed actors:              ${diff.changedActors.length}`);
  console.log(`Removed upstream:          ${diff.removedUpstream.length}`);
  console.log(`Alias additions:             ${diff.aliasAdditions}`);
  console.log(`Alias removals:              ${diff.aliasRemovals}`);
  console.log(`Identity conflicts:          ${identityConflicts}`);
  if (diff.potentialIdentityChanges?.length) {
    console.log(`Potential identity changes:  ${diff.potentialIdentityChanges.length}`);
  }
}

/**
 * Detect upstream canonical rename/replacement candidates between snapshots.
 * Informational only — never auto-merge runtime actors.
 */
export function detectPotentialCanonicalIdentityChanges(previousActors = [], nextActors = []) {
  const prevBySlug = indexSnapshotActors(previousActors);
  const nextBySlug = indexSnapshotActors(nextActors);
  const nextAliasOwners = new Map();

  for (const actor of nextActors) {
    for (const alias of actor.aliases || []) {
      const key = String(alias).trim().toLowerCase();
      if (!key) continue;
      if (!nextAliasOwners.has(key)) nextAliasOwners.set(key, actor);
    }
  }

  const potentialIdentityChanges = [];
  for (const [slug, prevActor] of prevBySlug.entries()) {
    if (nextBySlug.has(slug)) continue;
    const prevNameKey = String(prevActor.name || '').trim().toLowerCase();
    const related = nextAliasOwners.get(prevNameKey);
    if (!related) {
      potentialIdentityChanges.push({
        removed: prevActor.name,
        added: null,
        relationship: null
      });
      continue;
    }
    potentialIdentityChanges.push({
      removed: prevActor.name,
      added: related.name,
      relationship: `${prevActor.name} appears in aliases of ${related.name}`
    });
  }

  return potentialIdentityChanges;
}

export function printPotentialIdentityChanges(changes = []) {
  if (!changes.length) return;
  console.log('\nPotential canonical identity changes:');
  for (const change of changes.slice(0, 20)) {
    if (change.added && change.relationship) {
      console.log(`  REMOVED: ${change.removed}`);
      console.log(`  ADDED:   ${change.added}`);
      console.log(`  Possible relationship: ${change.relationship}`);
    } else {
      console.log(`  REMOVED: ${change.removed}`);
    }
  }
  if (changes.length > 20) {
    console.log(`  ... and ${changes.length - 20} more`);
  }
}
