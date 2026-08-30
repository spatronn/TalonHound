import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildThreatActorImportPlan,
  summarizeImportPlan
} from './reconciliation.js';
import {
  CATALOG_SOURCE_BUNDLED,
  CATALOG_SOURCE_MANUAL,
  canConfirmBundledCatalogIdentity,
  confirmBundledCatalogEquivalence,
  isManualOnlyActor,
  mergeCatalogSources,
  resolveCatalogSources,
  resolveReconciledActiveState
} from './catalogSources.js';
import { LEGACY_SEED_DESCRIPTION } from './normalization.js';
import { detectPotentialCanonicalIdentityChanges } from './snapshot.js';

const MANUAL_XYZ = {
  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  name: 'XYZ',
  slug: 'xyz',
  aliases: ['Internal Alias'],
  description: 'Internal/local description',
  active: false,
  created_by: 'analyst@example.com',
  catalog_sources: [CATALOG_SOURCE_MANUAL]
};

const BUNDLED_XYZ = {
  canonicalName: 'XYZ',
  slug: 'xyz',
  aliases: ['Foo Bear', 'Group 123'],
  description: 'Upstream Malpedia description',
  active: true
};

const SEED_APT28 = {
  id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
  name: 'APT28',
  slug: 'apt28',
  aliases: ['Fancy Bear', 'Sofacy'],
  description: LEGACY_SEED_DESCRIPTION,
  active: true,
  catalog_sources: ['legacy-seed', 'bundled']
};

const SEED_LAZARUS = {
  id: '364117ec-9e72-4531-956a-ba7f013f1b45',
  name: 'Lazarus',
  slug: 'lazarus',
  aliases: ['Lazarus Group', 'HIDDEN COBRA'],
  description: LEGACY_SEED_DESCRIPTION,
  active: true,
  catalog_sources: ['legacy-seed', 'bundled']
};

test('resolveCatalogSources marks admin-created actors as manual', () => {
  assert.deepEqual(resolveCatalogSources(MANUAL_XYZ), [CATALOG_SOURCE_MANUAL]);
});

test('manual XYZ + bundled XYZ collision preserves local data and records pending collision', () => {
  const plan = buildThreatActorImportPlan([BUNDLED_XYZ], [MANUAL_XYZ]);
  assert.equal(plan.inserts.length, 0);
  assert.equal(plan.updates.length, 0);
  assert.equal(plan.manualCanonicalCollisions.length, 1);
  assert.equal(plan.manualCanonicalCollisions[0].existingName, 'XYZ');
  assert.equal(plan.catalogSourceUpdates.length, 0);
  assert.equal(plan.collisionPendingUpdates.length, 1);
  assert.equal(plan.collisionPendingUpdates[0].bundled_catalog_collision_pending, true);
  assert.deepEqual(resolveCatalogSources(MANUAL_XYZ), [CATALOG_SOURCE_MANUAL]);
});

test('manual XYZ collision does not merge bundled aliases or description', () => {
  const plan = buildThreatActorImportPlan([BUNDLED_XYZ], [MANUAL_XYZ]);
  assert.equal(plan.aliasAdditions, 0);
  assert.equal(plan.updates.some((row) => row.id === MANUAL_XYZ.id), false);
});

test('confirmed manual+bundled XYZ allows safe bundled enrichment', () => {
  const confirmed = {
    ...MANUAL_XYZ,
    catalog_sources: confirmBundledCatalogEquivalence([CATALOG_SOURCE_MANUAL]),
    bundled_catalog_collision_pending: false
  };
  const plan = buildThreatActorImportPlan([BUNDLED_XYZ], [confirmed]);
  assert.equal(plan.manualCanonicalCollisions.length, 0);
  assert.equal(plan.updates.length, 1);
  assert.equal(plan.updates[0].id, MANUAL_XYZ.id);
  assert.ok(plan.updates[0].aliases.includes('Internal Alias'));
  assert.ok(plan.updates[0].aliases.includes('Foo Bear'));
  assert.equal(plan.updates[0].description, 'Internal/local description');
  assert.equal(plan.updates[0].active, false);
});

test('inactive manual XYZ remains inactive during collision handling', () => {
  const plan = buildThreatActorImportPlan([BUNDLED_XYZ], [MANUAL_XYZ]);
  assert.equal(plan.manualCanonicalCollisions[0].existingSlug, 'xyz');
  assert.equal(MANUAL_XYZ.active, false);
  assert.equal(plan.updates.length, 0);
});

test('inactive existing bundled actor is not re-enabled by bundled snapshot', () => {
  const inactiveApt28 = { ...SEED_APT28, active: false, description: 'Analyst disabled note' };
  const plan = buildThreatActorImportPlan([
    {
      canonicalName: 'APT28',
      slug: 'apt28',
      aliases: ['Pawn Storm'],
      description: 'Upstream text',
      active: true
    }
  ], [inactiveApt28]);
  assert.equal(plan.updates.length, 1);
  assert.equal(plan.updates[0].active, false);
});

test('existing bundled APT28 receives alias enrichment and preserves local aliases', () => {
  const apt28 = {
    ...SEED_APT28,
    aliases: [...SEED_APT28.aliases, 'Local APT28 Alias']
  };
  const plan = buildThreatActorImportPlan([
    {
      canonicalName: 'APT28',
      slug: 'apt28',
      aliases: ['Pawn Storm'],
      description: 'Malpedia description',
      active: true
    }
  ], [apt28]);
  assert.equal(plan.inserts.length, 0);
  assert.equal(plan.updates.length, 1);
  assert.equal(plan.updates[0].id, SEED_APT28.id);
  assert.ok(plan.updates[0].aliases.includes('Local APT28 Alias'));
  assert.ok(plan.updates[0].aliases.includes('Pawn Storm'));
});

test('empty bundled description may enrich legacy seed placeholder', () => {
  const plan = buildThreatActorImportPlan([
    {
      canonicalName: 'APT28',
      slug: 'apt28',
      aliases: [],
      description: 'Malpedia description',
      active: true
    }
  ], [SEED_APT28]);
  assert.equal(plan.updates[0].description, 'Malpedia description');
});

test('user-created actor with no collision remains untouched', () => {
  const custom = {
    id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    name: 'Internal Red Team',
    slug: 'internal-red-team',
    aliases: ['Local Alias'],
    description: 'Local only',
    active: true,
    catalog_sources: [CATALOG_SOURCE_MANUAL]
  };
  const plan = buildThreatActorImportPlan([
    {
      canonicalName: 'Turla',
      slug: 'turla',
      aliases: ['Snake'],
      description: 'Bundled Turla',
      active: true
    }
  ], [custom]);
  assert.equal(plan.manualCanonicalCollisions.length, 0);
  assert.equal(plan.updates.some((row) => row.id === custom.id), false);
  assert.equal(plan.inserts.length, 1);
  assert.equal(plan.inserts[0].slug, 'turla');
});

test('overlapping aliases keep separate canonical actors', () => {
  const apt29 = {
    id: '92e08e97-5e84-4d29-920f-df0428d35dc7',
    name: 'APT29',
    slug: 'apt29',
    aliases: ['Cozy Bear'],
    description: LEGACY_SEED_DESCRIPTION,
    active: true,
    catalog_sources: ['legacy-seed', 'bundled']
  };
  const plan = buildThreatActorImportPlan([
    {
      canonicalName: 'UNC2452',
      slug: 'unc2452',
      aliases: ['NOBELIUM', 'Midnight Blizzard'],
      description: 'Separate actor',
      active: true
    },
    {
      canonicalName: 'APT29',
      slug: 'apt29',
      aliases: ['UNC2452'],
      description: 'APT29 description',
      active: true
    }
  ], [apt29]);
  assert.ok(plan.inserts.some((row) => row.slug === 'unc2452'));
});

test('Lazarus legacy mapping remains a reviewed bundled equivalent', () => {
  const plan = buildThreatActorImportPlan([
    {
      canonicalName: 'Lazarus Group',
      slug: 'lazarus-group',
      aliases: ['Guardians of Peace'],
      description: 'Malpedia Lazarus Group',
      active: true
    }
  ], [SEED_LAZARUS]);
  assert.equal(plan.manualCanonicalCollisions.length, 0);
  assert.equal(plan.updates.length, 1);
  assert.equal(plan.updates[0].name, 'Lazarus');
  assert.equal(plan.updates[0].slug, 'lazarus');
});

test('second collision reconciliation is idempotent for pending collision state', () => {
  const pending = {
    ...MANUAL_XYZ,
    bundled_catalog_collision_pending: true
  };
  const first = buildThreatActorImportPlan([BUNDLED_XYZ], [pending]);
  const second = buildThreatActorImportPlan([BUNDLED_XYZ], [pending]);
  assert.equal(first.manualCanonicalCollisions.length, 1);
  assert.equal(first.collisionPendingUpdates.length, 0);
  assert.equal(second.manualCanonicalCollisions.length, 1);
  assert.equal(second.collisionPendingUpdates.length, 0);
  assert.equal(second.updates.length, 0);
});

test('summarizeImportPlan reports manual canonical collisions', () => {
  const plan = buildThreatActorImportPlan([BUNDLED_XYZ], [MANUAL_XYZ]);
  const summary = summarizeImportPlan(plan);
  assert.equal(summary.manualCanonicalCollisions, 1);
});

test('resolveReconciledActiveState preserves disabled actors', () => {
  assert.equal(resolveReconciledActiveState({ active: false }, true), false);
  assert.equal(resolveReconciledActiveState({ active: true }, false), true);
});

test('isManualOnlyActor distinguishes manual-only rows', () => {
  assert.equal(isManualOnlyActor(MANUAL_XYZ), true);
  assert.equal(isManualOnlyActor(SEED_APT28), false);
});

test('detectPotentialCanonicalIdentityChanges reports alias-based rename candidates', () => {
  const changes = detectPotentialCanonicalIdentityChanges(
    [{ name: 'Foo Group', slug: 'foo-group', aliases: [] }],
    [{ name: 'Foo Team', slug: 'foo-team', aliases: ['Foo Group'] }]
  );
  assert.equal(changes.length, 1);
  assert.equal(changes[0].removed, 'Foo Group');
  assert.equal(changes[0].added, 'Foo Team');
});

test('confirmBundledCatalogEquivalence adds bundled membership only', () => {
  assert.deepEqual(
    confirmBundledCatalogEquivalence([CATALOG_SOURCE_MANUAL]),
    [CATALOG_SOURCE_MANUAL, CATALOG_SOURCE_BUNDLED]
  );
});

test('mergeCatalogSources strips legacy collision marker and deduplicates memberships', () => {
  assert.deepEqual(
    mergeCatalogSources(['manual', 'bundled-collision'], ['bundled', 'manual']),
    ['manual', 'bundled']
  );
});

test('canConfirmBundledCatalogIdentity rejects Unknown and non-pending actors', () => {
  assert.equal(canConfirmBundledCatalogIdentity({ name: 'Unknown', slug: 'unknown' }).ok, false);
  assert.equal(canConfirmBundledCatalogIdentity(SEED_APT28).reason, 'already_confirmed');
  assert.equal(canConfirmBundledCatalogIdentity(MANUAL_XYZ).reason, 'no_pending_collision');
  assert.equal(canConfirmBundledCatalogIdentity({ ...MANUAL_XYZ, bundled_catalog_collision_pending: true }).ok, true);
});

test('real bundled snapshot actors do not become mass manual collisions', async () => {
  const { loadBundledSnapshot } = await import('./snapshot.js');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const fixturePath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/threat-actors-bundled.fixture.json');
  const bundled = await loadBundledSnapshot(fixturePath);
  const existing = bundled.records.slice(0, 20).map((record, index) => ({
    id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
    name: record.canonicalName,
    slug: record.slug,
    aliases: [],
    description: null,
    active: true,
    created_by: null,
    catalog_sources: [CATALOG_SOURCE_BUNDLED]
  }));
  const plan = buildThreatActorImportPlan(bundled.records.slice(0, 20), existing);
  assert.equal(plan.manualCanonicalCollisions.length, 0);
});
