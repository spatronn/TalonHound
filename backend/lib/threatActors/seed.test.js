import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildThreatActorImportPlan,
  IMPORT_OPERATOR_BUNDLED
} from './reconciliation.js';
import {
  ensureUnknownThreatActor,
  reconcileBundledThreatActors
} from './seed.js';
import { loadBundledSnapshot } from './snapshot.js';
import { LEGACY_SEED_DESCRIPTION } from './normalization.js';

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../fixtures/threat-actors-bundled.fixture.json'
);

const SEED_APT28 = {
  id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6',
  name: 'APT28',
  slug: 'apt28',
  aliases: ['Fancy Bear', 'Sofacy'],
  description: LEGACY_SEED_DESCRIPTION,
  active: true
};

const SEED_APT29 = {
  id: '92e08e97-5e84-4d29-920f-df0428d35dc7',
  name: 'APT29',
  slug: 'apt29',
  aliases: ['Cozy Bear', 'Midnight Blizzard', 'Nobelium'],
  description: LEGACY_SEED_DESCRIPTION,
  active: true
};

const SEED_LAZARUS = {
  id: '364117ec-9e72-4531-956a-ba7f013f1b45',
  name: 'Lazarus',
  slug: 'lazarus',
  aliases: ['Lazarus Group', 'HIDDEN COBRA'],
  description: LEGACY_SEED_DESCRIPTION,
  active: true
};

const SEED_UNKNOWN = {
  id: '11111111-1111-4111-8111-111111111111',
  name: 'Unknown',
  slug: 'unknown',
  aliases: [],
  description: 'System default actor',
  active: true,
  created_by: 'admin@example.com'
};

function cloneSeed(seed) {
  return { ...seed, aliases: [...(seed.aliases || [])] };
}

function createMockClient(initialRows = []) {
  const store = initialRows.map(cloneSeed);
  return {
    store,
    async query(sql, params = []) {
      const s = String(sql);
      if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') return { rows: [] };
      if (s.includes('SELECT * FROM threat_actors ORDER BY name ASC')) {
        return { rows: store.map(cloneSeed) };
      }
      if (s.includes("lower(name) = 'unknown' OR slug = 'unknown'")) {
        const row = store.find((r) => r.slug === 'unknown' || r.name.toLowerCase() === 'unknown');
        return { rows: row ? [cloneSeed(row)] : [] };
      }
      if (s.startsWith('INSERT INTO threat_actors')) {
        const row = s.includes("VALUES ('Unknown', 'unknown'")
          ? {
            id: `00000000-0000-4000-8000-${String(store.length + 1).padStart(12, '0')}`,
            name: 'Unknown',
            slug: 'unknown',
            aliases: null,
            description: params[1],
            active: true,
            catalog_sources: ['system'],
            created_by: params[0],
            updated_by: params[0]
          }
          : {
            id: `00000000-0000-4000-8000-${String(store.length + 1).padStart(12, '0')}`,
            name: params[0],
            slug: params[1],
            aliases: params[2],
            description: params[3],
            active: params[4],
            catalog_sources: params[5],
            created_by: params[6],
            updated_by: params[6]
          };
        store.push(row);
        return { rows: [cloneSeed(row)] };
      }
      if (s.startsWith('UPDATE threat_actors')) {
        const row = store.find((r) => r.id === params[0]);
        if (!row) return { rows: [] };
        if (s.includes('bundled_catalog_collision_pending = $2')) {
          row.bundled_catalog_collision_pending = params[1];
          row.updated_by = params[2];
        } else if (s.includes('SET catalog_sources = $2') && !s.includes('name = $2')) {
          row.catalog_sources = params[1];
          row.updated_by = params[2];
        } else {
          row.name = params[1];
          row.slug = params[2];
          row.aliases = params[3];
          row.description = params[4];
          row.active = params[5];
          row.catalog_sources = params[6];
          row.updated_by = params[7];
        }
        return { rows: [cloneSeed(row)] };
      }
      throw new Error(`Unhandled SQL in mock client: ${s}`);
    }
  };
}

test('ensureUnknownThreatActor inserts sentinel when missing', async () => {
  const client = createMockClient([]);
  const row = await ensureUnknownThreatActor(client);
  assert.equal(row.name, 'Unknown');
  assert.equal(row.slug, 'unknown');
  assert.equal(client.store.length, 1);
});

test('fresh bundled reconciliation inserts missing actors on empty DB', async () => {
  const client = createMockClient([]);
  const first = await reconcileBundledThreatActors(client, {
    snapshotPath: fixturePath,
    dryRun: false,
    ensureUnknown: true,
    operator: IMPORT_OPERATOR_BUNDLED
  });
  assert.ok(first.applied.inserted >= 4);
  assert.equal(first.applied.updated, 0);
  assert.ok(client.store.some((r) => r.slug === 'unknown'));
});

test('fresh bundled reconciliation is idempotent on second run', async () => {
  const client = createMockClient([]);
  await reconcileBundledThreatActors(client, { snapshotPath: fixturePath, dryRun: false });
  const second = await reconcileBundledThreatActors(client, { snapshotPath: fixturePath, dryRun: false });
  assert.equal(second.applied.inserted, 0);
  assert.equal(second.applied.updated, 0);
  const third = await reconcileBundledThreatActors(client, { snapshotPath: fixturePath, dryRun: false });
  assert.equal(third.applied.inserted, 0);
  assert.equal(third.applied.updated, 0);
});

test('upgrade reconciliation preserves IDs and enriches built-in actors', async () => {
  const client = createMockClient([SEED_APT28, SEED_APT29, SEED_LAZARUS, SEED_UNKNOWN]);
  const result = await reconcileBundledThreatActors(client, { snapshotPath: fixturePath, dryRun: false });
  const apt28 = client.store.find((r) => r.id === SEED_APT28.id);
  const apt29 = client.store.find((r) => r.id === SEED_APT29.id);
  const lazarus = client.store.find((r) => r.id === SEED_LAZARUS.id);
  const unknown = client.store.find((r) => r.id === SEED_UNKNOWN.id);

  assert.equal(apt28.id, SEED_APT28.id);
  assert.ok(apt28.aliases.includes('Pawn Storm'));
  assert.equal(apt29.id, SEED_APT29.id);
  assert.equal(lazarus.name, 'Lazarus');
  assert.equal(lazarus.slug, 'lazarus');
  assert.equal(unknown.description, SEED_UNKNOWN.description);
  assert.ok(result.applied.inserted >= 1);
});

test('user-created actor and local aliases survive bundled reconciliation', async () => {
  const custom = {
    id: '22222222-2222-4222-8222-222222222222',
    name: 'Custom Actor',
    slug: 'custom-actor',
    aliases: ['Local Alias'],
    description: 'Analyst-maintained actor',
    active: true,
    created_by: 'analyst@example.com'
  };
  const apt28 = cloneSeed(SEED_APT28);
  apt28.aliases = [...apt28.aliases, 'Local APT28 Alias'];

  const client = createMockClient([apt28, custom]);
  await reconcileBundledThreatActors(client, { snapshotPath: fixturePath, dryRun: false });

  const preservedCustom = client.store.find((r) => r.id === custom.id);
  const preservedApt28 = client.store.find((r) => r.id === SEED_APT28.id);
  assert.equal(preservedCustom.name, 'Custom Actor');
  assert.ok(preservedCustom.aliases.includes('Local Alias'));
  assert.ok(preservedApt28.aliases.includes('Local APT28 Alias'));
  assert.ok(preservedApt28.aliases.includes('Pawn Storm'));
});

test('dry-run bundled reconciliation performs zero writes', async () => {
  const client = createMockClient([]);
  const result = await reconcileBundledThreatActors(client, { snapshotPath: fixturePath, dryRun: true });
  assert.equal(result.applied, null);
  assert.equal(client.store.length, 0);
});

test('overlapping aliases keep UNC2452 separate from APT29 in bundled plan', async () => {
  const bundled = await loadBundledSnapshot(fixturePath);
  const plan = buildThreatActorImportPlan(bundled.records, [cloneSeed(SEED_APT29)]);
  assert.ok(plan.inserts.some((row) => row.slug === 'unc2452'));
  const apt29 = plan.updates.find((u) => u.id === SEED_APT29.id);
  assert.ok(apt29.aliases.includes('UNC2452'));
});

test('removed upstream actors are not deleted during reconciliation planning', async () => {
  const bundled = await loadBundledSnapshot(fixturePath);
  const existing = [{
    id: '99999999-9999-4999-8999-999999999999',
    name: 'Retired Upstream Actor',
    slug: 'retired-upstream-actor',
    aliases: [],
    description: 'Was once upstream',
    active: true
  }];
  const plan = buildThreatActorImportPlan(bundled.records, existing);
  assert.equal(plan.inserts.some((row) => row.slug === 'retired-upstream-actor'), false);
  assert.equal(plan.updates.some((u) => u.id === existing[0].id), false);
});
