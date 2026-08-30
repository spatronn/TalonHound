import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  inferCatalogSourcesForRow,
  summarizeThreatActorProvenance
} from './catalogBackfill.js';
import { CATALOG_SOURCE_BUNDLED, CATALOG_SOURCE_MANUAL, CATALOG_SOURCE_SYSTEM } from './catalogSources.js';
import { loadBundledSnapshot } from './snapshot.js';

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '../fixtures/threat-actors-bundled.fixture.json'
);

test('historical bundled actor with NULL created_by becomes bundled, not manual', async () => {
  const bundled = await loadBundledSnapshot(fixturePath);
  const slugSet = new Set(bundled.records.map((record) => record.slug));
  const turla = bundled.records.find((record) => record.slug === 'turla');
  assert.ok(turla);
  const sources = inferCatalogSourcesForRow(
    { id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', name: turla.canonicalName, slug: turla.slug, created_by: null },
    slugSet
  );
  assert.deepEqual(sources, [CATALOG_SOURCE_BUNDLED]);
});

test('historical APT28 classified bundled via legacy seed id', () => {
  const sources = inferCatalogSourcesForRow(
    { id: '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6', name: 'APT28', slug: 'apt28', created_by: null },
    new Set(['apt28'])
  );
  assert.deepEqual(sources, ['legacy-seed', CATALOG_SOURCE_BUNDLED]);
});

test('historical APT29 classified bundled via legacy seed id', () => {
  const sources = inferCatalogSourcesForRow(
    { id: '92e08e97-5e84-4d29-920f-df0428d35dc7', name: 'APT29', slug: 'apt29', created_by: null },
    new Set(['apt29'])
  );
  assert.deepEqual(sources, ['legacy-seed', CATALOG_SOURCE_BUNDLED]);
});

test('historical Lazarus classified via legacy seed id', () => {
  const sources = inferCatalogSourcesForRow(
    { id: '364117ec-9e72-4531-956a-ba7f013f1b45', name: 'Lazarus', slug: 'lazarus', created_by: null },
    new Set(['lazarus'])
  );
  assert.deepEqual(sources, ['legacy-seed', CATALOG_SOURCE_BUNDLED]);
});

test('Unknown protected as system sentinel', () => {
  const sources = inferCatalogSourcesForRow(
    { id: '11111111-1111-4111-8111-111111111111', name: 'Unknown', slug: 'unknown', created_by: null },
    new Set()
  );
  assert.deepEqual(sources, [CATALOG_SOURCE_SYSTEM]);
});

test('genuinely manual actor classified manual', () => {
  const sources = inferCatalogSourcesForRow(
    {
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      name: 'Internal Red Team',
      slug: 'internal-red-team',
      created_by: 'analyst@example.com',
      catalog_sources: [CATALOG_SOURCE_MANUAL]
    },
    new Set(['turla'])
  );
  assert.deepEqual(sources, [CATALOG_SOURCE_MANUAL]);
});

test('summarizeThreatActorProvenance counts pending collisions separately from memberships', () => {
  const summary = summarizeThreatActorProvenance([
    { slug: 'apt28', catalog_sources: [CATALOG_SOURCE_BUNDLED] },
    { slug: 'xyz', catalog_sources: [CATALOG_SOURCE_MANUAL], bundled_catalog_collision_pending: true },
    { slug: 'unknown', catalog_sources: [CATALOG_SOURCE_SYSTEM] }
  ]);
  assert.equal(summary.bundledOnly, 1);
  assert.equal(summary.manualOnly, 1);
  assert.equal(summary.pendingCollisions, 1);
  assert.equal(summary.unknown, 1);
});

test('012 false-positive manual marker on bundled slug is corrected to bundled', () => {
  const sources = inferCatalogSourcesForRow(
    {
      id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      name: 'Turla',
      slug: 'turla',
      created_by: null,
      catalog_sources: [CATALOG_SOURCE_MANUAL]
    },
    new Set(['turla'])
  );
  assert.deepEqual(sources, [CATALOG_SOURCE_BUNDLED]);
});

test('resolveCatalogSources does not default NULL created_by to manual', async () => {
  const { resolveCatalogSources } = await import('./catalogSources.js');
  assert.deepEqual(
    resolveCatalogSources({ id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', name: 'Mystery', slug: 'mystery', created_by: null }),
    []
  );
});
