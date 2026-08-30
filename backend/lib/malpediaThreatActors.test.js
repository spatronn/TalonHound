import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  LEGACY_SEED_DESCRIPTION,
  buildExistingActorIndex,
  buildThreatActorImportPlan,
  findExistingActorMatch,
  mergeThreatActorAliases,
  mergeThreatActorDescription,
  parseMalpediaActorsResponse,
  summarizeImportPlan,
  validateThreatActorName
} from './malpediaThreatActors.js';

const fixturePath = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'malpedia-actors.fixture.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

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
  active: true
};

function cloneSeed(seed) {
  return {
    ...seed,
    aliases: [...(seed.aliases || [])]
  };
}

function seedCatalog(...seeds) {
  return seeds.map(cloneSeed);
}

function parseFixture() {
  const parsed = parseMalpediaActorsResponse(fixture, { minActors: 1 });
  assert.equal(parsed.ok, true);
  return parsed.records;
}

test('parseMalpediaActorsResponse rejects unexpected shapes', () => {
  assert.deepEqual(parseMalpediaActorsResponse([]), { ok: false, error: 'unexpected_response_shape' });
  assert.deepEqual(parseMalpediaActorsResponse(null), { ok: false, error: 'unexpected_response_shape' });
});

test('parseMalpediaActorsResponse aborts on empty dataset', () => {
  const result = parseMalpediaActorsResponse({});
  assert.equal(result.ok, false);
  assert.equal(result.error, 'empty_or_incomplete_dataset');
  assert.equal(result.count, 0);
});

test('parseMalpediaActorsResponse parses fixture actors and skips invalid names', () => {
  const parsed = parseMalpediaActorsResponse(fixture, { minActors: 1 });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.records.length, 5);
  assert.ok(parsed.skippedInvalid >= 1);
  const apt28 = parsed.records.find((r) => r.canonicalName === 'APT28');
  assert.ok(apt28);
  assert.ok(apt28.aliases.includes('Fancy Bear'));
  assert.ok(!apt28.aliases.some((a) => a.toLowerCase() === 'apt28'));
});

test('mergeThreatActorAliases deduplicates case-insensitively and excludes canonical name', () => {
  const merged = mergeThreatActorAliases('APT28', ['fancy bear'], ['FANCY BEAR', 'Sofacy', 'APT28']);
  assert.deepEqual(merged, ['fancy bear', 'Sofacy']);
});

test('validateThreatActorName rejects empty and too-long names', () => {
  assert.deepEqual(validateThreatActorName(''), { ok: false, reason: 'empty_name' });
  assert.deepEqual(validateThreatActorName('x'.repeat(101)), { ok: false, reason: 'name_too_long' });
});

test('mergeThreatActorDescription keeps existing text and replaces legacy seed placeholder', () => {
  assert.equal(mergeThreatActorDescription(LEGACY_SEED_DESCRIPTION, 'Malpedia text'), 'Malpedia text');
  assert.equal(mergeThreatActorDescription('Keep me', 'Malpedia text'), 'Keep me');
  assert.equal(mergeThreatActorDescription('Keep me', ''), 'Keep me');
});

test('findExistingActorMatch uses canonical name and Lazarus legacy mapping', () => {
  const index = buildExistingActorIndex(seedCatalog(SEED_LAZARUS, SEED_APT28));
  const lazarusRecord = parseFixture().find((r) => r.canonicalName === 'Lazarus Group');
  const match = findExistingActorMatch(lazarusRecord, index);
  assert.equal(match.id, SEED_LAZARUS.id);
});

test('buildThreatActorImportPlan enriches APT28 and APT29 without inserting duplicates', () => {
  const records = parseFixture();
  const plan = buildThreatActorImportPlan(records, seedCatalog(SEED_APT28, SEED_APT29, SEED_LAZARUS));
  assert.equal(plan.inserts.length, 2);
  assert.ok(plan.updates.some((u) => u.id === SEED_APT28.id));
  assert.ok(plan.updates.some((u) => u.id === SEED_APT29.id));
  const apt28 = plan.updates.find((u) => u.id === SEED_APT28.id);
  assert.equal(apt28.name, 'APT28');
  assert.ok(apt28.aliases.includes('Pawn Storm'));
  assert.match(String(apt28.description), /Sofacy/);
});

test('buildThreatActorImportPlan preserves Lazarus primary name and slug', () => {
  const records = parseFixture();
  const plan = buildThreatActorImportPlan(records, seedCatalog(SEED_LAZARUS));
  const lazarus = plan.updates.find((u) => u.id === SEED_LAZARUS.id);
  assert.equal(lazarus.name, 'Lazarus');
  assert.equal(lazarus.slug, 'lazarus');
  assert.ok(lazarus.aliases.includes('Lazarus Group'));
  assert.ok(lazarus.aliases.includes('Guardians of Peace'));
  assert.equal(plan.preserved.lazarus.decision, 'preserve_primary_name_and_slug');
});

test('buildThreatActorImportPlan preserves Unknown sentinel', () => {
  const records = [
    ...parseFixture(),
    {
      canonicalName: 'Unknown',
      slug: 'unknown',
      aliases: ['Unattributed'],
      description: 'Malpedia placeholder unknown actor entry.',
      malpediaUuid: '22222222-2222-4222-8222-222222222222'
    }
  ];
  const plan = buildThreatActorImportPlan(records, seedCatalog(SEED_UNKNOWN, SEED_APT28));
  assert.equal(plan.skippedUnknownSentinel, 1);
  const unknownUpdate = plan.updates.find((u) => u.id === SEED_UNKNOWN.id);
  assert.equal(unknownUpdate, undefined);
  assert.equal(plan.preserved.unknown.action, 'preserved');
});

test('overlapping aliases keep UNC2452 separate from APT29', () => {
  const records = parseFixture();
  const plan = buildThreatActorImportPlan(records, seedCatalog(SEED_APT29));
  assert.ok(plan.inserts.some((row) => row.name === 'UNC2452'));
  const apt29 = plan.updates.find((u) => u.id === SEED_APT29.id);
  assert.ok(apt29.aliases.includes('UNC2452'));
});

test('second import plan is idempotent', () => {
  const records = parseFixture();
  const first = buildThreatActorImportPlan(records, seedCatalog(SEED_APT28, SEED_APT29, SEED_LAZARUS));
  const simulated = [
    ...seedCatalog(SEED_APT28, SEED_APT29, SEED_LAZARUS),
    ...first.inserts.map((row, idx) => ({
      id: `00000000-0000-4000-8000-${String(idx + 100).padStart(12, '0')}`,
      ...row
    }))
  ];
  for (const update of first.updates) {
    const row = simulated.find((r) => r.id === update.id);
    row.name = update.name;
    row.slug = update.slug;
    row.aliases = update.aliases;
    row.description = update.description;
  }
  const second = buildThreatActorImportPlan(records, simulated);
  assert.equal(second.inserts.length, 0);
  assert.equal(second.updates.every((u) => u.aliasAdditions === 0), true);
});

test('summarizeImportPlan counts expected buckets', () => {
  const records = parseFixture();
  const plan = buildThreatActorImportPlan(records, seedCatalog(SEED_APT28, SEED_APT29, SEED_LAZARUS));
  const summary = summarizeImportPlan(plan);
  assert.equal(summary.newActors, 2);
  assert.equal(summary.existingExactMatches, 3);
  assert.equal(summary.existingActorsEnriched, 3);
  assert.ok(summary.aliasAdditions > 0);
});
