import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildBundledSnapshotDocument,
  diffBundledSnapshots,
  loadBundledSnapshot,
  SNAPSHOT_SCHEMA_VERSION
} from './snapshot.js';
import { snapshotActorsToRecords, validateNormalizedActorRecords } from './normalization.js';
import { parseMalpediaActorsResponse } from './malpedia.js';

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const bundledFixturePath = path.join(fixtureDir, '../fixtures/threat-actors-bundled.fixture.json');
const malpediaFixturePath = path.join(fixtureDir, '../fixtures/malpedia-actors.fixture.json');

test('bundled snapshot fixture parses successfully', async () => {
  const bundled = await loadBundledSnapshot(bundledFixturePath);
  assert.equal(bundled.document.schema_version, SNAPSHOT_SCHEMA_VERSION);
  assert.equal(bundled.records.length, 5);
  assert.equal(bundled.records.every((r) => r.canonicalName && r.slug), true);
});

test('bundled snapshot fixture has unique canonical names and slugs', async () => {
  const bundled = await loadBundledSnapshot(bundledFixturePath);
  const validation = validateNormalizedActorRecords(bundled.records);
  assert.equal(validation.ok, true);
  assert.equal(validation.conflicts.length, 0);
});

test('empty bundled snapshot fails safely', async () => {
  await assert.rejects(
    () => loadBundledSnapshot(path.join(fixtureDir, '../fixtures/does-not-exist.json')),
    /Failed to read bundled snapshot/
  );
});

test('buildBundledSnapshotDocument rejects identity conflicts', () => {
  assert.throws(() => buildBundledSnapshotDocument([
    { canonicalName: 'APT28', slug: 'apt28', aliases: [], description: null },
    { canonicalName: 'APT28 duplicate', slug: 'apt28', aliases: [], description: null }
  ]), /Snapshot identity validation failed/);
});

test('diffBundledSnapshots reports new/changed/removed upstream', () => {
  const previous = JSON.parse(readFileSync(bundledFixturePath, 'utf8')).actors;
  const next = previous.map((actor) => (
    actor.slug === 'apt28'
      ? { ...actor, aliases: [...actor.aliases, 'Sofacy Group'] }
      : actor
  )).filter((actor) => actor.slug !== 'turla');

  const diff = diffBundledSnapshots(previous, next);
  assert.ok(diff.newActors.length >= 0);
  assert.ok(diff.changedActors.includes('APT28'));
  assert.deepEqual(diff.removedUpstream, ['Turla']);
  assert.ok(diff.aliasAdditions >= 1);
});

test('malpedia fixture normalizes into snapshot-compatible records', () => {
  const raw = JSON.parse(readFileSync(malpediaFixturePath, 'utf8'));
  const parsed = parseMalpediaActorsResponse(raw, { minActors: 1 });
  assert.equal(parsed.ok, true);
  const document = buildBundledSnapshotDocument(parsed.records, { sourceActorCount: Object.keys(raw).length, generatedAt: '2026-01-01T00:00:00.000Z' });
  assert.equal(document.actors.length, parsed.records.length);
  assert.deepEqual(snapshotActorsToRecords(document.actors).map((r) => r.slug).sort(), document.actors.map((a) => a.slug).sort());
});

test('production bundled snapshot parses with unique identities', async () => {
  const bundled = await loadBundledSnapshot();
  assert.equal(bundled.document.actor_count, bundled.records.length);
  assert.ok(bundled.records.length >= 1000);
  const validation = validateNormalizedActorRecords(bundled.records);
  assert.equal(validation.ok, true);
});
