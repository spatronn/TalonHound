import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMultiThreatActorResponseFields,
  diffThreatActorIds,
  legacyThreatActorColumnValue,
  normalizeIocThreatActorIds,
  parseThreatActorBody
} from './iocThreatActors.js';

test('normalizeIocThreatActorIds dedupes UUIDs case-insensitively', () => {
  const a = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const b = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
  assert.deepEqual(
    normalizeIocThreatActorIds([a, a.toUpperCase(), b, 'not-a-uuid', null]),
    [a, b]
  );
});

test('legacyThreatActorColumnValue picks first id', () => {
  assert.equal(legacyThreatActorColumnValue([]), null);
  assert.equal(legacyThreatActorColumnValue(['a', 'b']), 'a');
});

test('buildMultiThreatActorResponseFields sets primary legacy fields', () => {
  const fields = buildMultiThreatActorResponseFields([
    { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', name: 'APT29', slug: 'apt29', active: true },
    { id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', name: 'APT28', slug: 'apt28', active: true }
  ]);
  assert.equal(fields.threat_actor_id, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
  assert.equal(fields.threat_actor_name, 'APT29');
  assert.equal(fields.threat_actor_ids.length, 2);
  assert.equal(fields.threat_actors.length, 2);
});

test('parseThreatActorBody accepts ids array, objects, or singular', () => {
  assert.deepEqual(parseThreatActorBody({ threat_actor_ids: ['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'] }), [
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
  ]);
  assert.deepEqual(parseThreatActorBody({ threat_actors: [{ id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' }] }), [
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  ]);
  assert.deepEqual(parseThreatActorBody({ threat_actor_id: null }), []);
  assert.equal(parseThreatActorBody({}), undefined);
});

test('diffThreatActorIds reports added and removed', () => {
  const diff = diffThreatActorIds(
    ['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'],
    ['bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb']
  );
  assert.deepEqual(diff.added, ['bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb']);
  assert.deepEqual(diff.removed, ['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa']);
});
