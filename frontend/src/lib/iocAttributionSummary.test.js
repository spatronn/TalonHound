import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getThreatActorsFromSummary,
  getMalwareFamiliesFromSummary,
  getAnalystThreatActorIdsFromSummary,
  getAnalystMalwareFamilyIdsFromSummary,
  attributionHint
} from './iocAttributionSummary.js';

test('getThreatActorsFromSummary prefers attribution-aware list', () => {
  const actors = getThreatActorsFromSummary({
    threat_actors: [
      { id: 'a1', name: 'UNC3569', attribution: 'source_reported' },
      { name: 'UnresolvedActor', attribution: 'source_reported' }
    ]
  });
  assert.equal(actors.length, 2);
});

test('getAnalystThreatActorIdsFromSummary ignores source-only actors', () => {
  const ids = getAnalystThreatActorIdsFromSummary({
    analyst_threat_actor_ids: ['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'],
    threat_actors: [
      { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', name: 'APT29', attribution: 'analyst' },
      { id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', name: 'UNC3569', attribution: 'source_reported' }
    ]
  });
  assert.deepEqual(ids, ['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa']);
});

test('getMalwareFamiliesFromSummary reads first-class field', () => {
  const families = getMalwareFamiliesFromSummary({
    malware_families: [
      { name: 'GRAYRABBIT', attribution: 'source_reported' },
      { name: 'RABBITFUR', attribution: 'source_reported' }
    ]
  });
  assert.equal(families.length, 2);
  assert.equal(families[0].name, 'GRAYRABBIT');
});

test('getAnalystMalwareFamilyIdsFromSummary empty when source-only', () => {
  const ids = getAnalystMalwareFamilyIdsFromSummary({
    malware_families: [{ name: 'GRAYRABBIT', attribution: 'source_reported' }],
    analyst_malware_family_ids: []
  });
  assert.deepEqual(ids, []);
});

test('attributionHint distinguishes pulse-context source reporting', () => {
  const hint = attributionHint({
    name: 'UNC3569',
    attribution: 'source_reported',
    sources: [{
      source_name: 'AlienVault OTX',
      assertion_status: 'current',
      association_kind: 'associated_via_source_pulse'
    }]
  });
  assert.match(hint, /AlienVault OTX/);
  assert.match(hint, /pulse context/);
});

test('empty summary yields empty attribution lists', () => {
  assert.deepEqual(getThreatActorsFromSummary({}), []);
  assert.deepEqual(getMalwareFamiliesFromSummary({}), []);
});
