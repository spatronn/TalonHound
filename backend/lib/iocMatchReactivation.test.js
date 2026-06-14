import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizePgLookupType,
  normalizePgLookupObservable,
  selectMissingTuplesForPgSupplement,
  createPgSupplementStats
} from './iocMatchReactivation.js';

test('normalizePgLookupType maps hostname to domain', () => {
  assert.equal(normalizePgLookupType('hostname'), 'domain');
  assert.equal(normalizePgLookupType('IP'), 'ip');
});

test('normalizePgLookupObservable preserves URL case', () => {
  assert.equal(normalizePgLookupObservable('HTTPS://Example.COM/x', 'url'), 'HTTPS://Example.COM/x');
  assert.equal(normalizePgLookupObservable('EvIL.com', 'domain'), 'evil.com');
});

test('selectMissingTuplesForPgSupplement dedupes and caps keys', () => {
  const lookupMap = new Map([['ip\t1.1.1.1', { confidence: 90 }]]);
  const tupleList = [
    ['1.1.1.1', 'ip'],
    ['1.1.1.1', 'ip'],
    ['8.8.8.8', 'ip'],
    ['evil.com', 'domain'],
    ['9.9.9.9', 'ip']
  ];
  const { selected, totalMissing, skippedCount } = selectMissingTuplesForPgSupplement(tupleList, lookupMap, 2);
  assert.equal(totalMissing, 3);
  assert.equal(selected.length, 2);
  assert.equal(skippedCount, 1);
  assert.deepEqual(selected[0], ['8.8.8.8', 'ip']);
});

test('createPgSupplementStats returns zeroed counters', () => {
  const s = createPgSupplementStats();
  assert.equal(s.pg_supplement_attempted, false);
  assert.equal(s.pg_supplement_keys, 0);
  assert.equal(s.skip_reason, null);
});
