import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createSnapshotHandlerCache, mergeProviderSnapshot, snapshotsEqual } from './providerSnapshotState.js';

test('unchanged snapshot returns the same state object (React bails out, no re-render)', () => {
  const prev = { virustotal: { status: 'success', found: true, stats: { malicious: 3 } } };
  const next = mergeProviderSnapshot(prev, 'virustotal', { status: 'success', found: true, stats: { malicious: 3 } });
  assert.equal(next, prev);
});

test('changed or new snapshot produces a new state object', () => {
  const prev = { virustotal: { status: 'loading' } };
  const changed = mergeProviderSnapshot(prev, 'virustotal', { status: 'success' });
  assert.notEqual(changed, prev);
  assert.deepEqual(changed.virustotal, { status: 'success' });
  const added = mergeProviderSnapshot(changed, 'urlscan', { status: 'success' });
  assert.deepEqual(Object.keys(added).sort(), ['urlscan', 'virustotal']);
  assert.deepEqual(mergeProviderSnapshot(undefined, 'rdap', { status: 'x' }), { rdap: { status: 'x' } });
});

test('snapshotsEqual distinguishes values, keys and arrays', () => {
  assert.equal(snapshotsEqual({ a: 1 }, { a: 1 }), true);
  assert.equal(snapshotsEqual({ a: 1 }, { a: 2 }), false);
  assert.equal(snapshotsEqual({ a: 1 }, { a: 1, b: undefined }), false);
  assert.equal(snapshotsEqual([1, 2], [1, 2]), true);
  assert.equal(snapshotsEqual([1], { 0: 1 }), false);
  assert.equal(snapshotsEqual(null, undefined), false);
  assert.equal(snapshotsEqual(NaN, NaN), true);
});

test('handler cache returns a referentially stable callback per provider', () => {
  let state = {};
  let updates = 0;
  const setState = (fn) => { const next = fn(state); if (next !== state) updates += 1; state = next; };
  const handlerFor = createSnapshotHandlerCache(setState);
  assert.equal(handlerFor('virustotal'), handlerFor('virustotal'));
  assert.notEqual(handlerFor('virustotal'), handlerFor('urlscan'));
  // A card re-reporting an identical snapshot must not cause another state change.
  for (let i = 0; i < 100; i += 1) handlerFor('virustotal')({ status: 'success' });
  assert.equal(updates, 1);
});

test('Intelligence tab never passes inline onSnapshot callbacks or resets snapshots in an effect', () => {
  const src = readFileSync(new URL('../intelligenceTab.jsx', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /onSnapshot=\{\(/, 'inline arrow re-triggers card snapshot effects every render');
  assert.match(src, /createSnapshotHandlerCache\(setProviderSnapshots\)/);
  assert.match(src, /createSnapshotHandlerCache\(setDerivedProviderSnapshots\)/);
  assert.doesNotMatch(src, /useEffect\(\(\) => \{\s*setProviderSnapshots\(\{\}\)/);
});
