import test from 'node:test';
import assert from 'node:assert/strict';
import { createLatestOnly } from './latestOnly.js';

test('only the newest operation is not stale', () => {
  const guard = createLatestOnly();
  const isStaleA = guard.next();
  const isStaleB = guard.next();
  assert.equal(isStaleA(), true, 'older op A is stale');
  assert.equal(isStaleB(), false, 'newest op B is current');
});

test('a single operation is never stale', () => {
  const guard = createLatestOnly();
  const isStale = guard.next();
  assert.equal(isStale(), false);
});

test("an older FAILED response cannot overwrite a newer SUCCESS", () => {
  // Model the load() sequencing: request A starts, then request B starts and
  // succeeds (applies state). A then fails late — its handler must be skipped.
  const guard = createLatestOnly();
  const state = { integrations: null, error: '' };

  const isStaleA = guard.next(); // A begins
  const isStaleB = guard.next(); // B begins (newer)

  // B succeeds first and applies.
  if (!isStaleB()) state.integrations = ['feed-1', 'feed-2'];

  // A fails later; guard must prevent it from clobbering B's good state.
  if (!isStaleA()) state.error = 'Failed to load integrations';

  assert.deepEqual(state.integrations, ['feed-1', 'feed-2']);
  assert.equal(state.error, '', 'stale failure did not overwrite newer success');
});

test('a newer response still applies after an older one resolved', () => {
  const guard = createLatestOnly();
  const state = { value: null };

  const isStaleA = guard.next();
  if (!isStaleA()) state.value = 'A';

  const isStaleB = guard.next();
  if (!isStaleB()) state.value = 'B';

  assert.equal(state.value, 'B');
});
