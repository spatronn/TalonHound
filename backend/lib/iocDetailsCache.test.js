import test from 'node:test';
import assert from 'node:assert/strict';
import { createIocDetailsCache, pruneIocDetailsCache } from './iocDetailsCache.js';

test('get returns null for expired entries and deletes them', () => {
  let now = 1_000;
  const cache = createIocDetailsCache({ ttlMs: 100, maxEntries: 10, now: () => now });
  cache.set('a', { ok: true });
  assert.deepEqual(cache.get('a')?.payload, { ok: true });
  now = 1_200;
  assert.equal(cache.get('a'), null);
  assert.equal(cache.size(), 0);
});

test('set prunes expired then enforces max entries', () => {
  let now = 1_000;
  const cache = createIocDetailsCache({ ttlMs: 5_000, maxEntries: 2, now: () => now });
  cache.set('a', 1);
  cache.set('b', 2);
  cache.set('c', 3);
  assert.equal(cache.get('a'), null);
  assert.ok(cache.get('b'));
  assert.ok(cache.get('c'));
  assert.equal(cache.get('c').payload, 3);
});

test('prune removes expired and returns remaining size', () => {
  let now = 1_000;
  const cache = createIocDetailsCache({ ttlMs: 50, maxEntries: 10, now: () => now });
  cache.set('live', 1);
  now = 1_010;
  cache.set('fresh', 2);
  // live expires at 1050; fresh at 1060 — prune while only live is stale.
  now = 1_055;
  assert.equal(cache.prune(), 1);
  assert.equal(cache.get('live'), null);
  assert.ok(cache.get('fresh'));
});

test('delete and clear work', () => {
  const cache = createIocDetailsCache({ ttlMs: 10_000, maxEntries: 10 });
  cache.set('x', 1);
  cache.delete('x');
  assert.equal(cache.get('x'), null);
  cache.set('y', 2);
  cache.clear();
  assert.equal(cache.get('y'), null);
});

test('pruneIocDetailsCache exported helper delegates to instance prune', () => {
  let now = 1_000;
  const cache = createIocDetailsCache({ ttlMs: 50, maxEntries: 10, now: () => now });
  cache.set('gone', 1);
  now = 1_100;
  assert.equal(pruneIocDetailsCache(cache, now), 0);
});
