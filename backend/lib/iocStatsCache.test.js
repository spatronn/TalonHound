import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIocStatsCacheKey,
  invalidateIocStatsCache,
  readIocStatsCache,
  writeIocStatsCache
} from './iocStatsCache.js';

test('invalidateIocStatsCache clears prior entries', () => {
  const key = buildIocStatsCacheKey('active', '2026-01-01');
  writeIocStatsCache(key, { total: 10, by_source: [] });
  assert.ok(readIocStatsCache(key));
  invalidateIocStatsCache();
  assert.equal(readIocStatsCache(key), null);
});

test('buildIocStatsCacheKey includes status filter', () => {
  const a = buildIocStatsCacheKey('active', '2026-01-01');
  const b = buildIocStatsCacheKey('expired', '2026-01-01');
  assert.notEqual(a, b);
});
