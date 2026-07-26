import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveCanonicalIocTimestamps,
  IOC_LIST_TIMESTAMP_COLUMN,
  CANONICAL_LAST_CHANGED_AGG_SQL,
  CANONICAL_FIRST_SEEN_AGG_SQL
} from './iocListTimestamps.js';

test('uses last_changed_in_source when present', () => {
  const out = resolveCanonicalIocTimestamps({
    first_seen_in_source: '2026-01-01T00:00:00.000Z',
    last_changed_in_source: '2026-07-01T12:00:00.000Z',
    item_created_at: '2025-01-01T00:00:00.000Z'
  });
  assert.equal(out.last_changed_in_source, '2026-07-01T12:00:00.000Z');
  assert.equal(out.last_seen_at, '2026-07-01T12:00:00.000Z');
  assert.equal(out.display_timestamp_field, 'last_changed_in_source');
});

test('falls back to first_seen_in_feed aggregate when last_changed null', () => {
  const out = resolveCanonicalIocTimestamps({
    first_seen_in_source: '2026-03-01T00:00:00.000Z',
    last_changed_in_source: null,
    item_created_at: '2026-02-01T00:00:00.000Z'
  });
  assert.equal(out.last_seen_at, '2026-03-01T00:00:00.000Z');
  assert.equal(out.last_changed_in_source, '2026-03-01T00:00:00.000Z');
  assert.equal(out.display_timestamp_field, 'first_seen_in_feed');
});

test('falls back to created_at when membership timestamps missing', () => {
  const out = resolveCanonicalIocTimestamps({
    item_created_at: '2026-02-01T00:00:00.000Z'
  });
  assert.equal(out.last_seen_at, '2026-02-01T00:00:00.000Z');
  assert.equal(out.display_timestamp_field, 'created_at');
});

test('null only when all sources are null', () => {
  const out = resolveCanonicalIocTimestamps({});
  assert.equal(out.last_seen_at, null);
  assert.equal(out.display_timestamp_field, null);
});

test('browse and search share identical resolver output', () => {
  const membership = {
    first_seen_in_source: '2026-01-10T08:00:00.000Z',
    last_changed_in_source: '2026-06-15T09:30:00.000Z'
  };
  const browse = resolveCanonicalIocTimestamps({
    ...membership,
    item_created_at: '2026-01-01T00:00:00.000Z'
  });
  const search = resolveCanonicalIocTimestamps({
    ...membership,
    item_created_at: '2026-01-01T00:00:00.000Z'
  });
  assert.equal(browse.last_seen_at, search.last_seen_at);
  assert.equal(browse.last_changed_in_source, search.last_changed_in_source);
});

test('multi-membership aggregate SQL is shared and excludes technical last_seen_in_feed', () => {
  assert.match(CANONICAL_LAST_CHANGED_AGG_SQL, /last_changed_in_source/);
  assert.match(CANONICAL_LAST_CHANGED_AGG_SQL, /first_seen_in_feed/);
  assert.equal(CANONICAL_LAST_CHANGED_AGG_SQL.includes('last_seen_in_feed'), false);
  assert.equal(CANONICAL_FIRST_SEEN_AGG_SQL, 'MIN(m.first_seen_in_feed)');
  assert.equal(IOC_LIST_TIMESTAMP_COLUMN.label, 'Last changed in source');
  assert.deepEqual(IOC_LIST_TIMESTAMP_COLUMN.fallback, [
    'ioc_feed_memberships.last_changed_in_source',
    'ioc_feed_memberships.first_seen_in_feed',
    'ioc_items.created_at'
  ]);
});
