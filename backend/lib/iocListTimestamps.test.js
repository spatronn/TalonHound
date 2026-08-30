import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolvePlatformImportTimestamp,
  resolveSourceChangeTimestamps,
  resolveCanonicalIocTimestamps,
  attachCanonicalIocListTimestamps,
  resolveDetailPlatformImportTimestamp,
  resolveDetailLastConfirmedAt,
  IOC_LIST_TIMESTAMP_COLUMN,
  CANONICAL_LAST_CHANGED_AGG_SQL,
  CANONICAL_FIRST_SEEN_AGG_SQL
} from './iocListTimestamps.js';

test('new IOC Timestamp is platform created/imported time', () => {
  const out = resolvePlatformImportTimestamp({
    item_created_at: '2026-07-26T10:00:00.000Z'
  });
  assert.equal(out.imported_at, '2026-07-26T10:00:00.000Z');
  assert.equal(out.created_at, '2026-07-26T10:00:00.000Z');
  assert.equal(out.last_seen_at, '2026-07-26T10:00:00.000Z');
  assert.equal(out.list_timestamp_field, 'created_at');
});

test('re-sync / later membership times do not change platform Timestamp', () => {
  const created = '2026-07-26T10:00:00.000Z';
  const first = resolvePlatformImportTimestamp({ item_created_at: created });
  const afterResync = resolvePlatformImportTimestamp({ item_created_at: created });
  assert.equal(first.imported_at, afterResync.imported_at);

  // Source-change fields may move; list Timestamp must not.
  const source = resolveSourceChangeTimestamps({
    item_created_at: created,
    first_seen_in_source: '2026-07-26T10:00:00.000Z',
    last_changed_in_source: '2026-07-27T12:00:00.000Z'
  });
  const platform = resolvePlatformImportTimestamp({ item_created_at: created });
  assert.equal(platform.imported_at, created);
  assert.equal(source.last_changed_in_source, '2026-07-27T12:00:00.000Z');
  assert.notEqual(platform.imported_at, source.last_changed_in_source);
});

test('second feed seeing same IOC later does not change Timestamp', () => {
  const created = '2026-07-26T10:00:00.000Z';
  const out = resolveCanonicalIocTimestamps({
    item_created_at: created,
    first_seen_in_source: '2026-07-26T10:00:00.000Z',
    last_changed_in_source: '2026-07-26T12:00:00.000Z'
  });
  assert.equal(out.imported_at, created);
  assert.equal(out.display_timestamp, created);
  assert.equal(out.last_changed_in_source, '2026-07-26T12:00:00.000Z');
});

test('list Timestamp never uses last_seen_in_feed or updated_at', () => {
  const out = resolvePlatformImportTimestamp({
    item_created_at: '2026-01-01T00:00:00.000Z'
  });
  assert.equal(out.imported_at, '2026-01-01T00:00:00.000Z');
  assert.equal(IOC_LIST_TIMESTAMP_COLUMN.canonicalField, 'created_at');
  assert.equal(IOC_LIST_TIMESTAMP_COLUMN.apiField, 'imported_at');
  assert.equal(IOC_LIST_TIMESTAMP_COLUMN.label, 'Timestamp');
  assert.deepEqual(IOC_LIST_TIMESTAMP_COLUMN.fallback, ['ioc_items.created_at']);
  assert.equal(String(IOC_LIST_TIMESTAMP_COLUMN.description).includes('last_seen_in_feed'), false);
});

test('source-change fallback uses first_seen_in_feed when last_changed null', () => {
  const out = resolveSourceChangeTimestamps({
    first_seen_in_source: '2026-03-01T00:00:00.000Z',
    last_changed_in_source: null,
    item_created_at: '2026-02-01T00:00:00.000Z'
  });
  assert.equal(out.last_changed_in_source, '2026-03-01T00:00:00.000Z');
  assert.equal(out.last_changed_in_source_raw, null);
});

test('source-change does not fall back to created_at as last_changed', () => {
  const out = resolveSourceChangeTimestamps({
    item_created_at: '2026-02-01T00:00:00.000Z'
  });
  assert.equal(out.last_changed_in_source, null);
});

test('browse and search share identical platform Timestamp', () => {
  const input = {
    item_created_at: '2026-01-01T00:00:00.000Z',
    first_seen_in_source: '2026-01-10T08:00:00.000Z',
    last_changed_in_source: '2026-06-15T09:30:00.000Z'
  };
  const browse = resolveCanonicalIocTimestamps(input);
  const search = resolveCanonicalIocTimestamps(input);
  assert.equal(browse.imported_at, search.imported_at);
  assert.equal(browse.imported_at, '2026-01-01T00:00:00.000Z');
  assert.equal(browse.last_changed_in_source, search.last_changed_in_source);
});

test('attach loads created_at when omitted and sets imported_at', async () => {
  const db = {
    async query(sql) {
      if (String(sql).includes('FROM ioc_feed_memberships')) {
        return {
          rows: [{
            ioc_item_id: 7,
            first_seen_in_source: '2026-07-26T11:00:00.000Z',
            last_changed_in_source: '2026-07-26T12:00:00.000Z'
          }]
        };
      }
      if (String(sql).includes('FROM ioc_items')) {
        return { rows: [{ id: 7, created_at: '2026-07-26T10:00:00.000Z' }] };
      }
      return { rows: [] };
    }
  };
  const [item] = await attachCanonicalIocListTimestamps(db, [{ id: 7, observable: 'evil.test' }]);
  assert.equal(item.imported_at, '2026-07-26T10:00:00.000Z');
  assert.equal(item.created_at, '2026-07-26T10:00:00.000Z');
  assert.equal(item.last_changed_in_source, '2026-07-26T12:00:00.000Z');
  assert.notEqual(item.imported_at, item.last_changed_in_source);
});

test('multi-membership aggregate SQL is for source-change only', () => {
  assert.match(CANONICAL_LAST_CHANGED_AGG_SQL, /last_changed_in_source/);
  assert.match(CANONICAL_LAST_CHANGED_AGG_SQL, /first_seen_in_feed/);
  assert.equal(CANONICAL_LAST_CHANGED_AGG_SQL.includes('last_seen_in_feed'), false);
  assert.equal(CANONICAL_FIRST_SEEN_AGG_SQL, 'MIN(m.first_seen_in_feed)');
  assert.equal(IOC_LIST_TIMESTAMP_COLUMN.orderBySql, 'ioc_items.created_at DESC');
});

test('null platform Timestamp only when created_at missing', () => {
  const out = resolvePlatformImportTimestamp({});
  assert.equal(out.imported_at, null);
  assert.equal(out.list_timestamp_field, null);
});

test('detail imported_at maps from earliest created_at across rows', () => {
  const out = resolveDetailPlatformImportTimestamp([
    { created_at: '2026-07-26T12:00:00.000Z' },
    { created_at: '2026-07-26T10:00:00.000Z' },
    { created_at: '2026-07-26T11:00:00.000Z' }
  ]);
  assert.equal(out.imported_at, '2026-07-26T10:00:00.000Z');
  assert.equal(out.created_at, '2026-07-26T10:00:00.000Z');
});

test('detail imported_at stays fixed when later rows appear (re-import / multi-source)', () => {
  const first = resolveDetailPlatformImportTimestamp([
    { created_at: '2026-07-26T10:00:00.000Z' }
  ]);
  const afterExtraSource = resolveDetailPlatformImportTimestamp([
    { created_at: '2026-07-26T10:00:00.000Z' },
    { created_at: '2026-07-27T15:00:00.000Z' }
  ]);
  assert.equal(first.imported_at, '2026-07-26T10:00:00.000Z');
  assert.equal(afterExtraSource.imported_at, first.imported_at);
});

test('detail imported_at is null for legacy rows without created_at (no silent fallback)', () => {
  const out = resolveDetailPlatformImportTimestamp([
    { created_at: null },
    { first_seen_at: '2026-01-01T00:00:00.000Z' },
    {}
  ]);
  assert.equal(out.imported_at, null);
  assert.equal(out.created_at, null);
});

test('detail last_confirmed_at uses max last_seen_in_feed only', () => {
  assert.equal(
    resolveDetailLastConfirmedAt([
      { last_seen_in_feed: '2026-07-26T10:00:00.000Z' },
      { last_seen_in_feed: '2026-07-26T12:00:00.000Z', last_changed_in_source: '2026-07-26T11:00:00.000Z' }
    ]),
    '2026-07-26T12:00:00.000Z'
  );
  assert.equal(
    resolveDetailLastConfirmedAt([
      { last_changed_in_source: '2026-07-26T11:00:00.000Z', first_seen_in_feed: '2026-07-26T10:00:00.000Z' }
    ]),
    null
  );
});
