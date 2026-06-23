import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildFeedKeySourceSql,
  isCustomFeedKey,
  mergeOrphanPublishedFeedSources,
  BUILTIN_PUBLISHABLE_FEED_KEYS
} from './publishedFeedSources.js';
import { filtersHash } from './feedPublisherService.js';

test('isCustomFeedKey detects ctf- prefix', () => {
  assert.equal(isCustomFeedKey('ctf-abc123def456'), true);
  assert.equal(isCustomFeedKey('urlhaus-abusech'), false);
});

test('buildFeedKeySourceSql includes built-in source_name rule', () => {
  const params = [];
  const sql = buildFeedKeySourceSql(['urlhaus-abusech'], params);
  assert.match(sql, /source_name/);
  assert.deepEqual(params, ['URLhaus:abuse.ch']);
});

test('buildFeedKeySourceSql includes custom feed membership exists clause', () => {
  const params = [];
  const sql = buildFeedKeySourceSql(['ctf-abc123def456'], params);
  assert.match(sql, /ioc_feed_memberships/);
  assert.match(sql, /integration_feeds/);
  assert.deepEqual(params, [['ctf-abc123def456']]);
});

test('buildFeedKeySourceSql combines built-in and custom with OR', () => {
  const params = [];
  const sql = buildFeedKeySourceSql(['urlhaus-abusech', 'ctf-deadbeefcafe'], params);
  assert.match(sql, /source_name/);
  assert.match(sql, /ioc_feed_memberships/);
  assert.equal(params.length, 2);
});

test('buildFeedKeySourceSql empty for unknown non-custom keys only', () => {
  const params = [];
  const sql = buildFeedKeySourceSql(['not-a-real-feed-key'], params);
  assert.equal(sql, '');
});

test('filtersHash changes when custom feed key added', () => {
  const base = {
    ioc_type: 'ip',
    min_confidence: null,
    include_feed_keys: ['urlhaus-abusech'],
    include_tags: null,
    exclude_tags: null,
    exclude_false_positive: true,
    exclude_expired: true,
    max_items: null
  };
  const h1 = filtersHash(base, 'all');
  const h2 = filtersHash({ ...base, include_feed_keys: ['urlhaus-abusech', 'ctf-abc123'] }, 'all');
  assert.notEqual(h1, h2);
});

test('mergeOrphanPublishedFeedSources adds missing selected keys', () => {
  const merged = mergeOrphanPublishedFeedSources(
    [{ key: 'urlhaus-abusech', name: 'URLHaus', type: 'integration', active: true, selectable: true }],
    ['urlhaus-abusech', 'ctf-missing123']
  );
  assert.equal(merged.length, 2);
  assert.equal(merged[1].key, 'ctf-missing123');
  assert.equal(merged[1].missing, true);
  assert.equal(merged[1].selectable, false);
});

test('BUILTIN_PUBLISHABLE_FEED_KEYS includes known integration feeds', () => {
  assert.equal(BUILTIN_PUBLISHABLE_FEED_KEYS.has('urlhaus-abusech'), true);
  assert.equal(BUILTIN_PUBLISHABLE_FEED_KEYS.has('ctf-abc'), false);
});
