import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildFeedKeySourceSql,
  isCustomFeedKey,
  isManualFeedKey,
  formatManualFeedKey,
  parseManualFeedKey,
  extractManualFeedSourceIds,
  filterKnownFeedKeys,
  mergeOrphanPublishedFeedSources,
  BUILTIN_PUBLISHABLE_FEED_KEYS
} from './publishedFeedSources.js';
import { filtersHash } from './feedPublisherService.js';

test('isCustomFeedKey detects ctf- prefix', () => {
  assert.equal(isCustomFeedKey('ctf-abc123def456'), true);
  assert.equal(isCustomFeedKey('urlhaus-abusech'), false);
});

test('isManualFeedKey detects manual: prefix', () => {
  assert.equal(isManualFeedKey('manual:7'), true);
  assert.equal(isManualFeedKey('urlhaus-abusech'), false);
});

test('formatManualFeedKey and parseManualFeedKey round-trip', () => {
  assert.equal(formatManualFeedKey(12), 'manual:12');
  assert.equal(parseManualFeedKey('manual:12'), 12);
  assert.equal(parseManualFeedKey('manual:0'), null);
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

test('buildFeedKeySourceSql includes manual source ioc_source_id clause', () => {
  const params = [];
  const sql = buildFeedKeySourceSql(['manual:7'], params);
  assert.match(sql, /ioc_source_id = ANY/);
  assert.deepEqual(params, [[7]]);
});

test('buildFeedKeySourceSql combines built-in custom and manual with OR', () => {
  const params = [];
  const sql = buildFeedKeySourceSql(['urlhaus-abusech', 'ctf-deadbeefcafe', 'manual:3'], params);
  assert.match(sql, /source_name/);
  assert.match(sql, /ioc_feed_memberships/);
  assert.match(sql, /ioc_source_id = ANY/);
  assert.equal(params.length, 3);
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

test('filtersHash changes when manual source key added', () => {
  const base = {
    ioc_type: 'domain',
    min_confidence: null,
    include_feed_keys: ['urlhaus-abusech'],
    include_tags: null,
    exclude_tags: null,
    exclude_false_positive: true,
    exclude_expired: true,
    max_items: null
  };
  const h1 = filtersHash(base, 'all');
  const h2 = filtersHash({ ...base, include_feed_keys: ['urlhaus-abusech', 'manual:5'] }, 'all');
  assert.notEqual(h1, h2);
});

test('extractManualFeedSourceIds returns numeric ids', () => {
  assert.deepEqual(extractManualFeedSourceIds(['manual:7', 'urlhaus-abusech', 'manual:12']), [7, 12]);
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

test('mergeOrphanPublishedFeedSources adds missing manual source keys', () => {
  const merged = mergeOrphanPublishedFeedSources(
    [{ key: 'manual:1', name: 'Threat-Hunting', type: 'manual_source', active: true, selectable: true }],
    ['manual:1', 'manual:999']
  );
  assert.equal(merged.length, 2);
  assert.equal(merged[1].key, 'manual:999');
  assert.equal(merged[1].type, 'manual_source');
  assert.equal(merged[1].missing, true);
});

test('filterKnownFeedKeys separates valid and missing keys', () => {
  const known = new Set(['manual:1', 'urlhaus-abusech']);
  const { valid, missing } = filterKnownFeedKeys(['manual:1', 'manual:5', 'urlhaus-abusech'], known);
  assert.deepEqual(valid, ['manual:1', 'urlhaus-abusech']);
  assert.deepEqual(missing, ['manual:5']);
});

test('BUILTIN_PUBLISHABLE_FEED_KEYS includes known integration feeds', () => {
  assert.equal(BUILTIN_PUBLISHABLE_FEED_KEYS.has('urlhaus-abusech'), true);
  assert.equal(BUILTIN_PUBLISHABLE_FEED_KEYS.has('ctf-abc'), false);
});
