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
  BUILTIN_PUBLISHABLE_FEED_KEYS,
  fetchPublishedFeedSourceOptions,
  loadKnownPublishableFeedKeys
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

// fetchPublishedFeedSourceOptions and loadKnownPublishableFeedKeys tests

function makeSourceOptionsPool({ activeCustomFeeds = [], deactivatedCustomFeeds = [], manualSources = [], builtInFeeds = [] } = {}) {
  return {
    query: async (sql) => {
      const s = String(sql);
      // Custom feed source options query (must filter deactivated)
      if (s.includes('INNER JOIN custom_threat_feeds c') && s.includes('c.deactivated_at IS NULL')) {
        return { rows: activeCustomFeeds };
      }
      // loadKnownPublishableFeedKeys custom query (must filter deactivated)
      if (s.includes('JOIN custom_threat_feeds c') && s.includes('c.deactivated_at IS NULL')) {
        return { rows: activeCustomFeeds };
      }
      // built-in integration feeds
      if (s.includes("COALESCE(f.feed_kind, 'built_in') <> 'custom'")) {
        return { rows: builtInFeeds };
      }
      // manual ioc sources
      if (s.includes('FROM ioc_sources') && s.includes('active = TRUE')) {
        return { rows: manualSources };
      }
      return { rows: [] };
    }
  };
}

test('fetchPublishedFeedSourceOptions excludes deactivated custom feeds', async () => {
  const pool = makeSourceOptionsPool({
    activeCustomFeeds: [{ key: 'ctf-active123', name: 'Active Feed', integration_active: true, deactivated_at: null }],
    // deactivatedCustomFeeds: excluded by SQL WHERE c.deactivated_at IS NULL — won't be returned by mock
  });
  const { sources } = await fetchPublishedFeedSourceOptions(pool);
  const customSources = sources.filter((s) => s.type === 'custom');
  assert.equal(customSources.length, 1);
  assert.equal(customSources[0].key, 'ctf-active123');
});

test('fetchPublishedFeedSourceOptions active custom feed has (custom) display suffix', async () => {
  const pool = makeSourceOptionsPool({
    activeCustomFeeds: [{ key: 'ctf-active123', name: 'Active Feed', integration_active: true, deactivated_at: null }]
  });
  const { sources } = await fetchPublishedFeedSourceOptions(pool);
  const src = sources.find((s) => s.key === 'ctf-active123');
  assert.ok(src, 'active custom feed should appear in sources');
  assert.equal(src.display_name, 'Active Feed (custom)');
  assert.equal(src.selectable, true);
});

test('fetchPublishedFeedSourceOptions disabled (not deactivated) custom feed has (custom, disabled) display suffix', async () => {
  const pool = makeSourceOptionsPool({
    activeCustomFeeds: [{ key: 'ctf-disabled123', name: 'Disabled Feed', integration_active: false, deactivated_at: null }]
  });
  const { sources } = await fetchPublishedFeedSourceOptions(pool);
  const src = sources.find((s) => s.key === 'ctf-disabled123');
  assert.ok(src, 'disabled (not deactivated) custom feed should appear in sources');
  assert.equal(src.display_name, 'Disabled Feed (custom, disabled)');
  assert.equal(src.selectable, false);
  assert.equal(src.active, false);
});

test('loadKnownPublishableFeedKeys excludes deactivated custom feeds', async () => {
  const pool = makeSourceOptionsPool({
    activeCustomFeeds: [{ key: 'ctf-active123' }]
    // deactivated feed is NOT returned by the SQL (c.deactivated_at IS NULL filter)
  });
  const known = await loadKnownPublishableFeedKeys(pool);
  assert.equal(known.has('ctf-active123'), true, 'active custom feed key should be known');
  assert.equal(known.has('ctf-deactivated456'), false, 'deactivated custom feed key should not be known');
});

test('display_name does not double-suffix: no (custom) (custom, disabled) pattern', async () => {
  const pool = makeSourceOptionsPool({
    activeCustomFeeds: [{ key: 'ctf-disabled123', name: 'validin-phish-feed-7', integration_active: false, deactivated_at: null }]
  });
  const { sources } = await fetchPublishedFeedSourceOptions(pool);
  const src = sources.find((s) => s.key === 'ctf-disabled123');
  assert.ok(src);
  assert.equal(src.display_name.includes('(custom) (custom'), false, 'display_name must not contain double suffix');
  assert.equal(src.display_name, 'validin-phish-feed-7 (custom, disabled)');
});
