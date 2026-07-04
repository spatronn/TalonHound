import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { enrichItemsWithThreatMetadata, batchLoadFeedClassifications, mergeFeedClassificationsIntoItem } from './iocThreatMetadata.js';

function mockPool(queryMap) {
  return {
    async query(sql, _params) {
      for (const [pattern, result] of queryMap) {
        if (sql.includes(pattern)) return { rows: result, rowCount: result.length };
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

describe('enrichItemsWithThreatMetadata', () => {
  it('returns correct classifications when ioc_threat_classifications has entries', async () => {
    const pool = mockPool([
      ['FROM ioc_items', [{ id: 1, observable_type: 'sha256', threat_classification: 'malware', threat_actor_id: null, threat_actor_name: null }]],
      ['FROM ioc_threat_classifications', [{ ioc_id: 1, ioc_observable_type: 'sha256', classification_slug: 'malware' }]],
      ['FROM threat_classifications', [{ slug: 'malware', name: 'Malware', active: true, system_default: false }]]
    ]);
    const items = [{ id: 1, observable_type: 'sha256' }];
    const map = await enrichItemsWithThreatMetadata(pool, items);
    const key = '1|sha256';
    assert.ok(map.has(key));
    const entry = map.get(key);
    assert.equal(entry.threat_classification, 'malware');
    const tc = entry.threat_classifications.find((x) => x.value === 'malware');
    assert.ok(tc, 'should have malware classification');
    assert.equal(tc.label, 'Malware');
  });

  it('falls back to threat_classification column when ioc_threat_classifications is empty (bug fix)', async () => {
    const pool = mockPool([
      ['FROM ioc_items', [{ id: 2, observable_type: 'sha256', threat_classification: 'malware', threat_actor_id: null, threat_actor_name: null }]],
      ['FROM ioc_threat_classifications', []],
      ['FROM threat_classifications', []]
    ]);
    const items = [{ id: 2, observable_type: 'sha256' }];
    const map = await enrichItemsWithThreatMetadata(pool, items);
    const key = '2|sha256';
    assert.ok(map.has(key));
    const entry = map.get(key);
    // Before fix this would return 'unknown'; after fix it returns 'malware'
    assert.equal(entry.threat_classification, 'malware', 'list endpoint must use legacy column as fallback');
    const tc = entry.threat_classifications.find((x) => x.value === 'malware');
    assert.ok(tc, 'should surface malware from legacy column');
  });

  it('returns unknown when both ioc_threat_classifications and legacy column are empty', async () => {
    const pool = mockPool([
      ['FROM ioc_items', [{ id: 3, observable_type: 'ip', threat_classification: null, threat_actor_id: null, threat_actor_name: null }]],
      ['FROM ioc_threat_classifications', []],
      ['FROM threat_classifications', []]
    ]);
    const items = [{ id: 3, observable_type: 'ip' }];
    const map = await enrichItemsWithThreatMetadata(pool, items);
    const key = '3|ip';
    assert.ok(map.has(key));
    const entry = map.get(key);
    assert.equal(entry.threat_classification, 'unknown');
    assert.equal(entry.threat_classifications[0].value, 'unknown');
  });

  it('returns empty map for empty items list', async () => {
    const pool = mockPool([]);
    const map = await enrichItemsWithThreatMetadata(pool, []);
    assert.equal(map.size, 0);
  });

  it('correctly handles multiple classifications from junction table', async () => {
    const pool = mockPool([
      ['FROM ioc_items', [{ id: 4, observable_type: 'domain', threat_classification: 'malware', threat_actor_id: null, threat_actor_name: null }]],
      ['FROM ioc_threat_classifications', [
        { ioc_id: 4, ioc_observable_type: 'domain', classification_slug: 'malware' },
        { ioc_id: 4, ioc_observable_type: 'domain', classification_slug: 'phishing' }
      ]],
      ['FROM threat_classifications', [
        { slug: 'malware', name: 'Malware', active: true, system_default: false },
        { slug: 'phishing', name: 'Phishing', active: true, system_default: false }
      ]]
    ]);
    const items = [{ id: 4, observable_type: 'domain' }];
    const map = await enrichItemsWithThreatMetadata(pool, items);
    const key = '4|domain';
    const entry = map.get(key);
    assert.equal(entry.threat_classifications.length, 2);
    const slugs = entry.threat_classifications.map((x) => x.value).sort();
    assert.deepEqual(slugs, ['malware', 'phishing']);
  });
});

describe('batchLoadFeedClassifications', () => {
  it('returns empty map for empty items', async () => {
    const pool = mockPool([]);
    const map = await batchLoadFeedClassifications(pool, []);
    assert.equal(map.size, 0);
  });

  it('returns feed classifications from evidence note tags', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        {
          ioc_item_id: 10,
          ioc_observable_type: 'url',
          source_name: 'URLhaus:abuse.ch',
          category: null,
          note: 'Auto-imported | tags=malware_download,windows',
          feed_key: 'urlhaus-abusech'
        }
      ]],
      ['FROM integration_feeds', []]
    ]);
    const items = [{ id: 10, observable_type: 'url' }];
    const map = await batchLoadFeedClassifications(pool, items);
    const key = '10|url';
    assert.ok(map.has(key));
    const classes = map.get(key);
    const slugs = classes.map((c) => c.value);
    assert.ok(slugs.includes('malware_download'), 'malware_download tag should map to malware_download classification');
  });

  it('returns feed classifications from evidence category', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        {
          ioc_item_id: 11,
          ioc_observable_type: 'domain',
          source_name: 'ThreatFox:abuse.ch',
          category: 'botnet_cc',
          note: '',
          feed_key: 'threatfox-abusech'
        }
      ]]
    ]);
    const items = [{ id: 11, observable_type: 'domain' }];
    const map = await batchLoadFeedClassifications(pool, items);
    const key = '11|domain';
    assert.ok(map.has(key));
    const classes = map.get(key);
    const slugs = classes.map((c) => c.value);
    assert.ok(slugs.includes('command_and_control'));
  });

  it('deduplicates across multiple evidence rows', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        { ioc_item_id: 12, ioc_observable_type: 'url', source_name: 'Feed1', category: null, note: 'tags=malware_download', feed_key: 'feed1' },
        { ioc_item_id: 12, ioc_observable_type: 'url', source_name: 'Feed2', category: null, note: 'tags=malware_download', feed_key: 'feed2' }
      ]]
    ]);
    const items = [{ id: 12, observable_type: 'url' }];
    const map = await batchLoadFeedClassifications(pool, items);
    const classes = map.get('12|url');
    const slugs = classes.map((c) => c.value);
    assert.equal(slugs.filter((s) => s === 'malware_download').length, 1, 'should deduplicate malware_download');
  });
});

describe('mergeFeedClassificationsIntoItem', () => {
  it('returns item unchanged when no feed classifications', () => {
    const item = { id: 1, observable_type: 'url', threat_classifications: [{ value: 'malware', label: 'Malware' }] };
    const feedMap = new Map();
    const result = mergeFeedClassificationsIntoItem(item, feedMap);
    assert.equal(result.threat_classifications.length, 1);
  });

  it('appends feed classifications not already in stored list', () => {
    const item = { id: 1, observable_type: 'url', threat_classifications: [{ value: 'malware', label: 'Malware' }] };
    const feedMap = new Map([
      ['1|url', [{ value: 'malware_download', label: 'Malware Download', active: true, origin: 'feed', source_name: 'URLhaus:abuse.ch' }]]
    ]);
    const result = mergeFeedClassificationsIntoItem(item, feedMap);
    assert.equal(result.threat_classifications.length, 2);
    assert.equal(result.threat_classifications[1].value, 'malware_download');
  });

  it('skips feed classifications already in stored list', () => {
    const item = { id: 1, observable_type: 'url', threat_classifications: [{ value: 'malware', label: 'Malware' }] };
    const feedMap = new Map([
      ['1|url', [{ value: 'malware', label: 'Malware', active: true, origin: 'feed', source_name: 'URLhaus:abuse.ch' }]]
    ]);
    const result = mergeFeedClassificationsIntoItem(item, feedMap);
    assert.equal(result.threat_classifications.length, 1, 'duplicate slug must not be added');
  });

  it('does not mutate original item', () => {
    const orig = [{ value: 'malware', label: 'Malware' }];
    const item = { id: 1, observable_type: 'url', threat_classifications: orig };
    const feedMap = new Map([
      ['1|url', [{ value: 'malware_download', label: 'Malware Download', active: true, origin: 'feed' }]]
    ]);
    mergeFeedClassificationsIntoItem(item, feedMap);
    assert.equal(orig.length, 1, 'original array must not be mutated');
  });
});
