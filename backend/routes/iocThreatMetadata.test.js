import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  enrichItemsWithThreatMetadata,
  batchLoadFeedClassifications,
  mergeFeedClassificationsIntoItem,
  buildThreatMetadataFields
} from './iocThreatMetadata.js';

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

describe('buildThreatMetadataFields — details/list parity', () => {
  it('includes legacy column when junction empty + feed tag classifications (URLHaus malware_download case)', async () => {
    const pool = mockPool([
      ['FROM ioc_threat_classifications', []],
      ['FROM ioc_threat_classification_overrides', []]
    ]);
    const row = {
      id: 3137797,
      observable_type: 'url',
      threat_classification: 'malware',
      threat_actor_id: null,
      threat_actor_name: null
    };
    const feedClassifications = [
      {
        value: 'malware_download',
        label: 'Malware Download',
        active: true,
        origin: 'feed',
        source_name: 'URLhaus:abuse.ch'
      }
    ];
    const fields = await buildThreatMetadataFields(pool, row, { feedClassifications });
    const effective = (fields.effective_threat_classifications || []).map((x) => x.value).sort();
    assert.deepEqual(
      effective,
      ['malware', 'malware_download'],
      'details must surface legacy malware + feed malware_download like the list'
    );
    assert.ok(fields.threat_classifications.some((x) => x.value === 'malware'));
    assert.ok(fields.threat_classifications.some((x) => x.value === 'malware_download'));
  });

  it('prefers junction over legacy when junction has rows', async () => {
    const pool = mockPool([
      ['FROM ioc_threat_classifications', [
        { ioc_id: 10, ioc_observable_type: 'url', classification_slug: 'phishing' }
      ]],
      ['FROM ioc_threat_classification_overrides', []]
    ]);
    const row = {
      id: 10,
      observable_type: 'url',
      threat_classification: 'malware',
      threat_actor_id: null,
      threat_actor_name: null
    };
    const fields = await buildThreatMetadataFields(pool, row, {
      feedClassifications: []
    });
    const effective = (fields.effective_threat_classifications || []).map((x) => x.value);
    assert.deepEqual(effective, ['phishing']);
  });

  it('includes multi threat actors from junction (with legacy fallback)', async () => {
    const actorId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    const pool = mockPool([
      ['FROM ioc_threat_classifications', []],
      ['FROM ioc_threat_classification_overrides', []],
      ['FROM ioc_threat_actors', [{
        ioc_id: 11,
        ioc_observable_type: 'ip',
        threat_actor_id: actorId,
        name: 'APT29',
        slug: 'apt29',
        aliases: [],
        active: true
      }]]
    ]);
    const row = {
      id: 11,
      observable_type: 'ip',
      threat_classification: null,
      threat_actor_id: actorId,
      threat_actor_name: 'APT29'
    };
    const fields = await buildThreatMetadataFields(pool, row, { feedClassifications: [] });
    assert.equal(fields.threat_actor_id, actorId);
    assert.equal(fields.threat_actor_name, 'APT29');
    assert.equal(fields.threat_actors.length, 1);
    assert.deepEqual(fields.threat_actor_ids, [actorId]);
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

  it('derives botnet classification from MalwareBazaar signature=Mirai in note', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        {
          ioc_item_id: 20,
          ioc_observable_type: 'sha256',
          source_name: 'MalwareBazaar:abuse.ch',
          category: 'Mirai',
          note: 'Auto-imported from MalwareBazaar CSV | external_id=abc | signature=Mirai | tags=Mirai,elf',
          feed_key: 'malwarebazaar-abusech'
        }
      ]]
    ]);
    const items = [{ id: 20, observable_type: 'sha256' }];
    const map = await batchLoadFeedClassifications(pool, items);
    const key = '20|sha256';
    assert.ok(map.has(key));
    const classes = map.get(key);
    const slugs = classes.map((c) => c.value);
    assert.ok(slugs.includes('botnet'), 'Mirai signature must yield botnet classification');
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
    assert.ok(result.threat_classifications.some((x) => x.value === 'malware'));
    assert.equal(result.effective_threat_classifications.length, 1);
  });

  it('applies suppressions so feed classification is excluded from effective set', () => {
    const item = { id: 1, observable_type: 'url', threat_classifications: [{ value: 'malware', label: 'Malware' }] };
    const feedMap = new Map([
      ['1|url', [{ value: 'malware_download', label: 'Malware Download', origin: 'feed' }]]
    ]);
    const suppressMap = new Map([
      ['1|url', [{ classification_slug: 'malware_download' }]]
    ]);
    const result = mergeFeedClassificationsIntoItem(item, feedMap, suppressMap);
    assert.deepEqual(result.effective_threat_classifications.map((x) => x.value), ['malware']);
    assert.ok(result.suppressed_threat_classifications.some((x) => x.value === 'malware_download'));
  });

  it('appends feed classifications not already in stored list', () => {
    const item = { id: 1, observable_type: 'url', threat_classifications: [{ value: 'malware', label: 'Malware' }] };
    const feedMap = new Map([
      ['1|url', [{ value: 'malware_download', label: 'Malware Download', active: true, origin: 'feed', source_name: 'URLhaus:abuse.ch' }]]
    ]);
    const result = mergeFeedClassificationsIntoItem(item, feedMap);
    const slugs = result.threat_classifications.map((x) => x.value).sort();
    assert.deepEqual(slugs, ['malware', 'malware_download']);
    assert.ok(result.effective_threat_classifications.some((x) => x.value === 'malware_download'));
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

describe('batchLoadFeedClassifications — new feeds', () => {
  it('ThreatFox evidence with category=botnet_cc yields command_and_control', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        {
          ioc_item_id: 30,
          ioc_observable_type: 'domain',
          source_name: 'ThreatFox:abuse.ch',
          category: 'botnet_cc',
          note: 'Auto-imported from ThreatFox API | threat_type=botnet_cc | malware=Mirai | confidence=high',
          feed_key: 'threatfox-abusech'
        }
      ]]
    ]);
    const map = await batchLoadFeedClassifications(pool, [{ id: 30, observable_type: 'domain' }]);
    const key = '30|domain';
    assert.ok(map.has(key), 'should have entry for ThreatFox IOC');
    const slugs = map.get(key).map((c) => c.value);
    assert.ok(slugs.includes('command_and_control'), 'botnet_cc category must yield command_and_control');
  });

  it('PhishTank evidence with category=phishing yields phishing classification', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        {
          ioc_item_id: 31,
          ioc_observable_type: 'url',
          source_name: 'PhishTank:opendns',
          category: 'phishing',
          note: 'Auto-imported from PhishTank online-valid.csv',
          feed_key: 'phishtank-opendnsrr'
        }
      ]]
    ]);
    const map = await batchLoadFeedClassifications(pool, [{ id: 31, observable_type: 'url' }]);
    const key = '31|url';
    assert.ok(map.has(key), 'should have entry for PhishTank IOC');
    const slugs = map.get(key).map((c) => c.value);
    assert.ok(slugs.includes('phishing'), 'PhishTank phishing category must yield phishing classification');
  });

  it('OTX evidence with tags=phishing yields phishing classification', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        {
          ioc_item_id: 32,
          ioc_observable_type: 'url',
          source_name: 'AlienVault OTX',
          category: 'threat-intel',
          note: 'Auto-imported from AlienVault OTX (subscribed pulses) | pulse_id=xyz | tags=phishing,windows',
          feed_key: 'alienvault-otx'
        }
      ]]
    ]);
    const map = await batchLoadFeedClassifications(pool, [{ id: 32, observable_type: 'url' }]);
    const key = '32|url';
    assert.ok(map.has(key), 'should have entry for OTX IOC');
    const slugs = map.get(key).map((c) => c.value);
    assert.ok(slugs.includes('phishing'), 'OTX phishing tag must yield phishing classification');
  });

  it('OTX evidence with only ambiguous tags yields no classifications', async () => {
    const pool = mockPool([
      ['FROM ioc_feed_source_evidence', [
        {
          ioc_item_id: 33,
          ioc_observable_type: 'ip',
          source_name: 'AlienVault OTX',
          category: 'threat-intel',
          note: 'Auto-imported from AlienVault OTX (subscribed pulses) | tags=APT28,russia',
          feed_key: 'alienvault-otx'
        }
      ]]
    ]);
    const map = await batchLoadFeedClassifications(pool, [{ id: 33, observable_type: 'ip' }]);
    // category=threat-intel and tags APT28/russia don't map to any classification slug
    assert.equal(map.has('33|ip'), false, 'ambiguous OTX tags should not produce any feed classification');
  });
});
