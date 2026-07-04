import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { enrichItemsWithThreatMetadata } from './iocThreatMetadata.js';

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
