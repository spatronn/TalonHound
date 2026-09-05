import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeIocThreatClassificationSlugs,
  buildMultiThreatClassificationResponseFields,
  diffThreatClassificationSlugs,
  legacyThreatClassificationColumnValue,
  parseThreatClassificationInput,
  loadEffectiveIocClassificationSlugsBatch,
  iocPairKey
} from './iocThreatClassifications.js';

describe('iocThreatClassifications', () => {
  it('removes unknown when other slugs present', () => {
    assert.deepEqual(
      normalizeIocThreatClassificationSlugs(['unknown', 'phishing', 'phishing']),
      ['phishing']
    );
  });

  it('returns empty array for unknown-only selection', () => {
    assert.deepEqual(normalizeIocThreatClassificationSlugs(['unknown']), []);
    assert.deepEqual(normalizeIocThreatClassificationSlugs([]), []);
  });

  it('parses comma-separated input', () => {
    assert.deepEqual(parseThreatClassificationInput('phishing, command_and_control'), ['phishing', 'command_and_control']);
  });

  it('builds unknown fallback response when empty', () => {
    const fields = buildMultiThreatClassificationResponseFields([]);
    assert.equal(fields.threat_classification, 'unknown');
    assert.equal(fields.threat_classifications.length, 1);
    assert.equal(fields.threat_classifications[0].value, 'unknown');
  });

  it('syncs legacy column to first slug or unknown', () => {
    assert.equal(legacyThreatClassificationColumnValue(['phishing', 'malware']), 'phishing');
    assert.equal(legacyThreatClassificationColumnValue([]), 'unknown');
  });

  it('diffs added and removed slugs', () => {
    const diff = diffThreatClassificationSlugs(['phishing'], ['phishing', 'command_and_control']);
    assert.deepEqual(diff.added, ['command_and_control']);
    assert.deepEqual(diff.removed, []);
  });

  it('loadEffectiveIocClassificationSlugsBatch: junction-then-legacy in one junction query', async () => {
    const junctionRows = [
      { ioc_id: 1, ioc_observable_type: 'domain', classification_slug: 'command_and_control' }
    ];
    let junctionQueries = 0;
    let iocItemsReads = 0;
    const pool = {
      query: async (sql) => {
        const n = String(sql).replace(/\s+/g, ' ');
        if (/FROM ioc_threat_classifications/i.test(n)) { junctionQueries += 1; return { rows: junctionRows }; }
        if (/FROM ioc_items/i.test(n)) { iocItemsReads += 1; return { rows: [] }; }
        return { rows: [] };
      }
    };
    const rows = [
      { id: 1, observable_type: 'domain', threat_classification: 'unknown' }, // junction wins
      { id: 2, observable_type: 'md5', threat_classification: 'dropper_downloader' }, // legacy
      { id: 3, observable_type: 'ip', threat_classification: 'unknown' } // neither -> []
    ];
    const map = await loadEffectiveIocClassificationSlugsBatch(pool, rows);
    assert.deepEqual(map.get(iocPairKey(1, 'domain')), ['command_and_control']);
    assert.deepEqual(map.get(iocPairKey(2, 'md5')), ['dropper_downloader']);
    assert.deepEqual(map.get(iocPairKey(3, 'ip')), []);
    assert.equal(junctionQueries, 1, 'exactly one batched junction query for the whole batch');
    assert.equal(iocItemsReads, 0, 'no per-IOC legacy re-read (uses provided threat_classification)');
  });

  it('loadEffectiveIocClassificationSlugsBatch: empty input issues no query', async () => {
    let called = 0;
    const pool = { query: async () => { called += 1; return { rows: [] }; } };
    const map = await loadEffectiveIocClassificationSlugsBatch(pool, []);
    assert.equal(map.size, 0);
    assert.equal(called, 0);
  });
});
