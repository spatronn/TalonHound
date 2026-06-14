import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeIocThreatClassificationSlugs,
  buildMultiThreatClassificationResponseFields,
  diffThreatClassificationSlugs,
  legacyThreatClassificationColumnValue,
  parseThreatClassificationInput
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
    assert.deepEqual(parseThreatClassificationInput('phishing, command_and_control'), ['phishing', ' command_and_control']);
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
});
