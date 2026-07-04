import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeVisibleClassifications } from './classificationSummary.js';

describe('normalizeVisibleClassifications', () => {
  it('returns empty array for null/undefined input', () => {
    assert.deepEqual(normalizeVisibleClassifications(null), []);
    assert.deepEqual(normalizeVisibleClassifications(undefined), []);
    assert.deepEqual(normalizeVisibleClassifications([]), []);
  });

  it('returns empty array for unknown-only input', () => {
    assert.deepEqual(normalizeVisibleClassifications([{ value: 'unknown', label: 'Unknown' }]), []);
    assert.deepEqual(normalizeVisibleClassifications([{ value: 'UNKNOWN', label: 'Unknown' }]), []);
  });

  it('returns single item for one classification', () => {
    const result = normalizeVisibleClassifications([{ value: 'malware', label: 'Malware' }]);
    assert.equal(result.length, 1);
    assert.equal(result[0].value, 'malware');
    assert.equal(result[0].label, 'Malware');
  });

  it('returns two items for two classifications', () => {
    const result = normalizeVisibleClassifications([
      { value: 'malware', label: 'Malware' },
      { value: 'phishing', label: 'Phishing' }
    ]);
    assert.equal(result.length, 2);
    assert.equal(result[0].value, 'malware');
    assert.equal(result[1].value, 'phishing');
  });

  it('filters unknown from mixed array and returns only real classifications', () => {
    const result = normalizeVisibleClassifications([
      { value: 'unknown', label: 'Unknown' },
      { value: 'malware', label: 'Malware' },
      { value: 'phishing', label: 'Phishing' }
    ]);
    assert.equal(result.length, 2);
    assert.equal(result[0].value, 'malware');
    assert.equal(result[1].value, 'phishing');
  });

  it('deduplicates same value appearing twice', () => {
    const result = normalizeVisibleClassifications([
      { value: 'malware', label: 'Malware' },
      { value: 'malware', label: 'Malware' }
    ]);
    assert.equal(result.length, 1);
    assert.equal(result[0].value, 'malware');
  });

  it('deduplicates case-insensitively', () => {
    const result = normalizeVisibleClassifications([
      { value: 'Malware', label: 'Malware' },
      { value: 'malware', label: 'Malware' }
    ]);
    assert.equal(result.length, 1);
  });

  it('handles plain string items', () => {
    const result = normalizeVisibleClassifications(['malware', 'phishing']);
    assert.equal(result.length, 2);
    assert.equal(result[0].value, 'malware');
    assert.equal(result[0].label, null);
  });

  it('handles plain string unknown correctly', () => {
    const result = normalizeVisibleClassifications(['unknown', 'malware']);
    assert.equal(result.length, 1);
    assert.equal(result[0].value, 'malware');
  });

  it('preserves backend ordering', () => {
    const result = normalizeVisibleClassifications([
      { value: 'phishing', label: 'Phishing' },
      { value: 'malware', label: 'Malware' },
      { value: 'c2', label: 'C2' }
    ]);
    assert.deepEqual(result.map((x) => x.value), ['phishing', 'malware', 'c2']);
  });
});
