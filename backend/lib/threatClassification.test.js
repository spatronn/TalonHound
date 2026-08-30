import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeClassificationSlug,
  normalizeThreatClassificationSlugInput,
  buildThreatClassificationResponseFields,
  UNKNOWN_THREAT_CLASSIFICATION
} from './threatClassification.js';

describe('threatClassification slug normalization', () => {
  it('normalizes legacy c2 to command_and_control', () => {
    assert.equal(normalizeClassificationSlug('c2'), 'command_and_control');
    assert.equal(normalizeClassificationSlug('C2'), 'command_and_control');
  });

  it('normalizes legacy feed aliases to canonical dictionary slugs', () => {
    assert.equal(normalizeClassificationSlug('malware_download'), 'dropper_downloader');
    assert.equal(normalizeClassificationSlug('phish'), 'phishing');
    assert.equal(normalizeClassificationSlug('cc'), 'command_and_control');
    assert.equal(normalizeClassificationSlug('recon'), 'scanner_recon');
  });

  it('does not fuzzy-match ambiguous values', () => {
    // Slug-shaped unknowns pass through for dictionary validation; they are not
    // remapped to nearby canonical classifications.
    assert.equal(normalizeClassificationSlug('malicious'), 'malicious');
    assert.notEqual(normalizeClassificationSlug('malicious'), 'malware');
    assert.equal(normalizeClassificationSlug('apt28'), 'apt28');
    assert.notEqual(normalizeClassificationSlug('apt28'), 'phishing');
  });

  it('returns unknown for invalid values', () => {
    assert.equal(normalizeClassificationSlug('!!!'), 'unknown');
    assert.equal(normalizeClassificationSlug(null), 'unknown');
    assert.equal(normalizeClassificationSlug(''), 'unknown');
  });

  it('normalizes slug input for admin forms', () => {
    assert.equal(normalizeThreatClassificationSlugInput('Command and Control'), 'command_and_control');
    assert.equal(normalizeThreatClassificationSlugInput('Exploit / Exploitation'), 'exploit___exploitation');
  });

  it('builds response fields with row label when provided', () => {
    const fields = buildThreatClassificationResponseFields({
      threat_classification: 'exploit',
      threat_classification_label: 'Exploit',
      threat_classification_active: true
    });
    assert.equal(fields.threat_classification, 'exploit');
    assert.equal(fields.threat_classification_label, 'Exploit');
    assert.equal(fields.threat_classification_active, true);
    assert.equal(fields.primary_threat_classification, 'exploit');
  });

  it('defaults unknown slug label', () => {
    const fields = buildThreatClassificationResponseFields(UNKNOWN_THREAT_CLASSIFICATION);
    assert.equal(fields.threat_classification, 'unknown');
    assert.equal(fields.threat_classification_label, 'Unknown');
  });
});
