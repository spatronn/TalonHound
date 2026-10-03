import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeIocThreatClassificationSlugs,
  buildMultiThreatClassificationResponseFields,
  diffThreatClassificationSlugs,
  legacyThreatClassificationColumnValue,
  parseThreatClassificationInput,
  isImporterStoredClassification,
  writeLegacyClassificationMirror
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

  it('isImporterStoredClassification: feed row legacy not mirrored by junction', () => {
    assert.equal(
      isImporterStoredClassification(
        { ioc_source_id: null, threat_classification: 'dropper_downloader' },
        []
      ),
      true
    );
  });

  it('isImporterStoredClassification: false when junction already mirrors the legacy value', () => {
    assert.equal(
      isImporterStoredClassification(
        { ioc_source_id: null, threat_classification: 'dropper_downloader' },
        ['dropper_downloader']
      ),
      false
    );
  });

  it('isImporterStoredClassification: false for IOC-source rows', () => {
    assert.equal(
      isImporterStoredClassification(
        { ioc_source_id: 9, threat_classification: 'phishing' },
        []
      ),
      false
    );
  });

  it('writeLegacyClassificationMirror preserves importer-stored feed values', async () => {
    const updates = [];
    const client = {
      query: async (sql) => {
        const s = String(sql);
        if (s.includes('FROM ioc_items')) {
          return { rows: [{ ioc_source_id: null, threat_classification: 'dropper_downloader' }] };
        }
        if (s.includes('FROM ioc_threat_classifications')) {
          return { rows: [{ classification_slug: 'phishing' }] };
        }
        if (s.includes('UPDATE ioc_items')) {
          updates.push(sql);
          return { rows: [] };
        }
        throw new Error(`unexpected: ${s.slice(0, 80)}`);
      }
    };
    const result = await writeLegacyClassificationMirror(client, {
      iocId: 1,
      observableType: 'url',
      slugs: ['phishing']
    });
    assert.equal(result.written, false);
    assert.equal(result.preserved, 'dropper_downloader');
    assert.equal(updates.length, 0);
  });

  it('writeLegacyClassificationMirror updates when legacy is not an importer assertion', async () => {
    const updates = [];
    const client = {
      query: async (sql, params) => {
        const s = String(sql);
        if (s.includes('FROM ioc_items')) {
          return { rows: [{ ioc_source_id: 3, threat_classification: 'unknown' }] };
        }
        if (s.includes('FROM ioc_threat_classifications')) {
          return { rows: [] };
        }
        if (s.includes('UPDATE ioc_items')) {
          updates.push(params);
          return { rows: [] };
        }
        throw new Error(`unexpected: ${s.slice(0, 80)}`);
      }
    };
    const result = await writeLegacyClassificationMirror(client, {
      iocId: 1,
      observableType: 'domain',
      slugs: ['phishing']
    });
    assert.equal(result.written, true);
    assert.deepEqual(updates[0], [1, 'domain', 'phishing']);
  });
});
