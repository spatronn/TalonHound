import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeVisibleClassifications,
  getEffectiveThreatClassifications,
  getFeedThreatClassifications,
  getSuppressedThreatClassifications,
  buildThreatClassificationModalState,
  buildThreatClassificationSavePayload,
  mergeThreatClassificationModalOptions,
  formatThreatClassificationBadgeLabel
} from './classificationSummary.js';

describe('normalizeVisibleClassifications', () => {
  it('returns empty array for null/undefined input', () => {
    assert.deepEqual(normalizeVisibleClassifications(null), []);
    assert.deepEqual(normalizeVisibleClassifications(undefined), []);
    assert.deepEqual(normalizeVisibleClassifications([]), []);
  });

  it('filters unknown and deduplicates', () => {
    const result = normalizeVisibleClassifications([
      { value: 'unknown', label: 'Unknown' },
      { value: 'malware', label: 'Malware' },
      { value: 'malware', label: 'Malware' }
    ]);
    assert.deepEqual(result.map((x) => x.value), ['malware']);
  });
});

const SUMMARY = {
  analyst_threat_classifications: [{ value: 'malware', label: 'Malware', origin: 'analyst' }],
  feed_threat_classifications: [
    { value: 'malware', label: 'Malware', origin: 'feed', source_name: 'URLhaus' },
    { value: 'dropper_downloader', label: 'Dropper Downloader', origin: 'feed', source_name: 'URLhaus:abuse.ch' }
  ],
  suppressed_threat_classifications: [],
  effective_threat_classifications: [
    { value: 'malware', label: 'Malware', origin: 'feed', origins: ['feed', 'analyst'], source_name: 'URLhaus' },
    { value: 'dropper_downloader', label: 'Dropper Downloader', origin: 'feed', origins: ['feed'], source_name: 'URLhaus:abuse.ch' }
  ],
  feed_intelligence: {
    classifications: [
      { value: 'malware', label: 'Malware', origin: 'feed', source_name: 'URLhaus' },
      { value: 'dropper_downloader', label: 'Dropper Downloader', origin: 'feed', source_name: 'URLhaus:abuse.ch' }
    ]
  }
};

describe('effective classification model', () => {
  it('card shows Malware + Dropper Downloader from effective set', () => {
    assert.deepEqual(
      getEffectiveThreatClassifications(SUMMARY).map((x) => x.value),
      ['malware', 'dropper_downloader']
    );
  });

  it('card badge labels omit Feed/Analyst provenance text', () => {
    const labels = getEffectiveThreatClassifications(SUMMARY).map((c) => formatThreatClassificationBadgeLabel(c));
    assert.deepEqual(labels, ['Malware', 'Dropper Downloader']);
    for (const label of labels) {
      assert.equal(/Feed|Analyst/i.test(label), false);
    }
  });

  it('duplicate effective entry still yields one label without provenance suffix', () => {
    const dual = {
      value: 'malware',
      label: 'Malware',
      origins: ['feed', 'analyst'],
      source_name: 'URLhaus'
    };
    assert.equal(formatThreatClassificationBadgeLabel(dual), 'Malware');
  });

  it('modal opens with both feed classifications checked and editable', () => {
    const state = buildThreatClassificationModalState(SUMMARY);
    assert.ok(state.editableSlugs.includes('malware'));
    assert.ok(state.editableSlugs.includes('dropper_downloader'));
    assert.equal(state.provenanceByValue.dropper_downloader.feed, true);
    assert.equal(state.provenanceByValue.dropper_downloader.suppressed, false);
  });

  it('suppress removes feed classification from card but keeps provenance unchecked', () => {
    const suppressedSummary = {
      ...SUMMARY,
      suppressed_threat_classifications: [
        { value: 'dropper_downloader', label: 'Dropper Downloader', origin: 'suppress' }
      ],
      effective_threat_classifications: [
        { value: 'malware', label: 'Malware', origin: 'feed', origins: ['feed', 'analyst'] }
      ]
    };
    assert.deepEqual(
      getEffectiveThreatClassifications(suppressedSummary).map((x) => x.value),
      ['malware']
    );
    const state = buildThreatClassificationModalState(suppressedSummary);
    assert.ok(!state.editableSlugs.includes('dropper_downloader'));
    assert.equal(state.provenanceByValue.dropper_downloader.suppressed, true);
    assert.equal(state.provenanceByValue.dropper_downloader.feed, true);
  });

  it('unchanged save payload keeps both effective values', () => {
    const state = buildThreatClassificationModalState(SUMMARY);
    const payload = buildThreatClassificationSavePayload(state.editableSlugs);
    // Array#sort() is lexicographic; assert membership/order-independently via sorted copies.
    assert.deepEqual(
      [...payload.effective_threat_classifications].sort(),
      ['dropper_downloader', 'malware']
    );
  });

  it('removing one value only drops that slug from save payload', () => {
    const payload = buildThreatClassificationSavePayload(['malware']);
    assert.deepEqual(payload.threat_classifications, ['malware']);
  });

  it('hydrates by stable value for Command and Control (C2)', () => {
    const summary = {
      effective_threat_classifications: [
        { value: 'command_and_control', label: 'Command and Control (C2)', origin: 'analyst' }
      ],
      analyst_threat_classifications: [
        { value: 'command_and_control', label: 'Command and Control (C2)' }
      ],
      feed_threat_classifications: [],
      suppressed_threat_classifications: []
    };
    const state = buildThreatClassificationModalState(summary);
    assert.deepEqual(state.editableSlugs, ['command_and_control']);
  });

  it('reopening uses current server summary', () => {
    const after = {
      ...SUMMARY,
      suppressed_threat_classifications: [
        { value: 'dropper_downloader', label: 'Dropper Downloader' }
      ],
      effective_threat_classifications: [
        { value: 'malware', label: 'Malware', origin: 'feed' }
      ]
    };
    const second = buildThreatClassificationModalState(after);
    assert.deepEqual(second.editableSlugs, ['malware']);
    assert.equal(second.provenanceByValue.dropper_downloader.suppressed, true);
  });

  it('modal options include feed-only dropper_downloader with Feed provenance', () => {
    const options = mergeThreatClassificationModalOptions(
      [{ value: 'malware', label: 'Malware' }, { value: 'phishing', label: 'Phishing' }],
      SUMMARY
    );
    const md = options.find((o) => o.value === 'dropper_downloader');
    assert.ok(md);
    assert.equal(md.provenance.feed, true);
  });

  it('feed/suppressed helpers read explicit API fields', () => {
    assert.equal(getFeedThreatClassifications(SUMMARY).length, 2);
    assert.equal(getSuppressedThreatClassifications(SUMMARY).length, 0);
  });
});
