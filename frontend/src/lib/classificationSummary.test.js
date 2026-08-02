import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeVisibleClassifications,
  getAnalystThreatClassifications,
  getFeedOnlyThreatClassifications,
  getDisplayedThreatClassifications,
  editableThreatClassificationSlugs,
  buildThreatClassificationModalState,
  buildThreatClassificationSavePayload
} from './classificationSummary.js';

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

const MALWARE_DOWNLOAD_SUMMARY = {
  threat_classifications: [
    { value: 'malware', label: 'Malware', active: true }
  ],
  feed_intelligence: {
    classifications: [
      { value: 'malware', label: 'Malware', origin: 'feed', source_name: 'URLhaus' },
      {
        value: 'malware_download',
        label: 'Malware Download',
        origin: 'feed',
        source_name: 'URLhaus:abuse.ch'
      }
    ]
  }
};

describe('analyst vs feed classification split', () => {
  it('card display keeps Malware + Malware Download', () => {
    const displayed = getDisplayedThreatClassifications(MALWARE_DOWNLOAD_SUMMARY);
    assert.deepEqual(displayed.map((x) => x.value), ['malware', 'malware_download']);
  });

  it('editable slugs are analyst-only (Malware)', () => {
    assert.deepEqual(editableThreatClassificationSlugs(MALWARE_DOWNLOAD_SUMMARY), ['malware']);
    assert.deepEqual(
      getAnalystThreatClassifications(MALWARE_DOWNLOAD_SUMMARY).map((x) => x.value),
      ['malware']
    );
  });

  it('feed-only list exposes Malware Download as source-provided', () => {
    const feedOnly = getFeedOnlyThreatClassifications(MALWARE_DOWNLOAD_SUMMARY);
    assert.equal(feedOnly.length, 1);
    assert.equal(feedOnly[0].value, 'malware_download');
    assert.equal(feedOnly[0].label, 'Malware Download');
    assert.equal(feedOnly[0].origin, 'feed');
    assert.equal(feedOnly[0].source_name, 'URLhaus:abuse.ch');
  });
});

describe('buildThreatClassificationModalState', () => {
  it('opens with Malware checked and Malware Download present as feed-only', () => {
    const state = buildThreatClassificationModalState(MALWARE_DOWNLOAD_SUMMARY);
    assert.deepEqual(state.editableSlugs, ['malware']);
    assert.ok(state.presentValues.includes('malware'));
    assert.ok(state.presentValues.includes('malware_download'));
    assert.equal(state.feedOnly[0].value, 'malware_download');
  });

  it('hydrates by stable value key for labels like Command and Control (C2)', () => {
    const summary = {
      threat_classifications: [
        { value: 'command_and_control', label: 'Command and Control (C2)' },
        { value: 'malware_download', label: 'Malware Download' }
      ],
      feed_intelligence: { classifications: [] }
    };
    const state = buildThreatClassificationModalState(summary);
    assert.deepEqual(state.editableSlugs, ['command_and_control', 'malware_download']);
    assert.equal(state.feedOnly.length, 0);
  });

  it('reopening uses current server summary (stale prior draft not reused)', () => {
    const afterRemove = {
      threat_classifications: [{ value: 'malware', label: 'Malware' }],
      feed_intelligence: {
        classifications: [
          { value: 'malware_download', label: 'Malware Download', origin: 'feed', source_name: 'URLhaus' }
        ]
      }
    };
    const first = buildThreatClassificationModalState(MALWARE_DOWNLOAD_SUMMARY);
    const second = buildThreatClassificationModalState(afterRemove);
    assert.deepEqual(first.editableSlugs, ['malware']);
    assert.deepEqual(second.editableSlugs, ['malware']);
    assert.deepEqual(second.feedOnly.map((x) => x.value), ['malware_download']);
    assert.notEqual(first, second);
  });
});

describe('buildThreatClassificationSavePayload', () => {
  it('unchanged save keeps analyst set and does not drop feed-only from card model', () => {
    const state = buildThreatClassificationModalState(MALWARE_DOWNLOAD_SUMMARY);
    const payload = buildThreatClassificationSavePayload(state.editableSlugs);
    assert.deepEqual(payload.threat_classifications, ['malware']);
    // Feed-only remains outside the save payload but still displayed via feed_intelligence
    const afterSaveCard = getDisplayedThreatClassifications({
      threat_classifications: payload.threat_classifications.map((value) => ({ value, label: value })),
      feed_intelligence: MALWARE_DOWNLOAD_SUMMARY.feed_intelligence
    });
    assert.deepEqual(afterSaveCard.map((x) => x.value), ['malware', 'malware_download']);
  });

  it('removing one analyst classification only drops that slug', () => {
    const summary = {
      threat_classifications: [
        { value: 'malware', label: 'Malware' },
        { value: 'phishing', label: 'Phishing' }
      ],
      feed_intelligence: {
        classifications: [
          { value: 'malware_download', label: 'Malware Download', origin: 'feed', source_name: 'URLhaus' }
        ]
      }
    };
    const payload = buildThreatClassificationSavePayload(['malware']);
    assert.deepEqual(payload.classifications, ['malware']);
    assert.deepEqual(payload.threat_classifications, ['malware']);
    const card = getDisplayedThreatClassifications({
      threat_classifications: [{ value: 'malware', label: 'Malware' }],
      feed_intelligence: summary.feed_intelligence
    });
    assert.deepEqual(card.map((x) => x.value), ['malware', 'malware_download']);
  });

  it('filters unknown and deduplicates draft slugs', () => {
    assert.deepEqual(
      buildThreatClassificationSavePayload(['malware', 'unknown', 'malware', '']).threat_classifications,
      ['malware']
    );
  });
});
