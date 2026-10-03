import test from 'node:test';
import assert from 'node:assert/strict';
import { planThreatClassificationEffectiveSave } from './iocThreatClassificationOverrides.js';
import { computeCanonicalIocClassifications } from './iocCanonicalClassifications.js';

const FEED = [
  { value: 'malware', label: 'Malware', origin: 'feed', source_name: 'URLhaus', source_names: ['URLhaus'] },
  { value: 'dropper_downloader', label: 'Dropper Downloader', origin: 'feed', source_name: 'URLhaus:abuse.ch', source_names: ['URLhaus:abuse.ch'] }
];

function fromParts({ feedClassifications = [], analystAdditionSlugs = [], activeSuppressions = [] } = {}) {
  return computeCanonicalIocClassifications({
    rows: [{
      feed: feedClassifications,
      junction: analystAdditionSlugs.map((slug) => ({ slug, source_type: 'analyst' })),
      suppressions: activeSuppressions
    }]
  });
}

test('effective keeps feed minus suppressions plus analyst adds', () => {
  const computed = fromParts({
    feedClassifications: FEED,
    analystAdditionSlugs: ['phishing'],
    activeSuppressions: [{ classification_slug: 'dropper_downloader' }]
  });
  assert.deepEqual(computed.classifications, ['malware', 'phishing']);
  assert.equal(computed.feed.length, 2);
  assert.equal(computed.suppressions[0].classification_slug, 'dropper_downloader');
});

test('duplicate feed+analyst addition shows once with dual origin', () => {
  const computed = fromParts({
    feedClassifications: FEED,
    analystAdditionSlugs: ['malware'],
    activeSuppressions: []
  });
  assert.equal(computed.classifications.length, 2);
  const malware = computed.classification_context.find((x) => x.classification === 'malware');
  assert.deepEqual(
    malware.sources.map((s) => s.type).sort(),
    ['analyst', 'feed']
  );
});

test('plan save: unchecking feed creates suppress and keeps feed out of additions', () => {
  const planned = planThreatClassificationEffectiveSave({
    desiredEffectiveSlugs: ['malware'],
    feedClassifications: FEED
  });
  assert.deepEqual(planned.additions, []);
  assert.deepEqual(planned.suppressions, ['dropper_downloader']);
});

test('plan save: checking new analyst slug creates addition only', () => {
  const planned = planThreatClassificationEffectiveSave({
    desiredEffectiveSlugs: ['malware', 'dropper_downloader', 'phishing'],
    feedClassifications: FEED
  });
  assert.deepEqual(planned.additions, ['phishing']);
  assert.deepEqual(planned.suppressions, []);
});

test('plan save: restoring previously suppressed feed clears suppress list', () => {
  const planned = planThreatClassificationEffectiveSave({
    desiredEffectiveSlugs: ['malware', 'dropper_downloader'],
    feedClassifications: FEED
  });
  assert.deepEqual(planned.suppressions, []);
  assert.deepEqual(planned.additions, []);
});

test('suppression of missing feed slug is stale-safe in compute (no crash)', () => {
  const computed = fromParts({
    feedClassifications: [{ value: 'malware', label: 'Malware', origin: 'feed', source_names: [] }],
    analystAdditionSlugs: [],
    activeSuppressions: [{ classification_slug: 'dropper_downloader', created_at: '2026-01-01' }]
  });
  assert.deepEqual(computed.classifications, ['malware']);
  assert.equal(computed.suppressions[0].classification_slug, 'dropper_downloader');
});
