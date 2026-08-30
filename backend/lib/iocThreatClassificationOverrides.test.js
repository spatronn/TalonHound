import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeEffectiveThreatClassifications,
  planThreatClassificationEffectiveSave
} from './iocThreatClassificationOverrides.js';

const FEED = [
  { value: 'malware', label: 'Malware', origin: 'feed', source_name: 'URLhaus' },
  { value: 'dropper_downloader', label: 'Dropper Downloader', origin: 'feed', source_name: 'URLhaus:abuse.ch' }
];

test('effective keeps feed minus suppressions plus analyst adds', () => {
  const computed = computeEffectiveThreatClassifications({
    feedClassifications: FEED,
    analystAdditionSlugs: ['phishing'],
    activeSuppressions: [{ classification_slug: 'dropper_downloader' }]
  });
  assert.deepEqual(
    computed.effective_threat_classifications.map((x) => x.value),
    ['malware', 'phishing']
  );
  assert.equal(computed.feed_classifications.length, 2);
  assert.equal(computed.analyst_suppressions[0].value, 'dropper_downloader');
});

test('duplicate feed+analyst addition shows once with dual origin', () => {
  const computed = computeEffectiveThreatClassifications({
    feedClassifications: FEED,
    analystAdditionSlugs: ['malware'],
    activeSuppressions: []
  });
  assert.equal(computed.effective_threat_classifications.length, 2);
  const malware = computed.effective_threat_classifications.find((x) => x.value === 'malware');
  assert.deepEqual(malware.origins.sort(), ['analyst', 'feed']);
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
  const computed = computeEffectiveThreatClassifications({
    feedClassifications: [{ value: 'malware', label: 'Malware', origin: 'feed' }],
    analystAdditionSlugs: [],
    activeSuppressions: [{ classification_slug: 'dropper_downloader', created_at: '2026-01-01' }]
  });
  assert.deepEqual(computed.effective_threat_classifications.map((x) => x.value), ['malware']);
  assert.equal(computed.analyst_suppressions[0].value, 'dropper_downloader');
});
