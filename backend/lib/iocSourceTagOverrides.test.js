import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applySourceTagOverrides,
  feedTagsIncludeSourceTag,
  normalizeSourceTagKey
} from './iocSourceTagOverrides.js';
import { buildFeedIntelligence } from './feedTagNormalization.js';

test('applySourceTagOverrides hides only matching tag+source', () => {
  const fi = {
    tags: [
      { tag: 'SmartLoader', normalized: 'smartloader', origin: 'feed', source_name: 'URLhaus abuse.ch' },
      { tag: 'SmartLoader', normalized: 'smartloader', origin: 'feed', source_name: 'ThreatFox' },
      { tag: 'LuaJIT-loader', normalized: 'luajit-loader', origin: 'feed', source_name: 'URLhaus abuse.ch' }
    ],
    classifications: [],
    source_metadata: []
  };

  const filtered = applySourceTagOverrides(fi, [
    { tag_normalized: 'smartloader', source_name: 'URLhaus abuse.ch' }
  ]);

  assert.equal(filtered.tags.length, 2);
  assert.ok(filtered.tags.some((t) => t.source_name === 'ThreatFox' && t.normalized === 'smartloader'));
  assert.ok(filtered.tags.some((t) => t.normalized === 'luajit-loader'));
  assert.ok(!filtered.tags.some((t) => t.source_name === 'URLhaus abuse.ch' && t.normalized === 'smartloader'));
});

test('applySourceTagOverrides is no-op without overrides', () => {
  const fi = {
    tags: [{ tag: 'elf', normalized: 'elf', source_name: 'URLHaus' }],
    classifications: [{ value: 'botnet' }]
  };
  const filtered = applySourceTagOverrides(fi, []);
  assert.equal(filtered.tags.length, 1);
  assert.equal(filtered.classifications.length, 1);
});

test('feedTagsIncludeSourceTag matches case-insensitively on tag', () => {
  const tags = [{ tag: 'SmartLoader', normalized: 'smartloader', source_name: 'URLhaus abuse.ch' }];
  assert.equal(feedTagsIncludeSourceTag(tags, 'smartloader', 'URLhaus abuse.ch'), true);
  assert.equal(feedTagsIncludeSourceTag(tags, 'SmartLoader', 'ThreatFox'), false);
});

test('buildFeedIntelligence + override keeps other IOC unaffected conceptually', () => {
  const evidence = [{
    source_name: 'URLhaus abuse.ch',
    note: 'Auto | tags=SmartLoader,elf'
  }];
  const fi = buildFeedIntelligence(evidence);
  const hiddenForIoc1 = applySourceTagOverrides(fi, [
    { tag_normalized: 'smartloader', source_name: 'URLhaus abuse.ch' }
  ]);
  const forIoc2 = applySourceTagOverrides(fi, []);
  assert.ok(!hiddenForIoc1.tags.some((t) => t.normalized === 'smartloader'));
  assert.ok(forIoc2.tags.some((t) => t.normalized === 'smartloader'));
  assert.equal(normalizeSourceTagKey('SmartLoader'), 'smartloader');
});
