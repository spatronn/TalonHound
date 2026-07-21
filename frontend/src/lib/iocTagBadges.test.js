import test from 'node:test';
import assert from 'node:assert/strict';
import { buildIocTagBadges, formatTagSourcesCell } from './iocTagBadges.js';

test('formatTagSourcesCell truncates with +N and full tooltip', () => {
  assert.deepEqual(formatTagSourcesCell(['Manual']), { text: 'Manual', title: 'Manual' });
  assert.deepEqual(
    formatTagSourcesCell(['Manual', 'URLhaus', 'ThreatFox', 'OTX']),
    { text: 'Manual, URLhaus +2', title: 'Manual, URLhaus, ThreatFox, OTX' }
  );
});

test('buildIocTagBadges keeps manual orange priority and dedupes feed sources', () => {
  const { manual, feed, hasTags } = buildIocTagBadges({
    manualTags: [{ id: 1, name: 'mirai' }],
    feedTags: [
      { tag: 'elf', normalized: 'elf', source_name: 'URLhaus abuse.ch' },
      { tag: 'ELF', normalized: 'elf', source_name: 'ThreatFox abuse.ch' },
      { tag: 'Mirai', normalized: 'mirai', source_name: 'URLhaus abuse.ch' }
    ]
  });
  assert.equal(hasTags, true);
  assert.equal(manual.length, 1);
  assert.equal(manual[0].kind, 'manual');
  assert.equal(feed.length, 1);
  assert.equal(feed[0].normalized, 'elf');
  assert.deepEqual(feed[0].sources, ['URLhaus abuse.ch', 'ThreatFox abuse.ch']);
  assert.match(feed[0].title, /URLhaus/);
});

test('buildIocTagBadges hides disabled catalog names from feed badges', () => {
  const { manual, feed } = buildIocTagBadges({
    manualTags: [{ id: 2, name: 'c2', is_active: false }],
    feedTags: [{ tag: 'c2', normalized: 'c2', source_name: 'URLhaus abuse.ch' }],
    disabledTagNames: ['c2']
  });
  assert.equal(manual.length, 0);
  assert.equal(feed.length, 0);
});
