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

test('buildIocTagBadges ignores legacy stored tag.color (origin drives the chip)', () => {
  const { manual, feed } = buildIocTagBadges({
    manualTags: [{ id: 9, name: 'ransomware', color: '#ef4444' }],
    feedTags: [{ tag: 'botnet', normalized: 'botnet', source_name: 'URLhaus abuse.ch', color: '#10b981' }]
  });
  // Manual chips are orange, feed chips blue — decided by kind, never by a stored color.
  assert.equal(manual.length, 1);
  assert.equal(manual[0].kind, 'manual');
  assert.ok(!('color' in manual[0]));
  assert.equal(feed.length, 1);
  assert.equal(feed[0].kind, 'feed');
  assert.ok(!('color' in feed[0]));
});

test('buildIocTagBadges shows Threat Library tags as a separate, provenance-carrying group', () => {
  const reports = [
    { id: 'r-a', title: 'WinPot malware campaign' },
    { id: 'r-b', title: 'ATM jackpotting wave' }
  ];
  const { manual, feed, context, hasTags } = buildIocTagBadges({
    manualTags: [{ id: 1, name: 'clickfix' }],
    contextTags: [{ name: 'winpot', reports }, { name: 'atm', reports: [reports[0]] }]
  });
  assert.equal(hasTags, true);
  assert.deepEqual(manual.map((m) => m.label), ['clickfix']);
  assert.equal(feed.length, 0);
  // Inherited tags are never presented as direct assignments.
  assert.deepEqual(context.map((c) => [c.kind, c.label]), [['threat_library', 'winpot'], ['threat_library', 'atm']]);
  assert.equal(context[0].title, 'Inherited from Threat Library reports: WinPot malware campaign; ATM jackpotting wave');
  assert.equal(context[1].title, 'Inherited from Threat Library report: WinPot malware campaign');
});

test('buildIocTagBadges: direct tag wins over the same inherited tag, which is noted in its tooltip', () => {
  const { manual, context } = buildIocTagBadges({
    manualTags: [{ id: 5, name: 'winpot' }],
    contextTags: [{ name: 'winpot', reports: [{ id: 'r-a', title: 'WinPot malware campaign' }] }]
  });
  assert.equal(manual.length, 1);
  assert.equal(context.length, 0, 'effective tag appears once');
  assert.match(manual[0].title, /^Added by analyst\. Also inherited from Threat Library report: WinPot malware campaign$/);
});

test('buildIocTagBadges: only inherited tags still count as tags', () => {
  const { hasTags, context } = buildIocTagBadges({ contextTags: [{ name: 'atm', reports: [] }] });
  assert.equal(hasTags, true);
  assert.equal(context[0].title, 'Inherited from a Threat Library report');
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
