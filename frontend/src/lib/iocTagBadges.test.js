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
  // Report tags are never presented as direct assignments.
  assert.deepEqual(context.map((c) => [c.kind, c.label]), [['threat_library', 'winpot'], ['threat_library', 'atm']]);
  assert.equal(context[0].title, 'Report context from Threat Library reports: WinPot malware campaign; ATM jackpotting wave (not an assertion about this IOC)');
  assert.equal(context[1].title, 'Report context from Threat Library report: WinPot malware campaign (not an assertion about this IOC)');
});

test('buildIocTagBadges: overlap keeps Threat Context chip and annotates the direct badge', () => {
  const { manual, context } = buildIocTagBadges({
    manualTags: [{ id: 5, name: 'winpot' }],
    contextTags: [{ name: 'winpot', reports: [{ id: 'r-a', title: 'WinPot malware campaign' }] }]
  });
  assert.equal(manual.length, 1);
  assert.equal(context.length, 1, 'Threat Context keeps the report tag even when also direct');
  assert.equal(context[0].label, 'winpot');
  assert.equal(context[0].alsoDirect, true);
  assert.match(manual[0].title, /^Added by analyst\. Also report context from Threat Library report: WinPot malware campaign \(not an assertion about this IOC\)$/);
});

test('buildIocTagBadges: only inherited tags still count as tags', () => {
  const { hasTags, context } = buildIocTagBadges({ contextTags: [{ name: 'atm', reports: [] }] });
  assert.equal(hasTags, true);
  assert.equal(context[0].title, 'Report context from a Threat Library report (not an assertion about this IOC)');
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

test('report tags named by the IOC evidence vs report-level context get different, non-"inherited" tooltips', () => {
  const { context } = buildIocTagBadges({
    contextTags: [
      { name: 'clickfix', ioc_evidence: true, reports: [{ id: 'r-a', title: 'ClickFix wave', ioc_evidence: true }] },
      { name: 'data theft', ioc_evidence: false, reports: [{ id: 'r-b', title: 'Joint advisory', ioc_evidence: false }] },
      { name: 'mixed', ioc_evidence: true, reports: [{ id: 'r-a', title: 'ClickFix wave', ioc_evidence: true }, { id: 'r-b', title: 'Joint advisory', ioc_evidence: false }] },
      { name: 'untitled', ioc_evidence: true, reports: [] }
    ]
  });
  assert.equal(context[0].title, 'Named for this IOC in Threat Library report: ClickFix wave');
  assert.equal(context[0].iocEvidence, true);
  assert.equal(context[1].title, 'Report context from Threat Library report: Joint advisory (not an assertion about this IOC)');
  assert.equal(context[1].iocEvidence, false);
  assert.equal(context[2].title, 'Named for this IOC in Threat Library report: ClickFix wave. Report context from Threat Library report: Joint advisory (not an assertion about this IOC)');
  assert.equal(context[3].title, 'Named for this IOC in a Threat Library report');
  for (const c of context) assert.doesNotMatch(c.title, /Inherited/i);
});

test('IOC Details Threat Context group label no longer says "Inherited"', async () => {
  const fs = await import('node:fs');
  const src = fs.readFileSync(new URL('../main.jsx', import.meta.url), 'utf8');
  assert.doesNotMatch(src, /title="Inherited from Threat Library reports linked to this IOC/);
  assert.match(src, /report context unless the report's evidence for this IOC names the tag/);
});

test('buildIocTagBadges: only direct tags → empty Threat Context', () => {
  const { manual, feed, context, hasTags } = buildIocTagBadges({
    manualTags: [{ id: 1, name: 'powershell' }],
    feedTags: [{ tag: 'velvetcake', normalized: 'velvetcake', source_name: 'AlienVault OTX' }]
  });
  assert.equal(hasTags, true);
  assert.deepEqual(manual.map((m) => m.label), ['powershell']);
  assert.deepEqual(feed.map((f) => f.label), ['velvetcake']);
  assert.equal(context.length, 0);
});

test('buildIocTagBadges: only Threat Library context tags → Tags empty of direct, Threat Context full', () => {
  const { manual, feed, context } = buildIocTagBadges({
    contextTags: [
      { name: 'credential theft', reports: [{ id: 'r1', title: 'Report A' }] },
      { name: 'cyber espionage', reports: [{ id: 'r1', title: 'Report A' }] }
    ]
  });
  assert.equal(manual.length, 0);
  assert.equal(feed.length, 0);
  assert.deepEqual(context.map((c) => c.label), ['credential theft', 'cyber espionage']);
});

test('buildIocTagBadges: Kimsuky GitPower regression — all five report tags stay in Threat Context', () => {
  const report = {
    id: '2a34bdea-dd53-4549-b45d-55c32510738a',
    title: 'Kimsuky’s Operation GitPower Targeting Ukraine Behind the Front Lines of Russia’s War'
  };
  const reportTags = [
    'credential theft',
    'cyber espionage',
    'social engineering',
    'spear-phishing',
    'ukraine targeting'
  ];
  const { feed, context } = buildIocTagBadges({
    feedTags: [
      { tag: 'operation conflict compass', normalized: 'operation conflict compass', source_name: 'AlienVault OTX' },
      { tag: 'scheduled tasks', normalized: 'scheduled tasks', source_name: 'AlienVault OTX' },
      { tag: 'ukraine targeting', normalized: 'ukraine targeting', source_name: 'AlienVault OTX' },
      { tag: 'lnk files', normalized: 'lnk files', source_name: 'AlienVault OTX' },
      { tag: 'north korea', normalized: 'north korea', source_name: 'AlienVault OTX' },
      { tag: 'spear-phishing', normalized: 'spear-phishing', source_name: 'AlienVault OTX' },
      { tag: 'velvetcake', normalized: 'velvetcake', source_name: 'AlienVault OTX' },
      { tag: 'powershell', normalized: 'powershell', source_name: 'AlienVault OTX' }
    ],
    contextTags: reportTags.map((name) => ({ name, ioc_evidence: false, reports: [report] }))
  });
  assert.deepEqual(context.map((c) => c.label), reportTags);
  assert.equal(context.length, new Set(context.map((c) => c.normalized)).size, 'no duplicate chips in Threat Context');
  for (const slug of ['spear-phishing', 'ukraine targeting']) {
    const chip = context.find((c) => c.normalized === slug);
    assert.ok(chip, `${slug} must remain discoverable as Threat Library context`);
    assert.equal(chip.alsoDirect, true);
    const direct = feed.find((f) => f.normalized === slug);
    assert.ok(direct, `${slug} remains a direct feed tag`);
    assert.match(direct.title, /Also report context from Threat Library report/);
  }
  for (const slug of ['credential theft', 'cyber espionage', 'social engineering']) {
    assert.equal(context.find((c) => c.normalized === slug)?.alsoDirect, false);
  }
  assert.ok(feed.some((f) => f.normalized === 'powershell'));
  assert.ok(feed.some((f) => f.normalized === 'velvetcake'));
});

test('buildIocTagBadges: multi-report union with overlapping + unique slugs', () => {
  const { manual, context } = buildIocTagBadges({
    manualTags: [{ id: 1, name: 'spear-phishing' }, { id: 2, name: 'powershell' }],
    contextTags: [
      {
        name: 'spear-phishing',
        reports: [
          { id: 'a', title: 'Report A' },
          { id: 'b', title: 'Report B' }
        ]
      },
      { name: 'credential theft', reports: [{ id: 'a', title: 'Report A' }] },
      { name: 'north korea', reports: [{ id: 'b', title: 'Report B' }] },
      // Duplicate slug entry (defensive merge) must not create a second chip.
      { name: 'spear-phishing', reports: [{ id: 'b', title: 'Report B' }] }
    ]
  });
  assert.deepEqual(manual.map((m) => m.label).sort(), ['powershell', 'spear-phishing']);
  assert.deepEqual(context.map((c) => c.label).sort(), ['credential theft', 'north korea', 'spear-phishing']);
  const spear = context.find((c) => c.normalized === 'spear-phishing');
  assert.deepEqual(spear.reports.map((r) => r.id).sort(), ['a', 'b']);
  assert.equal(spear.alsoDirect, true);
  assert.match(manual.find((m) => m.normalized === 'spear-phishing').title, /Report A/);
  assert.match(manual.find((m) => m.normalized === 'spear-phishing').title, /Report B/);
});

test('buildIocTagBadges: analyst-added tags unchanged when Threat Context overlaps', () => {
  const { manual, context } = buildIocTagBadges({
    manualTags: [{ id: 9, name: 'spear-phishing' }],
    contextTags: [{ name: 'spear-phishing', reports: [{ id: 'r', title: 'R' }] }]
  });
  assert.equal(manual[0].id, 9);
  assert.equal(manual[0].kind, 'manual');
  assert.equal(manual[0].label, 'spear-phishing');
  assert.equal(context[0].label, 'spear-phishing');
});

test('buildIocTagBadges: Threat Context ordering follows input (deterministic)', () => {
  const names = ['ukraine targeting', 'credential theft', 'spear-phishing'];
  const { context } = buildIocTagBadges({
    contextTags: names.map((name) => ({ name, reports: [{ id: 'r', title: 'R' }] }))
  });
  assert.deepEqual(context.map((c) => c.label), names);
});

test('buildIocTagBadges: non-Threat-Library feed tags unaffected by empty context', () => {
  const { feed, context } = buildIocTagBadges({
    feedTags: [
      { tag: 'mirai', normalized: 'mirai', source_name: 'URLhaus abuse.ch' },
      { tag: 'c2', normalized: 'c2', source_name: 'ThreatFox abuse.ch' }
    ],
    contextTags: []
  });
  assert.deepEqual(feed.map((f) => f.normalized).sort(), ['c2', 'mirai']);
  assert.equal(context.length, 0);
});
