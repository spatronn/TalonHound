/**
 * Feed tag → classification matching uses one canonical SPELLING token
 * (lowercase, trim, whitespace/hyphen/underscore collapsed) — never a synonym.
 * A tag reaches a classification only when its canonical token is already a
 * mapped key, so this normalization cannot widen what a classification means.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFeedIntelligence, canonicalClassificationToken, normalizeFeedTags } from './feedTagNormalization.js';
import { resolveClassificationFromFeed } from './iocClassificationMapping.js';

const classify = (tag) => normalizeFeedTags({ sourceName: 'AlienVault OTX', rawTags: [tag] }).classifications.map((c) => c.value);

test('spelling variants of already-mapped tags resolve to the same classification', () => {
  const cases = {
    'command-and-control': 'command_and_control',
    'Command and Control': 'command_and_control',
    'command  and_control': 'command_and_control',
    'remote access trojan': 'malware',
    'Remote-Access-Trojan': 'malware',
    'malware download': 'dropper_downloader',
    'malware-delivery': 'dropper_downloader',
    'dropper downloader': 'dropper_downloader'
  };
  for (const [tag, slug] of Object.entries(cases)) {
    assert.deepEqual(classify(tag), [slug], tag);
  }
});

test('no new synonym: information-stealer spellings do NOT become credential_theft', () => {
  for (const tag of ['information stealer', 'information-stealer', 'information_stealer', 'Information  Stealer', 'info stealer', 'info-stealer', 'info_stealer']) {
    assert.deepEqual(classify(tag), [], tag);
  }
});

test('existing HEAD mappings are unchanged (including the pre-existing infostealer → credential_theft)', () => {
  const cases = {
    malware_download: 'dropper_downloader',
    'malware-download': 'dropper_downloader',
    phishing: 'phishing',
    botnet: 'botnet',
    c2: 'command_and_control',
    cnc: 'command_and_control',
    command_and_control: 'command_and_control',
    ransomware: 'ransomware',
    trojan: 'malware',
    rat: 'malware',
    stealer: 'credential_theft',
    infostealer: 'credential_theft',
    InfoStealer: 'credential_theft',
    loader: 'dropper_downloader',
    miner: 'cryptomining'
  };
  for (const [tag, slug] of Object.entries(cases)) {
    assert.deepEqual(classify(tag), [slug], tag);
  }
});

test('no family-name inference and no over-normalization', () => {
  for (const tag of ['vidar', 'vidar stealer', 'lumma stealer', 'metastealer', 'deerstealer', 'stealers', 'info.stealer', 'c2c', '-stealer']) {
    assert.deepEqual(classify(tag), [], tag);
  }
});

test('canonical token: separators collapse, other punctuation is kept', () => {
  assert.equal(canonicalClassificationToken('  Command - and _ Control '), 'command_and_control');
  assert.equal(canonicalClassificationToken('info.stealer'), 'info.stealer');
  assert.equal(canonicalClassificationToken('Info-Stealer'), 'info_stealer');
});

test('persistent import-time mapping is untouched by this change', () => {
  for (const tag of ['infostealer', 'information stealer', 'info-stealer']) {
    assert.equal(resolveClassificationFromFeed('alienvault-otx', tag), null, tag);
  }
  assert.equal(resolveClassificationFromFeed('threatfox-abusech', 'infostealer'), 'malware');
  assert.equal(resolveClassificationFromFeed('alienvault-otx', 'phishing'), 'phishing');
});

test('Vidar OTX note: no feed classification is introduced (taxonomy decision is a separate task)', () => {
  const note =
    'Auto-imported from AlienVault OTX (subscribed pulses) | pulse_id=6ab15f3f1d05b3fb6ae23973 | tlp=white | tags=chacha20,arx cipher,string obfuscation,vidar,custom stream cipher,bytecode interpreter,virtual machine,information stealer | indicator_id=4503147603';
  const intel = buildFeedIntelligence([{ source_name: 'AlienVault OTX', category: 'threat-intel', note }]);
  assert.deepEqual(intel.classifications, []);
  assert.equal(intel.tags.some((t) => t.normalized === 'information stealer'), true);
});
