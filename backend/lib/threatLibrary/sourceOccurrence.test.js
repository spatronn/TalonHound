/**
 * Source-span grounding: IPv4 inside a larger DNS token is not standalone.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  candidateHasStandaloneOccurrence,
  isOnlyEmbeddedInDnsHostname,
  isStandaloneObservableSpan,
  inspectSourceOccurrences,
  sourceTextFromDocument
} from './sourceOccurrence.js';

test('span: numeric hostname prefix is not standalone', () => {
  const t = '128.200.178.68.host.secureserver.net';
  assert.equal(isStandaloneObservableSpan(t, 0, '128.200.178.68'.length), false);
});

test('span: punctuation / URL boundaries remain standalone', () => {
  const cases = [
    ['C2 server: 1.2.3.4', '1.2.3.4'],
    ['(1.2.3.4)', '1.2.3.4'],
    ['"1.2.3.4"', '1.2.3.4'],
    ['1.2.3.4,', '1.2.3.4'],
    ['https://1.2.3.4/path', '1.2.3.4'],
    ['IOC: 128.200.178.68', '128.200.178.68']
  ];
  for (const [hay, needle] of cases) {
    const start = hay.indexOf(needle);
    assert.equal(isStandaloneObservableSpan(hay, start, start + needle.length), true, hay);
  }
});

test('inspect: defanged hostname is embedded-only for the IPv4 prefix', () => {
  const src = '128[.]200[.]178[.]68[.]host[.]secureserver[.]net';
  const r = inspectSourceOccurrences(src, 'ip', '128.200.178.68');
  assert.equal(r.total > 0, true);
  assert.equal(r.standalone, 0);
  assert.equal(isOnlyEmbeddedInDnsHostname(src, 'ip', '128.200.178.68'), true);
  assert.equal(candidateHasStandaloneOccurrence(src, 'ip', '128.200.178.68'), false);
});

test('inspect: both standalone IP and hostname keep the IP', () => {
  const src = 'C2 IP: 128[.]200[.]178[.]68\nHost: 128[.]200[.]178[.]68[.]host[.]secureserver[.]net';
  assert.equal(candidateHasStandaloneOccurrence(src, 'ip', '128.200.178.68'), true);
  assert.equal(isOnlyEmbeddedInDnsHostname(src, 'ip', '128.200.178.68'), false);
});

test('inspect: missing value is not treated as embedded', () => {
  assert.equal(isOnlyEmbeddedInDnsHostname('no addresses here', 'ip', '203.0.113.9'), false);
  assert.equal(candidateHasStandaloneOccurrence('no addresses here', 'ip', '203.0.113.9'), false);
});

test('sourceTextFromDocument joins block text only', () => {
  assert.equal(
    sourceTextFromDocument({ blocks: [{ text: 'a' }, { text: 'b' }, {}] }),
    'a\nb\n'
  );
});
