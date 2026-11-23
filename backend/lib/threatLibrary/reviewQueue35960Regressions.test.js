/**
 * Review queue 35960–35985 (tl-candidates-v74): defects found auditing the 26
 * Need Review reports (24 HivePro advisories + Securelist + Rapid7) against
 * their publisher pages.
 *
 * A. 35960 / 35968 (HivePro ransomware advisories): the IoC table ends with a
 *    "Recent Breaches | https://www.victim.example …" row (or a "Recent
 *    breaches" sub-table with a "Victim sites" row) listing leak-site victims'
 *    websites. Every victim URL became a malicious Indicator.
 * B. 35967 (HivePro UpdraftCentral): an IPv6 address defanged with a bracketed
 *    zero run ("2a09[:]bac5[:]4e21[:]2e3c[::]49b[:]9") was dropped.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { isVictimListingRowLabel, TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { looksDefanged, refangObservable, refangTextForExtraction } from './defang.js';

test('review queue 35960 contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v75');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v24');
});

function extract(blocks) {
  return extractReportCandidates(
    { source_type: 'url', source_url: 'https://publisher.example/advisory' },
    createCanonicalDocument({ title: 'Review queue 35960 fixture', blocks })
  );
}
const find = (r, type, value) => r.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const member = (r, type, value) => {
  const c = find(r, type, value);
  return Boolean(c && isReportIndicatorMember(c));
};

test('A: victim-listing row labels', () => {
  for (const label of ['Recent Breaches', 'Recent breaches', 'Victim sites', 'Victims', 'Breached organizations', 'Affected organizations']) {
    assert.equal(isVictimListingRowLabel(label), true, label);
  }
  // Attack infrastructure rows stay rows: hacked sites that serve the
  // payload (35612 "compromised websites") and ordinary type labels.
  for (const label of ['compromised websites', 'compromised base C&C websites', 'URL', 'Domains', 'C2 servers', 'Victim-facing phishing URL']) {
    assert.equal(isVictimListingRowLabel(label), false, label);
  }
});

test('A: "Recent Breaches" row of a Type | Value IoC table is Context Only (35960)', () => {
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise (IoCs)' },
    createTableBlock({
      id: 't1',
      headers: ['Type', 'Value'],
      rows: [
        ['URL', 'hxxps[:]//evil-update[.]example/payload[.]zip'],
        ['Domains', 'c2-relay[.]example'],
        ['Recent Breaches', 'https://www.fleetworksinc.comhttps://www.stjames.wa.edu.auhttps://www.amc.org.au']
      ]
    })
  ]);
  assert.equal(member(result, 'url', 'https://evil-update.example/payload.zip'), true);
  assert.equal(member(result, 'domain', 'c2-relay.example'), true);
  for (const v of ['https://www.fleetworksinc.com/', 'https://www.stjames.wa.edu.au/', 'https://www.amc.org.au/']) {
    const c = find(result, 'url', v);
    assert.ok(c, `${v} kept as provenance`);
    assert.equal(isReportIndicatorMember(c), false, v);
    assert.equal(c.assessment, 'context_only', v);
  }
});

test('A: "Victim sites" row under a "Recent breaches" sub-table is Context Only (35968)', () => {
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise (IoCs)' },
    createTableBlock({ id: 't1', headers: ['Type', 'Value'], rows: [['IPv4', '77[.]37[.]49[.]40']] }),
    { id: 'h2', type: 'heading', level: 3, text: 'Recent breaches' },
    createTableBlock({ id: 't2', headers: ['Type', 'Value'], rows: [['Victim sites', 'https://hiqbio.com https://www.dwi-bau.de https://www.t-systems.com']] })
  ]);
  assert.equal(member(result, 'ip', '77.37.49.40'), true);
  for (const v of ['https://hiqbio.com/', 'https://www.dwi-bau.de/', 'https://www.t-systems.com/']) {
    assert.equal(member(result, 'url', v), false, v);
  }
});

test('A: a "compromised websites" row that serves the payload stays an Indicator row (35612 control)', () => {
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'IOCs' },
    createTableBlock({
      id: 't1',
      headers: ['', ''],
      rows: [
        ['compromised websites', 'maximumrock[.]ro platinumcar[.]ca'],
        ['compromised base C&C websites', 'v-k.com[.]ua']
      ]
    })
  ]);
  assert.equal(member(result, 'domain', 'maximumrock.ro'), true);
  assert.equal(member(result, 'domain', 'platinumcar.ca'), true);
  assert.equal(member(result, 'domain', 'v-k.com.ua'), true);
});

test('B: an IPv6 zero run defanged as one bracket refangs (35967)', () => {
  assert.equal(refangObservable('2a09[:]bac5[:]4e21[:]2e3c[::]49b[:]9'), '2a09:bac5:4e21:2e3c::49b:9');
  assert.equal(refangTextForExtraction('IPv6 2a09[:]bac5[:]4e21[:]2e3c[::]49b[:]9 seen'), 'IPv6 2a09:bac5:4e21:2e3c::49b:9 seen');
  assert.equal(looksDefanged('2a09:bac5[::]9'), true);
  // Not between hex digits: prose / placeholders stay as written.
  assert.equal(refangObservable('std[::]vector'), 'std[::]vector');
  assert.equal(refangObservable('[::]'), '[::]');

  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise (IoCs)' },
    createTableBlock({
      id: 't1',
      headers: ['Type', 'Value'],
      rows: [
        ['IPv4', '43[.]250[.]53[.]42'],
        ['IPv6', '2a09[:]bac5[:]4e21[:]2e3c[::]49b[:]9']
      ]
    })
  ]);
  assert.equal(member(result, 'ip', '43.250.53.42'), true);
  assert.equal(member(result, 'ipv6', '2a09:bac5:4e21:2e3c::49b:9'), true);
});

test('C: a highlighter textarea whose entity-escaped samples the document holds decoded is a duplicate (35984)', async () => {
  const { isDuplicatedInDocumentRegion, unaccountedRegions } = await import('./reportQualityStatus.js');
  const documentText = [
    '1 2 3 | wss://main.pusher.ably.net/app/<APP_KEY>?protocol=7&client=cpp-socks5 Use Pusher Channels protocol version 7',
    'grant_type: https://graph.microsoft.com/.default&grant_type=client_credentials&client_secret=<redacted>'
  ].join('\n').toLowerCase();
  const ably = {
    region_kind: 'textarea',
    locator: 'textarea.urvanov-syntax-highlighter-plain print-no',
    observable_count: 1,
    sample_observables: ['wss://main.pusher.ably.net/app/&lt;APP_KEY&gt;?protocol=7&amp;client=cpp-socks5']
  };
  const graph = { ...ably, sample_observables: ['https://graph.microsoft.com/.default&amp;grant_type=client_credentials&amp;client_secret=&lt;redacted&gt;'] };
  assert.equal(isDuplicatedInDocumentRegion(ably, documentText), true);
  assert.equal(isDuplicatedInDocumentRegion(graph, documentText), true);
  // A value the document does not hold stays unaccounted.
  const lost = { ...ably, sample_observables: ['https://evil.example/a?x=1&amp;y=2'] };
  assert.equal(isDuplicatedInDocumentRegion(lost, documentText), false);
  const report = { source_url: 'https://securelist.example/x/', canonical_document: { blocks: [{ text: documentText }] } };
  assert.deepEqual(unaccountedRegions({ report, significantRegions: [ably, graph, lost] }).map((r) => r.sample_observables[0]), [lost.sample_observables[0]]);
});
