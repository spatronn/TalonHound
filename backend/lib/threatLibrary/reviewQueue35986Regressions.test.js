/**
 * Review queue 35986-36011 (tl-candidates-v75): defects found auditing the 26
 * Need Review reports against their publisher pages.
 *
 * A. 35994 / 35993 (HivePro): an IoC cell lists one value per adjacent <code>
 *    element with no text between them. The values ran together: 35994 lost 13
 *    IPv4 addresses and two ip:port endpoints.
 * B. 35994 / 35993: the "Recent breaches" sub-section is a label-less table of
 *    victims' websites; the glued list became a malicious URL Indicator.
 * C. 35997 (HivePro eMudhra CA compromise): certificate serials became MD5
 *    samples, SPKI hashes and certificate fingerprints became SHA-256 samples.
 * D. 35987 (StepSecurity WPPConnect): a "Commits" row and a "Docker digests"
 *    row (one of them the known-good image) became SHA-1 / SHA-256 samples.
 * E. 36010 (Bitdefender): "Domains and IPs:gta6cloud[.]nexus" (no space after
 *    the colon) in the IOC list was not read as a row.
 * F. Publication dates: 36000 took a patch release date out of a sentence,
 *    36011 a theme's hard-coded JSON-LD date; 35987 / 35988 / 36001 / 36002 /
 *    36005 had none although the page states it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { classifyHexDigest, digestRowLabel, DIGEST_KINDS } from './digestSemantics.js';
import { isLabeledObservableListLine } from './indicatorScope.js';
import { HTML_BLOCKS_VERSION, accountingTextOf, parseHtml, findElements, tableToRows } from './extract/htmlBlocks.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { detectReportPublicationDate, extractHtmlPublicationDate, PUBLICATION_DATE_EXTRACTOR_VERSION } from './publicationDate.js';

test('review queue 35986 contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v76');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v24');
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v15');
  assert.equal(PUBLICATION_DATE_EXTRACTOR_VERSION, 'tl-published-at-v8');
});

const URL = 'https://publisher.example/advisory';
function extract(blocks) {
  return extractReportCandidates(
    { source_type: 'url', source_url: URL },
    createCanonicalDocument({ title: 'Review queue 35986 fixture', blocks })
  );
}
function extractHtml(html) {
  const x = extractCanonicalDocumentFromHtml(html, { sourceUrl: URL, url: URL });
  return extractReportCandidates({ source_type: 'url', source_url: URL }, x.document || x);
}
const find = (r, type, value) => r.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const member = (r, type, value) => {
  const c = find(r, type, value);
  return Boolean(c && isReportIndicatorMember(c));
};
const members = (r) => r.candidates.filter(isReportIndicatorMember).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();

const tableOf = (html) => tableToRows(findElements(parseHtml(html), (e) => e.name === 'table')[0]);

test('A: adjacent <code> chips of a cell are separate values', () => {
  const { rows } = tableOf(
    '<table><tr><td>IPv4</td><td class="vals"><code>197[.]188[.]223[.]161</code><code>168[.]195[.]122[.]22</code></td></tr></table>'
  );
  assert.deepEqual(rows, [['IPv4', '197[.]188[.]223[.]161 168[.]195[.]122[.]22']]);
  // Wrapped once; a comment between the chips is not text.
  assert.deepEqual(tableOf('<table><tr><td><div><code>a.example</code><!-- --><code>b.example</code></div></td></tr></table>').rows, [
    ['a.example b.example']
  ]);
  // Fragments of one value, mixed inline prose and a single chip keep their reading.
  assert.deepEqual(tableOf('<table><tr><td><code>185.1.2</code><code>.3</code></td></tr></table>').rows, [['185.1.2.3']]);
  assert.deepEqual(tableOf('<table><tr><td>run<code>a</code><code>b</code></td></tr></table>').rows, [['runab']]);
  assert.deepEqual(tableOf('<table><tr><td><code>one.example</code></td></tr></table>').rows, [['one.example']]);
});

test('A: source accounting reads the chips the way the blocks do', () => {
  const dom = parseHtml('<p><code>https://a.example</code><code>https://b.example</code> and r<span>eview</span></p>');
  assert.equal(accountingTextOf(findElements(dom, (e) => e.name === 'p')[0]), 'https://a.example https://b.example and review');
});

const HIVEPRO_HTML = `<!doctype html><html><head><title>Refrigerator Botnet</title></head><body><article><h1>Refrigerator Botnet</h1>
<p>The operators hijack exposed controllers and later listed the retailers they had breached on their own site.</p>
<h3>Indicators of Compromise (IOCs)</h3>
<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>
<tr><td>IPv4</td><td class="vals"><code>197[.]188[.]223[.]161</code><code>168[.]195[.]122[.]22</code><code>85[.]137[.]52[.]63</code></td></tr>
<tr><td>IPv4:Port</td><td class="vals"><code>160[.]19[.]119[.]226[:]443</code><code>46[.]255[.]231[.]42[:]993</code></td></tr>
</tbody></table>
<h5>Recent breaches</h5>
<table><tbody><tr><td class="vals"><code>https://www.delhaize.be</code><code>https://www.carrefour.com</code></td></tr></tbody></table>
</article></body></html>`;

test('A + B: HivePro chip cells yield every address and no victim site (35994)', () => {
  const r = extractHtml(HIVEPRO_HTML);
  assert.deepEqual(members(r), [
    'ip:160.19.119.226', 'ip:168.195.122.22', 'ip:197.188.223.161', 'ip:46.255.231.42', 'ip:85.137.52.63'
  ]);
  for (const v of ['https://www.delhaize.be/', 'https://www.carrefour.com/']) {
    const c = find(r, 'url', v);
    assert.ok(c, `${v} kept as provenance`);
    assert.equal(c.assessment, 'context_only', v);
  }
});

test('B: a list under a victim heading is Context Only; the IOC list above it is not', () => {
  const r = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
    { id: 'p1', type: 'list', text: 'panel-login[.]example' },
    { id: 'h2', type: 'heading', level: 3, text: 'Victims' },
    { id: 'p2', type: 'list', text: 'retailer.example.net' },
    { id: 'h3', type: 'heading', level: 3, text: 'Recent breaches' },
    createTableBlock({ id: 't1', headers: null, rows: [['https://www.hospital-victim.org'], ['https://www.school-victim.org']] })
  ]);
  assert.equal(member(r, 'domain', 'panel-login.example'), true);
  assert.equal(member(r, 'domain', 'retailer.example.net'), false);
  assert.equal(member(r, 'url', 'https://www.hospital-victim.org/'), false);
  assert.equal(member(r, 'url', 'https://www.school-victim.org/'), false);
});

const CERT_ROWS = [
  ['SHA256', '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE'],
  ['SPKI SHA256', 'EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105 49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F'],
  ['Certificate Serial', 'c7c41efe92d825f05eae841a4a82c1 d8f8685e4f2bd9d82402a85a1c1eb731 e94223bde92f914e5ab9acabfdac3710']
];

test('C: a certificate table lists fingerprints, key hashes and serials, never samples (35997)', () => {
  const r = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise (IoCs)' },
    createTableBlock({ id: 't1', headers: ['Type', 'Value'], rows: CERT_ROWS })
  ]);
  assert.deepEqual(members(r), []);
  for (const v of ['42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493', '49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f', 'e94223bde92f914e5ab9acabfdac3710']) {
    assert.ok(find(r, 'technical_artifact', v), `${v} kept as certificate provenance`);
  }
});

test('C: a malware table that also lists a signer serial keeps its SHA256 row (control)', () => {
  const rows = [
    ['SHA256', '026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab'],
    ['Certificate Serial', 'd8f8685e4f2bd9d82402a85a1c1eb731']
  ];
  const r = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise (IoCs)' },
    createTableBlock({ id: 't1', headers: ['Type', 'Value'], rows })
  ]);
  assert.deepEqual(members(r), ['sha256:026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab']);
  // A file row beside SPKI rows also keeps the bare algorithm row.
  const block = createTableBlock({ id: 't2', headers: ['Type', 'Value'], rows: [...CERT_ROWS, ['Filename', 'loader.exe']] });
  assert.equal(digestRowLabel(block, '42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493'), 'SHA256');
});

test('D: "Commits" and "Docker digests" rows name repository objects (35987)', () => {
  const r = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise' },
    createTableBlock({
      id: 't1',
      headers: ['Type', 'Indicator', 'Notes'],
      rows: [
        ['SHA-1', '755274304012c7489e85c23da3c2423d184d113b (2.4.1); 950514e4fea481c0770bd618274cecb306bd8d56 (2.4.3)', 'Actions log'],
        ['Commits (pre-rewrite)', 'Library: 06caa8c6f5f06e47900d5466289b4aab2753add3, 27ed8e343f0393978c63f84888eeb9b8fa197852. Server: bdddf54ca86019c853ba68c2eeca45c2ac8128d6', 'Our reading'],
        ['Network', 'https://exfil-host[.]example/sendDocument', 'Our reading'],
        ['Docker digests', 'Infected: 2.10.82 sha256:56a546a38f6e59509f627168c8d67f9c87fd487babf3ad91f375fe99a235c4c7. Known-good: 2.10.81 sha256:7c882ee934a5663a107b5f5a0382bfd8b1fb95150cd21ab35cd8ff9cea70d1f8', 'Docker Hub']
      ]
    })
  ]);
  assert.equal(member(r, 'sha1', '755274304012c7489e85c23da3c2423d184d113b'), true);
  assert.equal(member(r, 'sha1', '950514e4fea481c0770bd618274cecb306bd8d56'), true);
  for (const v of ['06caa8c6f5f06e47900d5466289b4aab2753add3', '27ed8e343f0393978c63f84888eeb9b8fa197852', 'bdddf54ca86019c853ba68c2eeca45c2ac8128d6']) {
    assert.equal(find(r, 'sha1', v), null, v);
    assert.ok(find(r, 'technical_artifact', v), v);
  }
  for (const v of ['56a546a38f6e59509f627168c8d67f9c87fd487babf3ad91f375fe99a235c4c7', '7c882ee934a5663a107b5f5a0382bfd8b1fb95150cd21ab35cd8ff9cea70d1f8']) {
    assert.equal(find(r, 'sha256', v), null, v);
  }
});

test('D: a file noun on the row keeps the file reading; a row label governs every digest of its row', () => {
  const h1 = 'a'.repeat(40);
  const h2 = 'b'.repeat(40);
  assert.equal(classifyHexDigest(`${h1}, ${h2}`, h2, { rowLabel: 'Commits' }).kind, DIGEST_KINDS.OBJECT_ID);
  assert.equal(classifyHexDigest(`${h1}, ${h2}`, h2, { rowLabel: 'Payload (commit build)' }).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`payload ${h2}`, h2, { rowLabel: 'Commits' }).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`${h1}, ${h2}`, h2, { rowLabel: 'SHA-1' }).kind, DIGEST_KINDS.FILE);
});

test('E: a labelled IOC line with no space after the colon is a row (36010)', () => {
  assert.equal(isLabeledObservableListLine('Domains and IPs:gta6cloud[.]nexus'), true);
  assert.equal(isLabeledObservableListLine('C2:198[.]51[.]100[.]7'), true);
  for (const t of ['https://evil.example', 'host:8443', 'sha256:deadbeef', 'urn:evil.example', 'Legitimate domains:site.example', 'com.evil.app:main.example']) {
    assert.equal(isLabeledObservableListLine(t), false, t);
  }
  const r = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'IOC' },
    { id: 'l1', type: 'list', text: 'Domains and IPs:gta6cloud[.]nexus' },
    { id: 'l2', type: 'list', text: 'hxxps://velmontriq[.]net' }
  ]);
  assert.equal(member(r, 'domain', 'gta6cloud.nexus'), true);
  assert.equal(member(r, 'url', 'https://velmontriq.net/'), true);
});

const NOW = new Date('2026-11-24T00:00:00Z');
const day = (html) => {
  const d = extractHtmlPublicationDate(html, { now: NOW });
  return d.published_at ? String(d.published_at).slice(0, 10) : null;
};

test('F: dateline under the page title, header date class, report production stamp', () => {
  assert.equal(
    day('<html><head><title>Flash Alert: Weaponizing the Outage</title></head><body><h1>Flash Alert: Weaponizing the Outage</h1><span class="subtitle">November 16, 2026</span></body></html>'),
    '2026-11-16'
  );
  // A dated card of another post is not this page's dateline.
  assert.equal(
    day('<html><head><title>Flash Alert: Weaponizing the Outage</title></head><body><h1>Flash Alert: Weaponizing the Outage</h1><div><h2>Some Other Research Post</h2><span>November 2, 2026</span></div></body></html>'),
    null
  );
  assert.equal(
    day('<html><body><main><div class="blog-post-header_date"><p class="text-size-small">November 17, 2026</p></div><div class="card-blog-post_date"><p>November 12, 2026</p></div></main></body></html>'),
    '2026-11-17'
  );
  assert.equal(
    day('<html><body><footer><span>TA2026247 &bull; Report Generated On August 26, 2026 · 05:00 AM</span><span>&copy; 2026 All Rights Reserved</span></footer></body></html>'),
    '2026-08-26'
  );
  assert.equal(
    day('<html><body><div class="footer"><span>REPORT GENERATED ON August 10, 2026 • 08:30 AM (Updated September 2, 2026)</span></div></body></html>'),
    '2026-08-10'
  );
  // A stated publication date outranks the production stamp.
  assert.equal(
    day('<html><body><div><span>Published</span> <span>October 08, 2026</span></div><footer><span>Report generated October 09, 2026</span></footer></body></html>'),
    '2026-10-08'
  );
});

const ld = (date) => `<script type="application/ld+json">{"@context":"https://schema.org","@type":"BlogPosting","headline":"Bazuka","datePublished":"${date}"}</script>`;

test('F: of two disagreeing JSON-LD article dates, the one the page shows wins (36011)', () => {
  assert.equal(day(`<html><head>${ld('2024-10-01')}${ld('2026-11-18T13:09:10.000Z')}</head><body><h2>Bazuka</h2><p>18 November 2026</p></body></html>`), '2026-11-18');
  // No agreement with the page: the first node keeps winning.
  assert.equal(day(`<html><head>${ld('2024-10-01')}${ld('2026-11-18T13:09:10.000Z')}</head><body><h2>Bazuka</h2></body></html>`), '2024-10-01');
  assert.equal(day(`<html><head>${ld('2026-11-10')}</head><body><p>18 November 2026</p></body></html>`), '2026-11-10');
});

test('F: a release date inside a sentence never dates the report (36000)', () => {
  const doc = (text) => createCanonicalDocument({
    title: 'Head Mare Chains TrueConf Server Flaws',
    blocks: [
      { id: 'h', type: 'heading', level: 1, text: 'Head Mare Chains TrueConf Server Flaws' },
      { id: 'p', type: 'paragraph', text }
    ]
  });
  const detect = (text) => detectReportPublicationDate({ sourceType: 'url', sourceUrl: URL, html: '<html><body></body></html>', document: doc(text), now: NOW });
  const prose = 'Upgrade every TrueConf Server instance to version 5.3.9, 5.4.9, or 5.5.5, released on June 18, 2026, to close the CVE-2026-72529 and CVE-2026-72530 vulnerabilities exploited in this attack, and confirm the running build afterwards.';
  assert.equal(detect(prose).published_at, null);
  assert.equal(String(detect('Released on: June 18, 2026').published_at).slice(0, 10), '2026-06-18');
});
