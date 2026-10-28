/**
 * Twenty-seven-report batch audit regressions, reports 34387–34414
 * (tl-candidates-v43 / threat_library_html_v9 / tl-section-tree-v10 /
 * tl-table-v13). Generic shapes of the confirmed defects of the 2026-10-29
 * audit, each with its negative control:
 *
 * D1. A table the CMS nested inside a heading element (`<h3><span><table>`)
 *     keeps its rows: the hashes of an IOC "Files" table are Indicators, not
 *     narrative mentions of one flattened heading block.
 * D2. An IOC heading already grouped into deeper indicator-class children
 *     ("## IoCs" › "### Files") continues into a same-level indicator-class
 *     sibling over an inventory ("## Network"); a same-level topic heading
 *     ("## MITRE ATT&CK techniques") still closes it.
 * D3. A scheme-less IPv4-host URL with a non-digit path ("91.92.242[.]30/lamq4")
 *     is a URL Indicator; an IPv4 CIDR prefix ("10.20.0.0/16") is never a URL.
 * D4. A list lead-in that names its values as instances of a public service
 *     ("… on three Blockscout instances:") is a provider stance; a lead-in
 *     naming "C2 instances" keeps the assertion.
 * D5. A Type-column row naming request content ("macOS POST body",
 *     "User-Agent") asserts no indicator; a "C2 URL" row does.
 *
 * Values are public IOCs from the audited reports or documentation shapes.
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml, THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/twenty-seven-report-batch/';

function doc(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return r.document;
}
const run = (inner) => extractReportCandidates({ source_type: 'url', source_url: SOURCE }, doc(inner));
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const find = (out, value) => out.candidates.find((c) => String(c.normalized_value).toLowerCase() === value.toLowerCase());
const member = (out, value) => {
  const c = find(out, value);
  return Boolean(c) && isReportIndicatorMember(persisted(c));
};

test('versions: tl-candidates-v43, threat_library_html_v9, tl-section-tree-v10, tl-table-v13', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v43');
  assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v9');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v10');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v13');
});

// --- D1. Table nested in a heading ------------------------------------------

const FILES_TABLE_IN_HEADING = `<h2>IoCs</h2>
<p>A comprehensive list of indicators of compromise (IoCs) and samples can be found in our GitHub repository.</p>
<h3>Files</h3>
<h3><span style="font-size: medium; font-weight: 400;"><table border="1">
<thead><tr><td><strong>SHA-1</strong></td><td><strong>Filename</strong></td><td><strong>Detection</strong></td><td><strong>Description</strong></td></tr></thead>
<tbody>
<tr><td><span>799BB5127CA54239D3D4<wbr />A14367DB3B712012CF14</span></td><td>all.callhistory.deta<wbr />il.apk</td><td>Android/CallPhantom.K</td><td>Android CallPhantom.</td></tr>
<tr><td><span>56A4FD71D1E4BBA2C5C2<wbr />40BE0D794DCFF709D9EB</span></td><td>calldetaila.ndcallhisto.rytogetan.ynumber.apk</td><td>Android/CallPhantom.M</td><td>Android CallPhantom.</td></tr>
<tr><td><span>EC5E470753E76614CD28<wbr />ECF6A3591F08770B7215</span></td><td>callhistoryeditor.callhistory.numberdetails.calleridlocator.apk</td><td>Android/CallPhantom.F</td><td>Android CallPhantom.</td></tr>
<tr><td><span>77C8B7BEC79E7D9AE0D0<wbr />C02DEC4E9AC510429AD8</span></td><td>com.all_historydownload.anynumber.callhistorybackup.apk</td><td>Android/CallPhantom.G</td><td>Android CallPhantom.</td></tr>
<tr><td><span>9484EFD4C19969F57AFB<wbr />0C21E6E1A4249C209305</span></td><td>com.any.numbers.calls.history.apk</td><td>Android/CallPhantom.L</td><td>Android CallPhantom.</td></tr>
<tr><td><span>CE97CA7FEECDCAFC6B8E<wbr />9BD83A370DFA5C336C0A</span></td><td>com.anycallinformation.datadetailswho.callinfo.numberfinder.xapk</td><td>Android/CallPhantom.B</td><td>Android CallPhantom.</td></tr>
<tr><td><span>FC3BA2EDAC0BB9801F85<wbr />35E36F0BCC49ADA5FA5A</span></td><td>com.app.call.detail.history.apk</td><td>Android/CallPhantom.N</td><td>Android CallPhantom.</td></tr>
<tr><td><span>B7B80FA34A41E3259E37<wbr />7C0D843643FF736803B8</span></td><td>com.basehistory.historydownloading.xapk</td><td>Android/CallPhantom.O</td><td>Android CallPhantom.</td></tr>
</tbody></table></span></h3>
<h3>Network</h3>
<table border="1"><tr><td>IP</td><td>Domain</td><td>Details</td></tr>
<tr><td>34.120.160[.]131</td><td>N/A</td><td>C&amp;C server.</td></tr></table>`;

test('D1: a table nested inside a heading element is a table block, not heading text (34390)', () => {
  const d = doc(FILES_TABLE_IN_HEADING);
  const tables = d.blocks.filter((b) => b.type === 'table');
  assert.ok(tables.length >= 1, 'the nested table is its own block');
  assert.ok(!d.blocks.some((b) => b.type === 'heading' && /799BB5127CA5/i.test(String(b.text || ''))), 'no heading holds the table rows');
});

test('D1: the hashes of the heading-wrapped Files table are Indicators (34390)', () => {
  const out = run(FILES_TABLE_IN_HEADING);
  // A table row asserts the hash; the flattened heading only mentioned it
  // (body_mention, left to the model — production kept 21 of 28 unknown).
  assert.equal(find(out, '799bb5127ca54239d3d4a14367db3b712012cf14').source_assertion, 'explicit_ioc');
  assert.equal(find(out, 'b7b80fa34a41e3259e377c0d843643ff736803b8').source_assertion, 'explicit_ioc');
  assert.ok(member(out, '799bb5127ca54239d3d4a14367db3b712012cf14'));
  assert.ok(member(out, 'b7b80fa34a41e3259e377c0d843643ff736803b8'));
  assert.ok(member(out, '34.120.160.131'));
  assert.ok(!member(out, 'all.callhistory.detail.apk'), 'a filename cell stays a file name');
});

test('D1 control: a heading with only inline markup keeps its text', () => {
  const d = doc('<h2><span style="color:red">Indicators</span> of <em>Compromise</em></h2><p>None.</p>');
  assert.ok(d.blocks.some((b) => b.type === 'heading' && b.text.replace(/\s+/g, ' ').trim() === 'Indicators of Compromise'));
});

// --- D2. Same-level indicator-class sibling ---------------------------------

const ESET_SIBLING_NETWORK = `<h2>IoCs</h2>
<p>A comprehensive list of indicators of compromise (IoCs) and samples can be found in our GitHub repository.</p>
<h3>Files</h3>
<table border="1"><tr><td>SHA-1</td><td>Filename</td><td>Detection</td><td>Description</td></tr>
<tr><td>6BBC9AB132BA066F63676E05DA13D108598BC29B</td><td>net.ustexas.myavlive.apk</td><td>Android/Spy.VNCSpy.A</td><td>Android VNCSpy malware.</td></tr></table>
<h2>Network</h2>
<p><table border="1"><tr><td>IP</td><td>Domain</td><td>Hosting provider</td><td>First seen</td><td>Details</td></tr>
<tr><td>52.222.205[.]45</td><td>m-mgarg[.]com</td><td>Amazon.com, Inc.</td><td>2026-01-12</td><td>Phishing website.</td></tr>
<tr><td>54.67.2[.]84</td><td>N/A</td><td>Amazon.com, Inc.</td><td>N/A</td><td>C&amp;C server.</td></tr>
<tr><td>104.21.91[.]170</td><td>mgardownload[.]com</td><td>Cloudflare, Inc.</td><td>2026-01-13</td><td>Distribution website.</td></tr></table></p>
<h2>MITRE ATT&amp;CK techniques</h2>
<p>This table was built using version 18 of the MITRE ATT&amp;CK framework.</p>
<table border="1"><tr><td>Tactic</td><td>ID</td><td>Name</td><td>Description</td></tr>
<tr><td>Command and Control</td><td>T1437.001</td><td>Application Layer Protocol</td><td>PromptSpy talks to mgarg[.]com over HTTPS.</td></tr></table>`;

test('D2: a same-level "Network" group after "IoCs › Files" stays in the IOC inventory (34387)', () => {
  const out = run(ESET_SIBLING_NETWORK);
  assert.ok(member(out, '6bbc9ab132ba066f63676e05da13d108598bc29b'));
  for (const v of ['54.67.2.84', 'm-mgarg.com', 'mgardownload.com', '52.222.205.45', '104.21.91.170']) {
    assert.ok(member(out, v), `${v} is an Indicator`);
  }
});

test('D2 control: the following same-level topic heading closes the inventory', () => {
  const out = run(ESET_SIBLING_NETWORK);
  assert.ok(!member(out, 'mgarg.com'), 'a MITRE-table mention is not an Indicator');
});

test('D2 control: a same-level "Network" heading after an IOC section without class groups is a new topic', () => {
  const out = run(`<h2>IoCs</h2>
<table border="1"><tr><td>SHA-1</td><td>Description</td></tr>
<tr><td>6BBC9AB132BA066F63676E05DA13D108598BC29B</td><td>Android VNCSpy malware.</td></tr></table>
<h2>Network</h2>
<p>The operators rented servers from several providers; one was reachable at 198.51.100.23 during testing.</p>`);
  assert.ok(member(out, '6bbc9ab132ba066f63676e05da13d108598bc29b'));
  assert.ok(!member(out, '198.51.100.23'));
});

// --- D3. Scheme-less IPv4-host URL ------------------------------------------

test('D3: a scheme-less IPv4-host URL in an IOC list is a URL Indicator (34397)', () => {
  const out = run(`<h2>Indicators of Compromise</h2>
<h3>Domains, IP Addresses and URLs</h3>
<p>2.26.75[.]16</p><p>91.92.242[.]30</p><p>91.92.242[.]30/lamq4</p><p>download.setup-service[.]com</p>`);
  const url = find(out, '91.92.242.30/lamq4');
  assert.ok(url, 'URL extracted');
  assert.equal(url.candidate_type, 'url');
  assert.ok(member(out, '91.92.242.30/lamq4'));
  assert.ok(member(out, '91.92.242.30'), 'the standalone IP row stays an Indicator');
  assert.ok(member(out, 'download.setup-service.com'));
});

test('D3 control: an IPv4 CIDR prefix is never a scheme-less URL', () => {
  const out = run(`<h2>Indicators of Compromise</h2>
<ul><li>10.20.0.0/16</li><li>203.0.113.0/24</li></ul>`);
  assert.equal(out.candidates.filter((c) => c.candidate_type === 'url').length, 0);
  const cidr = find(out, '203.0.113.0/24');
  assert.ok(cidr);
  assert.equal(cidr.candidate_type, 'cidr');
});

// --- D4. Provider "instances" lead-in ---------------------------------------

const BLOCKSCOUT = (lead) => `<h2>Observations</h2>
<p>The following observables were discussed in this research.</p>
<table><thead><tr><th>Observable</th><th>Type</th><th>Name</th><th>Reference</th></tr></thead>
<tbody><tr><td>panel.fefea22134[.]net</td><td>domain-name</td><td></td><td>PhantomPulse C2 panel</td></tr></tbody></table>
<h3>RAT - PHANTOMPULSE</h3>
<h4>C2 rotation through blockchain</h4>
<p>PHANTOMPULSE implements a decentralized C2 resolution mechanism using public blockchain infrastructure as a dead drop.</p>
<p>${lead}</p>
<ul><li>eth.blockscout[.]com (Ethereum L1)</li><li>base.blockscout[.]com (Base L2)</li><li>optimism.blockscout[.]com (Optimism L2)</li></ul>
<p>Each request fetches the most recent transaction associated with a hardcoded wallet address.</p>`;

test('D4: values listed as "Blockscout instances" the malware queries are not Indicators (34400)', () => {
  const out = run(BLOCKSCOUT('The malware queries the Etherscan-compatible API (<code>/api?module=account&amp;action=txlist&amp;address=&lt;wallet&gt;</code>) on three Blockscout instances:'));
  assert.ok(member(out, 'panel.fefea22134.net'));
  for (const v of ['eth.blockscout.com', 'base.blockscout.com', 'optimism.blockscout.com']) {
    assert.ok(!member(out, v), `${v} is a provider instance`);
  }
});

test('D4 control: a lead-in naming "C2 instances" keeps the listed values', () => {
  const out = run(BLOCKSCOUT('The implant beacons to three C2 instances:'));
  assert.ok(member(out, 'eth.blockscout.com'));
});

// --- D5. Request-content type cells -----------------------------------------

const NETWORK_TYPED = `<h2>Indicators of Compromise (IOCs)</h2>
<h3>Network Indicators</h3>
<table><thead><tr><th>Type</th><th>Indicator</th></tr></thead><tbody>
<tr><td>C2 Domain</td><td>sfrclak[.]com</td></tr>
<tr><td>C2 IP</td><td>142.11.206[.]73</td></tr>
<tr><td>C2 URL</td><td>http://sfrclak[.]com:8000/6202033</td></tr>
<tr><td>User-Agent</td><td>mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)</td></tr>
<tr><td>macOS POST body</td><td>packages[.]npm[.]org/product0</td></tr>
<tr><td>Windows POST body</td><td>packages[.]npm[.]org/product1</td></tr>
</tbody></table>`;

test('D5: "POST body" rows of a typed network table are not Indicators (34410)', () => {
  const out = run(NETWORK_TYPED);
  assert.ok(!member(out, 'packages.npm.org/product0'));
  assert.ok(!member(out, 'packages.npm.org/product1'));
  assert.ok(!member(out, 'packages.npm.org'));
});

test('D5 control: C2 domain / IP / URL rows of the same table stay Indicators', () => {
  const out = run(NETWORK_TYPED);
  assert.ok(member(out, 'sfrclak.com'));
  assert.ok(member(out, '142.11.206.73'));
  assert.ok(member(out, 'http://sfrclak.com:8000/6202033'));
});
