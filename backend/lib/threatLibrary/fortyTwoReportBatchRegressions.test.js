/**
 * Forty-two-report batch audit regressions (tl-candidates-v48, tl-section-tree-v11).
 *
 * A. An IOC heading grouped into qualified indicator-class children ("Observed
 *    C2 IPs …") continues into a same-level qualified sibling whose groups are
 *    deeper headings ("Representative observed domains" › "Wave 1 domains").
 * B. Bullet glyphs separate the values of one IOC-table cell ("•h1 •h2"); each
 *    row's description governs every value of that row.
 * C. A free-text category cell ("Input method") never retypes a value whose
 *    indicator column declares a network type ("Spoofed domain").
 * D. With a promoted header row, the operator-owned provider row check reads
 *    the right row ("CaptiveCrunch DNS Resolver").
 * E. "DKIM-signed by the operator" is attacker stance, not a signed component.
 * F. Backtick-wrapped IOC-table values (`host`) are parsed.
 * G. "downloads the legitimate <tool> from <URL>" names a benign source.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { isReportIndicatorMember, isUnionReportIndicatorMember } from './indicatorMembership.js';
import { toLinkedSourceCandidate } from './iocSources/linkedCandidate.js';
import { demoteFilenameDomains } from './iocSources/extract.js';
import { publicPromoteEligibility } from './promotion.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { TABLE_SEMANTICS_VERSION, interpretIocTable } from './tableSemantics.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://www.microsoft.com/en-us/security/blog/2026/06/25/example-report/';

function run(html) {
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, 'html extract ok');
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document).candidates;
}

function member(c) {
  return Boolean(c) && isReportIndicatorMember({
    ...c,
    has_original_document_occurrence: true,
    review_status: 'pending',
    evidence: buildCandidateEvidenceRecord(c)
  });
}

function find(cands, type, value) {
  const v = String(value).toLowerCase();
  return cands.find((c) => c.candidate_type === type && String(c.normalized_value || '').toLowerCase() === v);
}

const BODY = '<h2>Analysis</h2><p>The operators ran a multi-stage campaign against hospitality targets.</p>';

test('versions: tl-candidates-v48, tl-section-tree-v11, tl-table-v14', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v48');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v11');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v14');
});

test('A. a qualified sibling heading with deeper domain groups stays in the IOC inventory', () => {
  const cands = run(`<article>${BODY}
<h3>Indicators of compromise</h3>
<h4>Observed C2 IPs and non-standard ports</h4>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>178.16.54[.]27</td><td>IP</td><td>Primary C2</td></tr></table>
<h3>Representative observed domains</h3>
<h4>Wave 1 domains</h4>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>prejointl[.]info</td><td>Domain</td><td>C2 domain</td></tr>
<tr><td>kellystreets[.]info</td><td>Domain</td><td>C2 domain</td></tr></table>
<h4>Wave 2 domains</h4>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>photo-26254[.]cfd</td><td>Domain</td><td>Phishing landing page</td></tr></table>
<h3>Mitigation and protection guidance</h3>
<p>Block the domain photo-99999[.]cfd at the proxy if you see it.</p>
</article>`);
  assert.equal(member(find(cands, 'ip', '178.16.54.27')), true);
  for (const d of ['prejointl.info', 'kellystreets.info', 'photo-26254.cfd']) {
    const c = find(cands, 'domain', d);
    assert.ok(c, `${d} extracted`);
    assert.equal(member(c), true, `${d} is an Indicator`);
  }
  const after = find(cands, 'domain', 'photo-99999.cfd');
  assert.ok(!after || member(after) === false, 'the next topic heading closes the inventory');
});

test('A2. an unqualified topic sibling still closes the IOC heading', () => {
  const cands = run(`<article>${BODY}
<h3>Indicators of compromise</h3>
<h4>Observed C2 IPs</h4>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>178.16.54[.]27</td><td>IP</td><td>Primary C2</td></tr></table>
<h3>Representative victims</h3>
<h4>Wave 1 notes</h4>
<p>Victims browsed bookingportal[.]example while travelling.</p>
</article>`);
  assert.equal(member(find(cands, 'ip', '178.16.54.27')), true);
  const c = find(cands, 'domain', 'bookingportal.example');
  assert.ok(!c || member(c) === false, 'a non-indicator sibling heading is not inventory');
});

const H = (ch) => ch.repeat(64);

test('B. bullet-separated values in one cell follow their own row description', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise (IOCs)</h2>
<table><tr><td>Indicator</td><td>Type</td><td>Description</td></tr>
<tr><td>•${H('1')}</td><td>SHA256</td><td>Legitimate MSP360 RMM installer distributed under deceptive filenames.</td></tr>
<tr><td>•${H('2')}<br>•${H('3')}<br>•${H('4')}</td><td>SHA256</td><td>Legitimate MSP360 RMM Agent Service observed during the campaign</td></tr>
<tr><td>•adswre[.]cfd<br>•trews[.]cfd<br>•swedcorry[.]stefneyv[.]com</td><td>Domains</td><td>Domains contacted by ScreenConnect clients in observed malicious sessions.</td></tr>
<tr><td>•${H('5')}<br>•${H('6')}</td><td>SHA256</td><td>Utilities transferred through ScreenConnect sessions during post-compromise activity.</td></tr>
</table></article>`);
  for (const ch of ['1', '2', '3', '4']) {
    const c = find(cands, 'sha256', H(ch));
    assert.ok(c, `hash ${ch} extracted`);
    assert.equal(member(c), false, `legitimate row hash ${ch} is Context Only`);
  }
  for (const d of ['adswre.cfd', 'trews.cfd', 'swedcorry.stefneyv.com']) {
    const c = find(cands, 'domain', d);
    assert.ok(c, `${d} extracted`);
    assert.equal(member(c), true, `${d} is an Indicator`);
  }
  for (const ch of ['5', '6']) assert.equal(member(find(cands, 'sha256', H(ch))), true, `tool hash ${ch} is an Indicator`);
});

test('C. a category cell does not retype a declared spoofed-domain column', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><th>Impersonated brand</th><th>Spoofed domain (defanged)</th><th>Category</th></tr>
<tr><td>Razer</td><td>pc-razerzone[.]com[.]cn</td><td>Peripherals</td></tr>
<tr><td>Sogou</td><td>gw-sogou[.]com[.]cn</td><td>Input method</td></tr>
<tr><td>Calibre</td><td>calibre-ebook[.]com[.]cn</td><td>E-book</td></tr>
</table></article>`);
  for (const d of ['pc-razerzone.com.cn', 'gw-sogou.com.cn', 'calibre-ebook.com.cn']) {
    const c = find(cands, 'domain', d);
    assert.ok(c, `${d} is a domain candidate`);
    assert.equal(member(c), true, `${d} is an Indicator`);
  }
});

test('C2. a code-label column still types its values as artifacts', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>Loader.Core.Run</td><td>Method</td><td>Entry method of the loader</td></tr>
<tr><td>badhost[.]com</td><td>Domain</td><td>C2</td></tr>
</table></article>`);
  assert.equal(find(cands, 'domain', 'loader.core.run'), undefined, 'a declared method is never a domain');
  assert.equal(member(find(cands, 'domain', 'badhost.com')), true);
});

test('D. a header-row table reads the right row for an operation-owned resolver', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table>
<tr><td>Indicator</td><td>Type</td><td>Description</td><td>First seen</td></tr>
<tr><td>cdn-gstat[.]com</td><td>Domain</td><td>CaptiveCrunch redirect</td><td>2026-09-30</td></tr>
<tr><td>38.146.28[.]75</td><td>IP address</td><td>CaptiveCrunch AitM infrastructure</td><td>2026-07-01</td></tr>
<tr><td>38.146.28[.]132</td><td>IP address</td><td>CaptiveCrunch DNS Resolver</td><td>2026-07-15</td></tr>
<tr><td>8.8.4[.]4</td><td>IP address</td><td>Google DNS Resolver</td><td>2026-07-15</td></tr>
</table></article>`);
  assert.equal(member(find(cands, 'ip', '38.146.28.132')), true, 'the operation-owned resolver is an Indicator');
  assert.equal(member(find(cands, 'ip', '38.146.28.75')), true);
  const google = find(cands, 'ip', '8.8.4.4');
  assert.ok(!google || member(google) === false, 'a third-party resolver stays a provider');
});

test('E. a DKIM-signed operator sending domain is an Indicator; a signed binary is not', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise (IOCs)</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>9i6pokerdepot[.]com</td><td>Domain</td><td>Sending domain; DKIM-signed by the operator</td></tr>
<tr><td>${H('7')}</td><td>SHA-256</td><td>Installer signed by Microsoft Corporation</td></tr>
<tr><td>ecajovna[.]sk</td><td>Domain</td><td>Domain used to send campaign emails</td></tr>
</table></article>`);
  assert.equal(member(find(cands, 'domain', '9i6pokerdepot.com')), true, 'DKIM-signed by the operator is attacker stance');
  assert.equal(member(find(cands, 'sha256', H('7'))), false, 'a vendor-signed binary stays Context Only');
  assert.equal(member(find(cands, 'domain', 'ecajovna.sk')), true);
});

test('F. backtick-wrapped IOC-table cells are parsed', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of Compromise (IOC)</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>\`oob.moika[.]tech\`</td><td>Domain</td><td>C2 server for payload delivery</td></tr>
<tr><td>\`https://oob.moika[.]tech/payload/win\`</td><td>URL</td><td>Windows payload endpoint</td></tr>
</table></article>`);
  const table = interpretIocTable({
    id: 't1',
    type: 'table',
    table: { headers: ['Indicator', 'Type', 'Description'], rows: [['`oob.moika[.]tech`', 'Domain', 'C2 server for payload delivery']] }
  }, { inAuthoritativeScope: true });
  assert.deepEqual(table.rows[0].values.map((v) => `${v.candidate_type}:${v.normalized_value}`), ['domain:oob.moika.tech'],
    'the backtick row asserts its domain');
  const d = find(cands, 'domain', 'oob.moika.tech');
  assert.ok(d, 'backtick domain extracted');
  assert.equal(member(d), true);
  assert.equal(member(find(cands, 'url', 'https://oob.moika.tech/payload/win')), true);
});

test('G. a legitimate runtime download source is not an Indicator; an attacker download host is', () => {
  const cands = run(`<article>${BODY}
<h2>Gen-2 stager</h2>
<p>The following section lists the indicators observed for the Gen-2 stager.</p>
<p>setup.mjs (a) checks whether bun is already present on the host; (b) if not, downloads the legitimate Bun runtime v1.3.13 from github.com/oven-sh/bun/releases for the correct platform.</p>
<p>The stager then downloads the stage-2 payload from hxxp://aab.sportsontheweb[.]net/x.php and runs it.</p>
</article>`);
  const bun = find(cands, 'url', 'github.com/oven-sh/bun/releases');
  assert.ok(!bun || member(bun) === false, 'the legitimate Bun release page is context');
  const payload = find(cands, 'url', 'http://aab.sportsontheweb.net/x.php');
  assert.ok(payload, 'payload URL extracted');
  assert.equal(member(payload), true, 'the attacker payload URL stays an Indicator');
});

test('H. bullet value paragraphs take the stance of the lead-in that introduces them', () => {
  const cands = run(`<article>${BODY}
<h2>Certificate pivoting</h2>
<p>Using OSINT, this TLS certificate was presented by 3 IP addresses. Microsoft assesses that these IPs are part of the C2 infrastructure.</p>
<p>• 93.115[.]10.35</p>
<p>• 198.23[.]185.238</p>
<h2>Connectivity checks</h2>
<p>The loader first checks these legitimate public resolvers.</p>
<p>• 9.9.9[.]9</p>
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>193.42.11[.]108</td><td>IP address</td><td>ScreenConnect relay</td></tr></table>
</article>`);
  for (const ip of ['93.115.10.35', '198.23.185.238']) {
    const c = find(cands, 'ip', ip);
    assert.ok(c, `${ip} extracted`);
    assert.ok(c.occurrences.some((o) => o.source_relation === 'operational_malicious'), `${ip} reads as C2 from its lead-in`);
    assert.equal(member(c), false, 'a MODE A body value is still not an automatic Indicator');
  }
  const resolver = find(cands, 'ip', '9.9.9.9');
  assert.ok(!resolver || !resolver.occurrences.some((o) => o.source_relation === 'operational_malicious'),
    'a benign lead-in never makes its values operational');
  assert.equal(member(find(cands, 'ip', '193.42.11.108')), true);
});

test('I. a role-labelled body column or hunting list makes a MODE A value promotable, never a member', () => {
  const cands = run(`<article>${BODY}
<h2>Brand-impersonation infrastructure</h2>
<table><tr><th>Impersonated brand</th><th>Spoofed domain (defanged)</th><th>Category</th></tr>
<tr><td>Sejda PDF</td><td>sejda[.]hl[.]cn</td><td>Productivity</td></tr></table>
<h2>Advanced hunting</h2>
<pre>let c2ip = dynamic(["202.95.14.237",</pre>
<pre>"47.239.232.245"]);</pre>
<pre>let ncsi_endpoints = dynamic(["13.107.4.52"]);</pre>
<h2>Indicators of compromise (IOC)</h2>
<table><tr><th>Indicator</th><th>Type</th></tr>
<tr><td>202.95.14[.]237</td><td>IP</td></tr></table>
</article>`);
  const eligible = (c) => publicPromoteEligibility({
    ...c,
    has_original_document_occurrence: true,
    review_status: 'context_only',
    evidence: buildCandidateEvidenceRecord(c)
  }).promotable;
  const spoofed = find(cands, 'domain', 'sejda.hl.cn');
  assert.ok(spoofed);
  assert.equal(member(spoofed), false);
  assert.equal(eligible(spoofed), true, 'a Spoofed-domain column value is promotable');
  const c2 = find(cands, 'ip', '47.239.232.245');
  assert.ok(c2);
  assert.equal(member(c2), false);
  assert.ok(c2.occurrences.some((o) => o.code_list_name === 'c2ip'), 'the open list name carries to the next code line');
  assert.equal(eligible(c2), true, 'a c2ip hunting-list value is promotable');
  const ncsi = find(cands, 'ip', '13.107.4.52');
  assert.ok(!ncsi || eligible(ncsi) === false, 'a neutral list name is not role evidence');
});

test('J. values the publisher enumerates as delivery hosts are promotable, never members', () => {
  const cands = run(`<article>${BODY}
<h2>Delivery</h2>
<p>Telemetry ties each downloaded archive to rotating delivery hosts (yimxg25tiy[.]com/73inst, cc8ttkv35b[.]com/7qinst) and the impersonation page that served it.</p>
<p>Users later browsed docs-portal[.]example for documentation.</p>
<h2>Indicators of compromise (IOC)</h2>
<table><tr><th>Indicator</th><th>Type</th></tr>
<tr><td>gehie246[.]com</td><td>Domain</td></tr></table>
</article>`);
  const eligible = (c) => publicPromoteEligibility({
    ...c,
    has_original_document_occurrence: true,
    review_status: 'context_only',
    evidence: buildCandidateEvidenceRecord(c)
  }).promotable;
  for (const u of ['yimxg25tiy.com/73inst', 'cc8ttkv35b.com/7qinst']) {
    const c = find(cands, 'url', u);
    assert.ok(c, `${u} extracted`);
    assert.equal(member(c), false);
    assert.equal(eligible(c), true, `${u} is promotable as a delivery host`);
  }
  const doc = find(cands, 'domain', 'docs-portal.example');
  assert.ok(!doc || eligible(doc) === false, 'an unrelated narrative domain is not promotable');
});

test('K. a linked pack that publishes a report file name as a domain is Context Only', () => {
  const prior = [
    { candidate_type: 'technical_artifact', normalized_value: 'sqlmap.py', has_original_document_occurrence: true },
    { candidate_type: 'technical_artifact', normalized_value: 'BBScan.py', has_original_document_occurrence: true },
    { candidate_type: 'domain', normalized_value: 'natcloudservice.com', has_original_document_occurrence: true }
  ];
  const linked = [
    toLinkedSourceCandidate({ candidate_type: 'domain', normalized_value: 'sqlmap.py' }),
    toLinkedSourceCandidate({ candidate_type: 'domain', normalized_value: 'bbscan.py' }),
    toLinkedSourceCandidate({ candidate_type: 'domain', normalized_value: 'natcloudservice.com' }),
    toLinkedSourceCandidate({ candidate_type: 'domain', normalized_value: 'evil-update.pl' })
  ];
  const out = demoteFilenameDomains(linked, prior);
  const by = (v) => out.find((c) => c.normalized_value === v);
  for (const v of ['sqlmap.py', 'bbscan.py']) {
    assert.equal(by(v).assessment, 'context_only', `${v} is the report's file, not a host`);
    assert.equal(isUnionReportIndicatorMember(by(v)), false);
  }
  assert.equal(isUnionReportIndicatorMember(by('natcloudservice.com')), true, 'a real domain stays a linked Indicator');
  assert.equal(isUnionReportIndicatorMember(by('evil-update.pl')), true, 'a .pl domain the report never lists as a file stays');
});
