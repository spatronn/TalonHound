/**
 * 31-report audit regressions (tl-candidates-v34 / threat_library_html_v8 /
 * tl-type-resolver-v13 / tl-section-tree-v6 / tl-quality-v9 /
 * tl-evidence-integrity-v2 / tl-ioc-source-scope-v1). Generic shapes of the
 * confirmed production defects, with synthetic values — no publisher, report
 * or value condition:
 *
 * RC-1  a table behind inline wrappers inside <p> stays a table.
 * RC-2  a declared hash column types only exact digests; stacked sub-tables
 *       ("IP Address | Notes" mid-table) re-declare column types.
 * RC-3  spaced / mixed-bracket defang; unresolved residue is rejected.
 * RC-4  scheme-less host:port/path URL cells keep their port, no scheme invented.
 * RC-5  a row stating "not malicious" covers every hash of the row; a
 *       legitimate-stance sub-heading covers its value lines.
 * RC-6  a list lead-in naming certificate fingerprints types its items.
 * RC-7  a numbered footnote link after an IOC table is a citation.
 * RC-8  a formal IOC-title paragraph label over an inventory is MODE A, and
 *       quality reports the MODE membership uses.
 * RC-9  code calls are not hosts; a publisher disclaimer is a document stance;
 *       a model escalation needs a publisher assertion, not a mention.
 * RC-10 IOC Source discovery is anchor-local and precise; linked packs are
 *       campaign-scoped; repository roots are resolved, never walked.
 * RC-11 (30301 / MacSync): a path IOC never authorizes a broader origin URL;
 *       an inventory-listed root that coexists with path siblings stays an Indicator.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml, THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import { HTML_BLOCKS_VERSION } from './extract/htmlBlocks.js';
import { extractReportCandidates, mergeAiCandidateUpdates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember, hasAuthoritativePublisherIocScope } from './indicatorMembership.js';
import { refangTextForExtraction } from './defang.js';
import { normalizeCandidateValue } from './candidateValue.js';
import { resolveDottedToken, OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { EXTRACTION_QUALITY_VERSION } from './extractionQuality.js';
import { EVIDENCE_INTEGRITY_VERSION, groundAiCandidateUpdate, indexDocumentBlocks } from './evidenceIntegrity.js';
import { discoverIocSourcesFromHtml } from './iocSources/discover.js';
import {
  IOC_SOURCE_SCOPE_VERSION,
  asciidocToCanonicalDocument,
  distinctiveReportTokens,
  isPublisherReferenceCandidate,
  resolveGitHubCampaignFolder,
  selectCampaignScope
} from './iocSources/campaignScope.js';
import { parseIocSourceContent } from './iocSources/parseContent.js';
import { applyCampaignFileSelection } from './iocSources/inspect.js';
import { parseGitHubUrl, enumerateGitHubIocSource } from './iocSources/github.js';
import { summarizeLinkedIocSources, withLinkedSourceQuality, LINKED_SOURCE_NOT_INGESTED_CODE } from './iocSources/linkedSourceStatus.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/thirty-one/';
const H1 = 'a'.repeat(63) + '1';
const H2 = 'b'.repeat(63) + '2';
const H3 = 'c'.repeat(63) + '3';
const M1 = 'd'.repeat(31) + '4';
const S1 = 'e'.repeat(39) + '5';

function docOf(inner, source = SOURCE) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: source, finalUrl: source, httpStatus: 200 });
  assert.equal(r.ok, true);
  return r.document;
}
function run(inner, opts = {}) {
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, docOf(inner, opts.source));
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const members = (x) => x.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
const modeA = (x) => x.candidates.some((c) => hasAuthoritativePublisherIocScope(persisted(c)));

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v46');
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v9');
  assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v9');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v19');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v10');
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v14');
  assert.equal(EVIDENCE_INTEGRITY_VERSION, 'tl-evidence-integrity-v3');
  assert.equal(IOC_SOURCE_SCOPE_VERSION, 'tl-ioc-source-scope-v3');
});

// --- RC-1 -----------------------------------------------------------------------

test('RC-1. a table behind <p><span> stays a table; a hosting-provider cell never demotes the C2 IP', () => {
  const inner = `<h2>IoCs</h2><h3>Network</h3>
<p><span style="font-size: medium;"><table><thead><tr><td>IP</td><td>Domain</td><td>Hosting provider</td><td>Details</td></tr></thead>
<tbody><tr><td>203.0.113[.]10</td><td>N/A</td><td>EXAMPLE IT SOLUTIONS LIMITED</td><td>Loader C&amp;C server.</td></tr>
<tr><td>198.51.100[.]20</td><td>relay-node[.]example-c2.com</td><td>Cloudflare, Inc.</td><td>Loader C&amp;C server.</td></tr></tbody></table></span></p>`;
  const doc = docOf(inner);
  assert.equal(doc.blocks.some((b) => b.type === 'table' && /Hosting provider/.test(b.text)), true);
  assert.deepEqual(members(run(inner)), ['domain:relay-node.example-c2.com', 'ip:198.51.100.20', 'ip:203.0.113.10']);
});

// --- RC-2 -----------------------------------------------------------------------

test('RC-2. a declared hash column types only exact digests', () => {
  assert.equal(normalizeCandidateValue('203.0.113.7', 'sha256').ok, false);
  assert.equal(normalizeCandidateValue('IP Address', 'sha256').ok, false);
  assert.equal(normalizeCandidateValue('f'.repeat(41), 'sha1').ok, false, 'a 41-hex typo is no SHA-1');
  assert.equal(normalizeCandidateValue(H1, 'sha256').candidateType, 'sha256');
});

test('RC-2. stacked sub-tables in one <table>: each mid-table label row re-declares the columns', () => {
  const x = run(`<h3>IOCs</h3><table>
<tr><td><strong>SHA256</strong></td><td><strong>Notes</strong></td></tr>
<tr><td>${H1}</td><td>Stealer build A</td></tr>
<tr><td>${H2}</td><td>Stealer build B</td></tr>
<tr><td><strong>IP Address</strong></td><td><strong>Notes</strong></td></tr>
<tr><td>203.0.113[.]5</td><td>Stealer C2</td></tr>
<tr><td><strong>Domain/URL</strong></td><td><strong>Notes</strong></td></tr>
<tr><td>gate-example[.]top</td><td>Stealer C2 host</td></tr>
<tr><td>https[:]//cdn-example[.]ru/a[.]bin</td><td>Shellcode</td></tr>
<tr><td><strong>Other IOCs</strong></td><td><strong>Notes</strong></td></tr></table>`);
  assert.deepEqual(members(x), ['domain:gate-example.top', 'ip:203.0.113.5', `sha256:${H1}`, `sha256:${H2}`, 'url:https://cdn-example.ru/a.bin']);
  assert.equal(x.candidates.some((c) => c.candidate_type === 'sha256' && !/^[0-9a-f]{64}$/.test(c.normalized_value)), false, 'no label / IP typed as sha256');
});

// --- RC-3 -----------------------------------------------------------------------

test('RC-3. spaced and mixed-bracket defang refang; prose dots and unresolved residue do not', () => {
  assert.equal(refangTextForExtraction('relay-c2 [.]com'), 'relay-c2.com');
  assert.equal(refangTextForExtraction('relay-c2[ . ]com'), 'relay-c2.com');
  assert.equal(refangTextForExtraction('hxxp://203[.]0[.]113[.]9/ssd[.}png'), 'http://203.0.113.9/ssd.png');
  assert.equal(refangTextForExtraction('see a [.] b'), 'see a . b', 'a dot spaced on both sides is prose');
  assert.equal(normalizeCandidateValue('http://host.example/x[.%7Dpng').error, 'defang_residue', 'the corrupted serialisation is never persisted');
  assert.equal(normalizeCandidateValue('http://host.example/x[.}png?').error, undefined);
  assert.equal(normalizeCandidateValue('host.example/x[.').error, 'defang_residue');
  const x = run(`<h2>Indicators of Compromise</h2><table><tr><th>Value</th><th>Description</th></tr>
<tr><td>relay-c2 [.]com</td><td>C2</td></tr><tr><td>hxxp://203[.]0[.]113[.]9/ssd[.}png</td><td>Payload URL</td></tr></table>`);
  assert.deepEqual(members(x), ['domain:relay-c2.com', 'url:http://203.0.113.9/ssd.png']);
});

// --- RC-4 -----------------------------------------------------------------------

test('RC-4. a scheme-less host:port/path URL cell is a URL that keeps its port', () => {
  const n = normalizeCandidateValue('www.staging-example.net:8080/GetCluster', 'url');
  assert.equal(n.ok, true);
  assert.equal(n.candidateType, 'url');
  assert.equal(n.normalizedValue, 'www.staging-example.net:8080/GetCluster');
  assert.equal(normalizeCandidateValue('host-example.com:99999/x', 'url').ok, false, 'invalid port');
  const x = run(`<h2>Indicators of Compromise</h2><table><tr><th>Indicator Type</th><th>Value</th><th>Description</th></tr>
<tr><td>URL</td><td>www[.]staging-example[.]net:8080/GetCluster</td><td>Registration URL for staging domain.</td></tr>
<tr><td>URL</td><td>www[.]staging-example[.]net/checksum.bin</td><td>Implant download</td></tr></table>`);
  assert.deepEqual(members(x), ['url:www.staging-example.net/checksum.bin', 'url:www.staging-example.net:8080/GetCluster']);
});

// --- RC-5 -----------------------------------------------------------------------

test('RC-5. a row that states its file is not malicious covers its MD5, SHA1 and SHA256', () => {
  const x = run(`<h2>Indicators of Compromise</h2><h3>Host Based Indicators</h3>
<table><tr><th>File Name</th><th>Description</th><th>MD5</th><th>SHA1</th><th>SHA256</th><th>AV Signature</th></tr>
<tr><td>loader.dll</td><td>Sideloaded loader.</td><td>${M1}</td><td>${S1}</td><td>${H1}</td><td>MSIL/Agent!tr</td></tr>
<tr><td>host.exe</td><td>Legitimate Windows binary used to sideload the loader. Not malicious.</td><td>${'1'.repeat(32)}</td><td>${'2'.repeat(40)}</td><td>${H2}</td><td>Legitimate executable (not malicious)</td></tr></table>`);
  assert.deepEqual(members(x), [`md5:${M1}`, `sha1:${S1}`, `sha256:${H1}`]);
});

test('RC-5. a sub-heading that calls its hashes legitimate software covers the value lines', () => {
  const x = run(`<h2>Indicators of compromise</h2><h3>Dropper</h3><p>${M1}</p>
<h3>Hashes of TWApp (the legitimate software used to distribute JarApp)</h3>
<p>${'1'.repeat(32)}<br>${'2'.repeat(32)}</p>`);
  assert.deepEqual(members(x), [`md5:${M1}`]);
});

// --- RC-6 -----------------------------------------------------------------------

test('RC-6. a list lead-in naming certificate fingerprints keeps them out of file-hash Indicators', () => {
  const x = run(`<h2>Indicators of Compromise</h2><p>Domains:</p><ul><li>panel-example.duckdns[.]org</li></ul>
<p>Certificate SHA-256 Hashes for Fingerprints and Corresponding Hosts:</p>
<ul><li>${H1}</li><li>203.0.113[.]60</li></ul>
<p>SHA-256 hashes:</p><ul><li>${H2}</li></ul>`);
  assert.deepEqual(members(x), ['domain:panel-example.duckdns.org', 'ip:203.0.113.60', `sha256:${H2}`]);
});

// --- RC-7 -----------------------------------------------------------------------

test('RC-7. a numbered footnote link after an IOC table is a citation, not an Indicator', () => {
  const x = run(`<h2>Indicators of Compromise</h2><table><tr><th>Indicator Type</th><th>Value</th><th>Description</th></tr>
<tr><td>Domain</td><td>staging-example[.]net</td><td>Staging domain</td></tr></table>
<p>1 https://github.com/obfuscator-author/obfuscator.NET</p>`);
  assert.deepEqual(members(x), ['domain:staging-example.net']);
});

// --- RC-8 -----------------------------------------------------------------------

test('RC-8. a formal IOC-title paragraph label over an inventory is MODE A; quality reports the same MODE', () => {
  const x = run(`<p>Property | Value</p><table><tr><td>Name</td><td>implant</td></tr><tr><td>MD5</td><td>${M1}</td></tr></table>
<p>The implant runs from memory and hides its process.</p>
<p>Indicators of Compromise (IoCs)</p>
<table><tr><td>SHA256</td><td>File Name</td></tr><tr><td>${H1}</td><td>implant</td></tr><tr><td>${H2}</td><td>libhide.so</td></tr></table>`);
  assert.equal(modeA(x), true);
  assert.equal(x.diagnostics.quality.mode, 'A');
  assert.deepEqual(members(x), [`sha256:${H1}`, `sha256:${H2}`]);
});

test('RC-8. a bold "IOCs" label in narrative without an inventory never invents MODE A', () => {
  const x = run(`<p>IOCs</p><p>The operators rotated their infrastructure weekly and relied on relay-c2[.]com for tasking.</p>`);
  assert.equal(modeA(x), false);
});

// --- RC-9 -----------------------------------------------------------------------

test('RC-9. a call glued to a dotted token is code even with a real TLD; a port note stays a host', () => {
  assert.equal(resolveDottedToken('reg.run', { surroundingText: 'A wrapper called reg.run(None) once and returned.' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('app.run', { surroundingText: 'then app.run() starts the server' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('panel-sync.com', { surroundingText: 'the RAT connects to panel-sync.com(port 443)' }).kind, 'domain');
});

test('RC-9. a publisher disclaimer is a document stance: unasserted mentions are Context Only in MODE B', () => {
  const x = run(`<p>The program creates accounts via disposable inbox-example.tm mailboxes and posts to relay-example.com/api.</p>
<p>Account handles, repository names and hashes should not be treated as standalone malicious indicators.</p>`);
  assert.equal(modeA(x), false);
  assert.deepEqual(members(x), []);
  assert.equal(x.candidates.every((c) => c.publisher_disclaimer === true), true);
});

test('RC-9. a model malicious label needs a publisher assertion around the value, not a mention', () => {
  const inner = `<p>The tool automates sign-up through the disposable inbox-example.tm service and an identity generator.</p>
<p>The loader beacons to the C2 server relay-c2-example.com every minute.</p>`;
  const doc = docOf(inner);
  const { candidates } = extractReportCandidates({ source_type: 'url', source_url: SOURCE }, doc);
  const out = mergeAiCandidateUpdates(
    candidates,
    { candidate_updates: [
      { candidate_type: 'domain', normalized_value: 'inbox-example.tm', assessment: 'malicious', role: 'phishing', confidence: 0.8 },
      { candidate_type: 'domain', normalized_value: 'relay-c2-example.com', assessment: 'malicious', role: 'command_and_control', confidence: 0.9 }
    ] },
    { document: doc }
  );
  const inbox = out.find((c) => c.normalized_value === 'inbox-example.tm');
  const c2 = out.find((c) => c.normalized_value === 'relay-c2-example.com');
  assert.equal(inbox.ai_classification.applied, false);
  assert.equal(inbox.ai_classification.unsupported_reason, 'no_publisher_assertion');
  assert.notEqual(inbox.assessment, 'malicious');
  assert.equal(c2.ai_classification.applied, true);
  assert.equal(c2.assessment, 'malicious');
  // Uncited reading: the blocks naming the value decide.
  const blocks = indexDocumentBlocks(doc);
  assert.equal(groundAiCandidateUpdate({ candidate_type: 'domain', normalized_value: 'relay-c2-example.com' }, {}, blocks).supported, true);
  assert.equal(groundAiCandidateUpdate({ candidate_type: 'domain', normalized_value: 'inbox-example.tm' }, {}, blocks).supported, false);
});

// --- RC-10: discovery -------------------------------------------------------------

const DISCOVERY_PAGE = `<html><body><article>
<h2>Indicators of Compromise</h2>
<p>A comprehensive list of indicators of compromise (IoCs) and samples can be found in our <a href="https://github.com/vendor/malware-ioc/tree/master/campaign_x">GitHub repository</a>.</p>
<p>MD5 <a href="https://opentip.kaspersky.com/${M1}/results">${M1}</a></p>
<p>Deobfuscation script can be found <a href="https://github.com/vendor/iocs/blob/main/campaign_x/deob.js">here</a>.</p>
<ul><li><a href="https://vendor-research.example/tag/malware/">Malware</a></li><li><a href="https://vendor-research.example/author/analyst/">Analyst</a></li></ul>
<p><a href="https://vendor-research.example/blog/previous-post/">Previous Blog Post</a> <a href="https://vendor-research.example/blog/thirty-one/#respond">Cancel</a></p>
<p>This site uses Akismet to reduce spam. <a href="https://akismet.com/privacy/">Learn how your comment data is processed.</a></p>
<table><tr><td>URL</td><td><a href="https://nodejs.example/dist/node-v18-win-x64.zip">https://nodejs.example/dist/node-v18-win-x64.zip</a></td><td>Node.js download URL</td></tr></table>
<p>For inquiries visit the <a href="https://vendor-research.example/threat-intelligence/">Threat Intelligence</a> page.</p>
</article></body></html>`;

test('RC-10. discovery accepts only the anchor-local publisher IOC pack under an IOC heading', () => {
  const found = discoverIocSourcesFromHtml(DISCOVERY_PAGE, { reportUrl: SOURCE });
  assert.deepEqual(found.map((f) => f.canonical_url), ['https://github.com/vendor/malware-ioc/tree/master/campaign_x']);
});

test('RC-10. a publisher pointer to a pack file and to a repository root are both recorded', () => {
  const html = `<html><body><article><h2>Indicators of Compromise</h2>
<p>Indicators of Compromise can be found <a href="https://github.com/vendor/iocs/blob/main/X/X-IoCs.txt">here</a>.</p>
<p>A comprehensive list of IoCs can be found in our <a href="https://github.com/vendor/malware-ioc/tree/master/">GitHub repository</a>.</p></article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, { reportUrl: SOURCE }).map((f) => f.canonical_url).sort();
  assert.equal(found.length, 2);
  assert.equal(parseGitHubUrl('https://github.com/vendor/malware-ioc/tree/master/').path, '');
});

// --- RC-10: campaign scope ---------------------------------------------------------

const README_MULTI = `= VendorAPT -- Indicators of Compromise

== VendorAPT: Thirty-one report campaign
The blog post is available at ${SOURCE}

=== Files
[options="header"]
|===
|SHA-1 |Filename |Detection |Description
|\`${S1.toUpperCase()}\` |setup.exe |Win32/Agent |Downloader.
|===

=== Network
[options="header"]
|===
|IP |Domain |Hosting provider |First seen |Details
|\`+203.0.113[.]70+\` |relay-example[.]com |EXAMPLE CLOUD LTD |2026-01-01 |C&C server.
|\`+198.51.100[.]71+\` |N/A |Cloudflare, Inc. |2026-01-02 |C&C server hidden behind Cloudflare.
|===

== VendorAPT 2018 watering hole
=== Network
|===
|\`+192.0.2[.]99+\` |old-campaign[.]example
|===

== MITRE ATT&CK techniques
https://attack.mitre.org/resources/versions/
`;

test('RC-10. AsciiDoc README: only the section tied to the report; tables stay tables; refs dropped', async () => {
  const parsed = await parseIocSourceContent({
    body: README_MULTI,
    contentType: 'text/plain',
    url: 'https://raw.githubusercontent.com/vendor/malware-ioc/sha/vendorapt/README.adoc',
    path: 'vendorapt/README.adoc',
    reportScope: { reportUrl: SOURCE, reportTitle: 'VendorAPT: Thirty-one report campaign' }
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.scope.status, 'campaign_section');
  assert.equal(parsed.scope.multi_campaign, true);
  const keys = parsed.candidates.map((c) => `${c.candidate_type}:${c.normalized_value}:${c.assessment}`).sort();
  assert.deepEqual(keys, [
    'domain:relay-example.com:malicious',
    'ip:198.51.100.71:malicious',
    'ip:203.0.113.70:malicious',
    `sha1:${S1}:malicious`
  ]);
});

test('RC-10. AsciiDoc listing blocks: a defang bracket is never read as link-macro text', async () => {
  const body = `== Campaign X
The post: ${SOURCE}

=== URLs

----
http://www.host-example[.]co.kr/upload/me.jpg
http://other-example.co[.]kr/a.jpg
----
`;
  const parsed = await parseIocSourceContent({
    body, contentType: 'text/plain', url: 'https://raw.githubusercontent.com/v/r/s/x/README.adoc', path: 'x/README.adoc',
    reportScope: { reportUrl: SOURCE, reportTitle: 'Campaign X' }
  });
  assert.deepEqual(parsed.candidates.map((c) => c.normalized_value).sort(), [
    'http://other-example.co.kr/a.jpg',
    'http://www.host-example.co.kr/upload/me.jpg'
  ]);
});

test('RC-10. a README not tied to the report contributes nothing', async () => {
  const parsed = await parseIocSourceContent({
    body: README_MULTI,
    contentType: 'text/plain',
    url: 'https://raw.githubusercontent.com/vendor/malware-ioc/sha/vendorapt/README.adoc',
    path: 'vendorapt/README.adoc',
    reportScope: { reportUrl: 'https://vendor-research.example/blog/another-report/', reportTitle: 'Unrelated espionage campaign' }
  });
  assert.equal(parsed.ok, false);
  assert.equal(parsed.code, 'campaign_scope_unresolved');
});

test('RC-10. single-campaign README is whole; multi-campaign folder hash lists are deselected', () => {
  const single = asciidocToCanonicalDocument(`= Op -- Indicators of Compromise\nThe post: ${SOURCE}\n\n== IoCs\n=== Files\n|===\n|\`${S1}\` |a.exe\n|===\n`);
  assert.equal(selectCampaignScope(single, { reportUrl: SOURCE, reportTitle: 'x' }).status, 'single_campaign');
  const files = [{ path: 'f/README.adoc' }, { path: 'f/samples.sha256' }, { path: 'f/samples.md5' }];
  const multi = applyCampaignFileSelection(files, [{ path: 'f/README.adoc', scope: { multi_campaign: true } }, { path: 'f/samples.sha256' }]);
  assert.deepEqual(multi.deselected, ['f/samples.sha256', 'f/samples.md5']);
  assert.equal(multi.fileRows.filter((f) => f.selected === false).length, 2);
  const one = applyCampaignFileSelection(files, [{ path: 'f/README.adoc', scope: { multi_campaign: false } }]);
  assert.deepEqual(one.deselected, []);
});

test('RC-10. publisher self-links and ATT&CK links are references, never linked indicators', () => {
  assert.equal(isPublisherReferenceCandidate({ candidate_type: 'url', normalized_value: SOURCE }, { reportUrl: SOURCE }), true);
  assert.equal(isPublisherReferenceCandidate({ candidate_type: 'url', normalized_value: 'https://attack.mitre.org/techniques/T1059/' }, {}), true);
  assert.equal(isPublisherReferenceCandidate({ candidate_type: 'domain', normalized_value: 'relay-example.com' }, { reportUrl: SOURCE }), false);
});

test('RC-10. a "no longer infected" remark in a linked file is a remediated stance', async () => {
  const parsed = await parseIocSourceContent({
    body: 'IPv4:\n\n203.0.113.80 - Campaign C2\n\nURL:\n\nhxxps://github[.]com/someone/ShopApp - GitHub repo (no longer infected with backdoor)\n',
    contentType: 'text/plain',
    url: 'https://raw.githubusercontent.com/vendor/iocs/main/X/X-IoCs.txt',
    path: 'X/X-IoCs.txt',
    reportScope: { reportUrl: SOURCE, reportTitle: 'X' }
  });
  const byKey = Object.fromEntries(parsed.candidates.map((c) => [`${c.candidate_type}:${c.normalized_value}`, c.assessment]));
  assert.equal(byKey['ip:203.0.113.80'], 'malicious');
  assert.equal(byKey['url:https://github.com/someone/ShopApp'], 'context_only');
});

test('RC-10. a repository root is never enumerated; the campaign folder is resolved by name + README backlink', async () => {
  const listing = await enumerateGitHubIocSource('https://github.com/vendor/malware-ioc/tree/master/', { fetchImpl: async () => { throw new Error('no fetch expected'); } });
  assert.equal(listing.code === 'repository_root_requires_scope' || listing.ok === false, true);
  const tree = {
    '': [{ name: 'oceanx', type: 'dir', path: 'oceanx' }, { name: 'UAC-0099', type: 'dir', path: 'UAC-0099' }, { name: 'README.adoc', type: 'file', path: 'README.adoc' }],
    'UAC-0099': [{ name: 'MATCHX', type: 'dir', path: 'UAC-0099/MATCHX' }],
    'UAC-0099/MATCHX': [{ name: 'README.adoc', type: 'file', path: 'UAC-0099/MATCHX/README.adoc' }, { name: 'samples.sha1', type: 'file', path: 'UAC-0099/MATCHX/samples.sha1' }]
  };
  const files = { 'UAC-0099/MATCHX/README.adoc': `== MATCHX -- IoCs\nThe blog post: ${SOURCE}\n` };
  const io = { listDir: async (p) => tree[p] || [], readFile: async (p) => files[p] || null };
  const report = { reportUrl: SOURCE, reportTitle: 'MATCHX: New tricks', headings: ['UAC-0099 profile', 'MATCHX 101', 'Conclusion'] };
  assert.deepEqual(distinctiveReportTokens({ title: report.reportTitle, headings: report.headings }).includes('uac0099'), true);
  const ok = await resolveGitHubCampaignFolder({ owner: 'vendor', repo: 'malware-ioc', ref: 'master', path: '' }, report, io);
  assert.equal(ok.ok, true);
  assert.equal(ok.path, 'UAC-0099/MATCHX');
  assert.ok(ok.requests <= 8, 'bounded requests');
  const none = await resolveGitHubCampaignFolder({ owner: 'vendor', repo: 'malware-ioc', ref: 'master', path: '' }, { reportUrl: 'https://other.example/x', reportTitle: 'Unrelated', headings: [] }, io);
  assert.equal(none.ok, false);
});

test('RC-10. an un-ingested publisher pack overlays a quality warning at read time', () => {
  const summary = summarizeLinkedIocSources([{ lifecycle_status: 'discovered' }, { lifecycle_status: 'extracted' }, { lifecycle_status: 'dismissed' }]);
  // scope_mismatch: tl-ioc-source-scope-v3 (sources leading to other reports).
  assert.deepEqual(summary, { declared: 2, extracted: 1, pending: 1, unresolved: 0, dismissed: 1, scope_mismatch: 0 });
  const q = withLinkedSourceQuality({ status: 'clean', counts: { high: 0, warning: 0, info: 0 }, warnings: [] }, summary);
  assert.equal(q.status, 'warning');
  assert.equal(q.warnings[0].code, LINKED_SOURCE_NOT_INGESTED_CODE);
  const done = withLinkedSourceQuality({ status: 'clean', warnings: [] }, summarizeLinkedIocSources([{ lifecycle_status: 'extracted' }]));
  assert.equal(done.status, 'clean');
});

test('RC-10. OpenTIP lookups, same-site tags, and comment chrome never register as IOC Sources', () => {
  const html = `<html><body><article>
<h2>Indicators of Compromise</h2>
<p>Stage one loader ${M1}</p>
<p>URL hxxps://toria[.]app/ hxxps://docsend.appstore.com[.]mx/dcc737d157ef4271/stage2.enc</p>
<p>MD5 <a href="https://opentip.kaspersky.com/${M1}?icid=gl_sl_opentip-lnk">${M1}</a></p>
<p><a href="https://opentip.kaspersky.com/hxxps%3a%2f%2fdocsend.appstore.com.mx?icid=gl_sl">lookup</a></p>
<ul>
<li><a href="https://securelist.example/tag/apple-macos">Apple MacOS</a></li>
<li><a href="https://securelist.example/tag/infostealers">Infostealers</a></li>
<li><a href="https://securelist.example/macsync-new-version/121383?replytocom=3582213">Reply</a></li>
</ul>
<p>This site uses Akismet. <a href="https://akismet.com/privacy">Privacy</a>.</p>
</article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, { reportUrl: 'https://securelist.example/macsync-new-version/121383/' });
  assert.deepEqual(found, []);
});

// --- RC-11: origin URL authority (30301 MacSync shape) ------------------------------

test('RC-11. path IOCs do not authorize a C2-chrome origin; inventory-listed roots stay', () => {
  const inner = `<h2>Indicators of compromise</h2>
<p>Stage one loader</p>
<p>${M1}</p>
<p>${'a'.repeat(31)}5</p>
<p>URL</p>
<p>hxxps://toria[.]app/</p>
<p>hxxps://toria.apple03cloudstore[.]com/</p>
<p>hxxps://toria.apple03cloudstore[.]com/e3c1a6b00bc31e14/stage2.enc</p>
<p>hxxps://docsend.appstore.com[.]mx/dcc737d157ef4271/stage2.enc</p>
<p>hxxps://docsend.appstore.com[.]mx/dcc737d157ef4271/CoreUpdate.pkg.enc</p>
<p>hxxps://docsend.appstore.com[.]mx/dcc737d157ef4271/Helper.pkg.enc</p>
<h3>C2</h3>
<p>hxxps://docsend.appstore[.]com[.]mx</p>
<p>hxxps://toria.apple03cloudstore[.]com</p>`;
  const got = members(run(inner));
  assert.equal(got.includes('url:https://docsend.appstore.com.mx/'), false, 'C2-chrome docsend origin demoted');
  assert.equal(got.includes('url:https://toria.apple03cloudstore.com/'), true, 'inventory toria root kept');
  assert.equal(got.includes('url:https://toria.app/'), true);
  assert.equal(got.includes('url:https://docsend.appstore.com.mx/dcc737d157ef4271/stage2.enc'), true);
  assert.equal(got.includes('url:https://docsend.appstore.com.mx/dcc737d157ef4271/CoreUpdate.pkg.enc'), true);
  assert.equal(got.includes('url:https://docsend.appstore.com.mx/dcc737d157ef4271/Helper.pkg.enc'), true);
  assert.equal(got.includes('url:https://toria.apple03cloudstore.com/e3c1a6b00bc31e14/stage2.enc'), true);
  assert.equal(got.includes(`md5:${M1}`), true);
});
