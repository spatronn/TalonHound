/**
 * Ten-report audit regressions (tl-candidates-v31 / tl-type-resolver-v11 /
 * tl-zones-v14 / tl-section-tree-v4 / tl-quality-v8). Generic shapes of the
 * confirmed production defects, with synthetic values — no publisher, report
 * or value condition:
 *
 * A. Markdown-escaped bracket defang (`host\[.\]tld`) refangs like `[.]`.
 * B. "Observations" opens an IOC section only when a declared-type IOC table
 *    leads it (MODE A follows); a narrative "Observations" section does not.
 * C. A table row labelled only by its digest algorithm takes its subject from
 *    the table heading (certificate tables); a serial number and a bare "key"
 *    label are never file hashes; sample tables keep their hashes.
 * D. A typed row / list lead-in that names its value a provider / service is a
 *    provider relation (not an assertion); a C2 / staging row stays asserted.
 * E. Numbered citation entries, the publisher's own tooling links, URN
 *    identifiers, product names and intercepted target services never become
 *    MODE B Indicators; defanged or IOC-section values are unaffected.
 *
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember, hasAuthoritativePublisherIocScope, isContextOnlyCandidate } from './indicatorMembership.js';
import { refangObservable, refangTextForExtraction, looksDefanged } from './defang.js';
import { refang as directSourceRefang } from '../directSourceEvidence.js';
import { classifyHexDigest, DIGEST_KINDS } from './digestSemantics.js';
import { annotateListStances, isQualifiedIocInventoryHeading, namesProviderService } from './indicatorScope.js';
import { hasCodeIdentifierShape, OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import { EXTRACTION_QUALITY_VERSION } from './extractionQuality.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/ten-report-audit/';
const BS = '\\';
const H1 = '1'.repeat(63) + 'a';
const H2 = '2'.repeat(63) + 'b';
const SHA1A = '4'.repeat(39) + 'd';
const M1 = '6'.repeat(31) + 'f';

function run(inner, { source = SOURCE } = {}) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: source, finalUrl: source, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: source }, r.document);
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const members = (x) => x.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
const modeA = (x) => x.candidates.some((c) => hasAuthoritativePublisherIocScope(persisted(c)));
const find = (x, type, value) => x.candidates.find((c) => c.candidate_type === type && c.normalized_value === value);

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v47');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v20');
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v16');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v10');
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v14');
});

// --- A. Markdown-escaped defang ----------------------------------------------

test('A. escaped bracket defang refangs in text, tokens and direct-source values; other backslashes stay', () => {
  const esc = `stage${BS}[.${BS}]example${BS}[.${BS}]shop`;
  assert.equal(refangTextForExtraction(`${esc} | hxxps://${esc}/files/a.dll`), 'stage.example.shop | https://stage.example.shop/files/a.dll');
  assert.equal(refangObservable(`203.0.113${BS}[.${BS}]7`), '203.0.113.7');
  assert.equal(refangObservable(`a${BS}[.]example.com`), 'a.example.com');
  assert.equal(refangObservable(`a[.${BS}]example.com`), 'a.example.com');
  assert.equal(refangObservable(`hxxps${BS}[:${BS}]//x${BS}[.${BS}]example.com`), 'https://x.example.com');
  assert.equal(directSourceRefang(`evil${BS}[.${BS}]example.org`), 'evil.example.org');
  assert.equal(looksDefanged(esc), true);
  // Windows paths, regex classes and ordinary escapes are not defang tokens.
  assert.equal(refangTextForExtraction(`C:${BS}${BS}Users${BS}${BS}Public`), `C:${BS}${BS}Users${BS}${BS}Public`);
  assert.equal(refangTextForExtraction(`match ${BS}[a-z${BS}]+`), `match ${BS}[a-z${BS}]+`);
  assert.equal(looksDefanged(`match ${BS}[a-z${BS}]+`), false);
});

test('A. an IOC table written with escaped defang yields every row as an explicit Indicator', () => {
  const rows = ['stage-one', 'stage-two', 'stage-three'].map((n, i) =>
    `<tr><td><code>${n}${BS}[.${BS}]example${BS}[.${BS}]shop</code></td><td>2026-06-0${i + 1}</td><td><code>hxxps://${n}${BS}[.${BS}]example${BS}[.${BS}]shop/files/x.dll</code></td></tr>`).join('');
  const x = run(`<h2>Indicators of compromise</h2>
<table><thead><tr><th>Domain</th><th>First Seen</th><th>URL</th></tr></thead><tbody>${rows}</tbody></table>`);
  assert.deepEqual(members(x), [
    'domain:stage-one.example.shop', 'domain:stage-three.example.shop', 'domain:stage-two.example.shop',
    'url:https://stage-one.example.shop/files/x.dll', 'url:https://stage-three.example.shop/files/x.dll', 'url:https://stage-two.example.shop/files/x.dll'
  ]);
  assert.ok(x.candidates.filter((c) => c.candidate_type === 'domain').every((c) => c.source_assertion === 'explicit_ioc'));
});

// --- B. Qualified "Observations" heading ---------------------------------------

const OBS_TABLE = `<table><thead><tr><th>Observable</th><th>Type</th><th>Name</th><th>Reference</th></tr></thead><tbody>
<tr><td>${H1}</td><td>SHA-256</td><td>loader.exe</td><td>Loader</td></tr>
<tr><td>c2-panel.example[.]net</td><td>domain-name</td><td></td><td>C2 server</td></tr>
<tr><td>203.0.113[.]44</td><td>ipv4-addr</td><td></td><td>Staging server</td></tr>
</tbody></table>`;

test('B. "Observations" + declared-type IOC table: MODE A, every row an Indicator, body narrative excluded', () => {
  const x = run(`<h2>Command and control</h2>
<p>The implant falls back to the hardcoded URL https://fallback.example[.]org when resolution fails and also beacons to body-only.example[.]com.</p>
<h2>Observations</h2>
<p>The following observables were discussed in this research.</p>
${OBS_TABLE}
<h2>References</h2><p>Vendor blog https://vendor-research.example/blog/older-post/</p>`);
  assert.equal(modeA(x), true);
  const m = members(x);
  for (const id of [`sha256:${H1}`, 'domain:c2-panel.example.net', 'ip:203.0.113.44']) assert.ok(m.includes(id), id);
  assert.ok(find(x, 'domain', 'c2-panel.example.net').source_assertion.startsWith('explicit_'));
});

test('B. a narrative "Observations" section (no declared-type IOC table) never opens an IOC scope', () => {
  assert.equal(isQualifiedIocInventoryHeading('Observations'), true);
  assert.equal(isQualifiedIocInventoryHeading('Key observations'), true);
  assert.equal(isQualifiedIocInventoryHeading('Observations from the incident response engagement and lessons learned for defenders'), false);
  const x = run(`<h2>Observations</h2>
<p>During the engagement the operators reused the server panel.example[.]net and the loader ${H1}.</p>
<table><thead><tr><th>Phase</th><th>Duration</th><th>Notes</th></tr></thead><tbody>
<tr><td>Initial access</td><td>2 days</td><td>phishing lure</td></tr></tbody></table>`);
  assert.equal(modeA(x), false, 'no authoritative section');
  assert.equal(x.candidates.some((c) => c.source_assertion && String(c.source_assertion).startsWith('explicit_')), false);
});

test('B. "Observations" over a value table without a declared type column stays narrative', () => {
  const x = run(`<h2>Observations</h2>
<table><thead><tr><th>Host</th><th>Seen</th></tr></thead><tbody>
<tr><td>panel.example[.]net</td><td>2026-05-01</td></tr></tbody></table>`);
  assert.equal(modeA(x), false);
});

// --- C. Digest semantics ---------------------------------------------------------

test('C. certificate key/value table under its own heading: SHA-256 / SHA-1 / Serial are not file hashes', () => {
  assert.equal(classifyHexDigest(`SHA-256 | ${H1}`, H1, { scopeLabel: 'Custom certificate used for TLS communication' }).kind, DIGEST_KINDS.CERTIFICATE);
  assert.equal(classifyHexDigest(`Serial | ${M1}`, M1).kind, DIGEST_KINDS.CERTIFICATE);
  assert.equal(classifyHexDigest(`using the cipher with the key (${M1}) and IV`, M1).kind, DIGEST_KINDS.CRYPTO_KEY);
  // Sample tables keep their hashes even when the heading names certificates.
  assert.equal(classifyHexDigest(`${H1} | Example Signer | ${SHA1A}`, H1, { scopeLabel: 'Malware samples signed with suspicious certificates' }).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`SHA-256 | ${H1}`, H1, { scopeLabel: 'Malware samples' }).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`SHA-256 | ${H1}`, H1, { scopeLabel: 'Indicators of Compromise' }).kind, DIGEST_KINDS.FILE);
  // A key with a file noun stays a file hash; API keys keep the credential reading.
  assert.equal(classifyHexDigest(`payload key file: ${H1}`, H1).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`API key: ${M1}`, M1).kind, DIGEST_KINDS.CREDENTIAL);
  // A registry run key names a location; a non-hex cell is never key material.
  assert.equal(classifyHexDigest(`HKCU\\Software\\Run | Run Key | ${H1}`, H1).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest('Payload | Key | N/A', 'n/a').kind, DIGEST_KINDS.FILE);

  const x = run(`<h2>Indicators of Compromise</h2>
<h3>Files</h3>
<table><thead><tr><th>Type</th><th>IOC</th><th>What it is</th></tr></thead><tbody>
<tr><td>SHA1</td><td>${SHA1A}</td><td>Backdoor</td></tr>
<tr><td>Domain</td><td>c2.example[.]net</td><td>C2</td></tr></tbody></table>
<h3>Custom certificate used for TLS communication</h3>
<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>
<tr><td>SHA-256</td><td>${H2}</td></tr>
<tr><td>Serial</td><td>${M1}</td></tr></tbody></table>`);
  assert.deepEqual(members(x), [`domain:c2.example.net`, `sha1:${SHA1A}`]);
});

// --- D. Provider / service rows and list lead-ins -----------------------------------

test('D. provider vocabulary: provider / resolver rows read as providers; C2 / staging / weaponized roles do not', () => {
  assert.equal(namesProviderService('domain | Blockchain provider | C2 URL resolution'), true);
  assert.equal(namesProviderService('domain | public DNS resolver'), true);
  assert.equal(namesProviderService('domain | C2 server | hosted at a hosting provider'), false);
  assert.equal(namesProviderService('ipv4 | Staging server | loader delivery'), false);
  assert.equal(namesProviderService('README with references to the weaponized provider domain'), false);
  assert.equal(namesProviderService('ecommerce-platform.zip | Trojanized repository'), false);
  const blocks = [
    { type: 'paragraph', text: 'The implant resolves its C2 through three public explorer providers:' },
    { type: 'list', text: 'eth.explorer-a.example.com (Ethereum L1)' },
    { type: 'list', text: 'base.explorer-a.example.com (Base L2)' }
  ];
  annotateListStances(blocks);
  assert.deepEqual(blocks.map((b) => b.list_stance), [undefined, 'non_malicious', 'non_malicious']);
  const c2 = [
    { type: 'paragraph', text: 'The malware uses the following C2 servers:' },
    { type: 'list', text: 'c2-a.example.com (primary)' }
  ];
  annotateListStances(c2);
  assert.equal(c2[1].list_stance, undefined);
});

test('D. Observations table: provider rows are context, C2 / staging rows stay Indicators', () => {
  const x = run(`<h2>Command and control</h2>
<p>The RAT decentralizes C2 lookup through two explorer providers:</p>
<ul><li>eth.explorer-a.example (Ethereum L1)</li><li>base.explorer-a.example (Base L2)</li></ul>
<h2>Observations</h2>
<table><thead><tr><th>Observable</th><th>Type</th><th>Name</th><th>Reference</th></tr></thead><tbody>
<tr><td>panel.c2-domain.example</td><td>domain</td><td>C2 panel</td><td>Hardcoded fallback</td></tr>
<tr><td>198.51.100[.]9</td><td>ipv4-addr</td><td>Staging server</td><td>Loader delivery</td></tr>
<tr><td>eth.explorer-a[.]example</td><td>domain</td><td>Blockchain provider</td><td>C2 URL resolution</td></tr>
<tr><td>base.explorer-a[.]example</td><td>domain</td><td>Blockchain provider</td><td>C2 URL resolution</td></tr>
</tbody></table>`);
  assert.deepEqual(members(x), ['domain:panel.c2-domain.example', 'ip:198.51.100.9']);
  const p = find(x, 'domain', 'eth.explorer-a.example');
  assert.ok(p && !isReportIndicatorMember(persisted(p)));
});

// --- E. MODE B references, identifiers, product names, intercepted services --------

test('E. MODE B: citations, own tooling, URN audiences, product names and intercepted services are not Indicators', () => {
  const x = run(`<h2>Analysis</h2>
<p>Our toolkit is publicly available at https://github.com/research-lab/deobfuscator [7]</p>
<p>The payload beacons to hxxps://beacon.bad-actor[.]example/gate.php every minute.</p>
<p>The kit uses the urn:ms-drs:enterpriseregistration.service-cloud.example access token to enroll a device.</p>
<p>The relay forwards traffic over WebSocket (Socket.IO) to the identity provider.</p>
<p>A wallet-specific handler intercepts /public/analytics.min.js from resources.wallet-vendor.example and substitutes a script.</p>
<h2>References</h2>
<p>[3] Disassembler (original): https://github.com/tool-author/disassembler</p>
<p>[4] Compression library: https://github.com/compression/library</p>`);
  assert.equal(modeA(x), false);
  assert.deepEqual(members(x), ['url:https://beacon.bad-actor.example/gate.php']);
  const own = find(x, 'url', 'https://github.com/research-lab/deobfuscator');
  assert.ok(own && isContextOnlyCandidate(persisted(own)), 'own tooling link is context only');
  assert.equal(find(x, 'domain', 'enterpriseregistration.service-cloud.example'), undefined, 'URN audience is not a domain');
  assert.equal(find(x, 'domain', 'socket.io'), undefined, 'product name is not a domain');
  const target = find(x, 'domain', 'resources.wallet-vendor.example');
  assert.ok(target && !isReportIndicatorMember(persisted(target)), 'intercepted service is not an Indicator');
});

test('E. a numbered IOC list inside an IOC section keeps its entries; defanged citations are not references', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<p>[1] Loader: hxxps://loader.bad-actor[.]example/a.bin</p>
<p>[2] Panel: https://panel.bad-actor.example/login</p>`);
  assert.deepEqual(members(x), ['url:https://loader.bad-actor.example/a.bin', 'url:https://panel.bad-actor.example/login']);
});

test('E. product-name shape is narrow: hostnames in one case are unaffected', () => {
  assert.equal(hasCodeIdentifierShape('Socket.IO'), true);
  assert.equal(hasCodeIdentifierShape('EVIL.IO'), false);
  assert.equal(hasCodeIdentifierShape('evil.io'), false);
  assert.equal(hasCodeIdentifierShape('Exploit.in'), false);
});
