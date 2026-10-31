/**
 * Twelve-report audit regressions (tl-candidates-v32 / tl-type-resolver-v12 /
 * tl-zones-v16 / tl-section-tree-v5 / tl-scope-engine-section-tree-v3).
 * Generic shapes of the confirmed production defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * A. A descriptive table under a C2 heading never opens C2 authority, and
 *    prose that names services only as legitimate / unblockable is not
 *    inventory: a pointer-only IOC section still delegates to body assertions.
 *    A C2 heading over a real IOC table keeps its authority.
 * B. Delegated-scope precision: a legitimate / signed binary stays excluded
 *    even when the sentence places the malice in another component; ZIP / JAR
 *    containers name the analysed sample; redaction residue and runtime
 *    namespaces are never hosts; "Internet Archive" is not a sample noun.
 * C. A role-labelled list inside an IOC section ("operator-side IPs observed:
 *    X and Y") asserts every listed value; a legitimate / victim list does not.
 * D. "Contact Form …" is not a reference heading ("Contact us" still is); a
 *    lookalike / impersonation role asserts the value it governs, never the
 *    organisation being imitated.
 * E. camelCase / PascalCase digest keys read as words (`accessTokenHash`).
 * F. Delegated-scope key-value rows ("SHA256 | <hex>") declare their type,
 *    unless the table calls the file legitimate.
 * G. Cloudflare `data-cfemail` addresses are decoded at HTML ingestion.
 *
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { decodeCloudflareEmail, decodeCloudflareEmails, HTML_BLOCKS_VERSION } from './extract/htmlBlocks.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember, hasAuthoritativePublisherIocScope } from './indicatorMembership.js';
import { classifyHexDigest, DIGEST_KINDS, labelWords } from './digestSemantics.js';
import { classifySectionRole, SECTION_ROLES } from './indicatorScope.js';
import { isRuntimeNamespace, OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import { SECTION_TREE_SCOPE_ENGINE_VERSION, SECTION_TREE_VERSION } from './sectionTree/version.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/twelve-report-audit/';
const H1 = '1'.repeat(63) + 'a';
const H2 = '2'.repeat(63) + 'b';
const H3 = '3'.repeat(63) + 'c';
const H4 = '4'.repeat(63) + 'd';
const TOKEN_HASH = '5'.repeat(63) + 'e';

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
const has = (x, type, value) => x.candidates.some((c) => c.candidate_type === type && c.normalized_value === value);
const delegated = (x) => x.diagnostics?.scope_engine?.delegated_scope === true;

// An empty formal IOC section whose only sentence names NO concrete external
// dataset: the body assertions are delegated. (A pointer to a concrete pack —
// "can be found here" → github …/campaign.txt — suppresses delegation since
// tl-section-tree-v5 / PR #25; the linked IOC Source owns that pack, see the
// pointer test below and iocSources/hrefAuthorityConsistency.test.js.)
const POINTER_IOC_SECTION = `<h2>Indicators of Compromise</h2>
<p>Indicators of Compromise are available to customers on request.</p>
<h2>References</h2>
<ul><li>https://learn.vendor.example/docs/device-code</li></ul>`;

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v48');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v20');
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v16');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v11');
  assert.equal(SECTION_TREE_SCOPE_ENGINE_VERSION, 'tl-scope-engine-section-tree-v3');
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v9');
});

// --- A. C2 authority needs an IOC inventory; provider prose does not veto ----

test('A. a descriptive endpoint table under a C2 heading opens no authority; a JSON token hash there is not an Indicator', () => {
  const x = run(`<h2>Loader analysis</h2>
<h3>C2 Communication</h3>
<table><tr><td>Endpoint</td><td>Method</td><td>Description</td></tr>
<tr><td>/health</td><td>GET</td><td>Health check with C2</td></tr>
<tr><td>/user</td><td>POST</td><td>Register infected device with the C2</td></tr></table>
<p>The figure below shows the task JSON returned by the C2.</p>
<pre><code>{
"accessTokenHash": "${TOKEN_HASH}",
"task": "exec"
}</code></pre>
<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th><th>Description</th></tr>
<tr><td>Domain-Name</td><td>loader-c2[.]example</td><td>C2 server</td></tr>
<tr><td>File</td><td>${H1}</td><td>Loader</td></tr></table>`);
  assert.equal(modeA(x), true);
  assert.deepEqual(members(x), ['domain:loader-c2.example', `sha256:${H1}`]);
});

test('A. a pointer-only IOC section still delegates when a C2 topic holds only a descriptive table and provider prose', () => {
  const x = run(`<h2>Stage 3: Instruction sheet</h2>
<p>Rather than typing commands, the threat actor pasted a URL into the chat: pastebin[.]com/AbC123xy.</p>
<h2>Stage 6: Cloud-Based Command and Control</h2>
<table><tr><td>Channel</td><td>Authentication</td><td>Normal Poll</td></tr>
<tr><td>Drive - Service Account</td><td>JSON key</td><td>45-75 seconds</td></tr>
<tr><td>Direct TLS Socket</td><td>None</td><td>45-75 seconds</td></tr></table>
<p>This C2 design is difficult to detect at the network layer. Blocking docs.cloudsuite.example or api.cloudsuite.example is not viable in most environments.</p>
${POINTER_IOC_SECTION}`);
  assert.equal(modeA(x), true);
  assert.equal(delegated(x), true);
  assert.deepEqual(members(x), ['url:pastebin.com/AbC123xy']);
});

test('A. a pointer to a concrete external IOC pack suppresses delegation (the linked source owns the pack)', () => {
  const x = run(`<h2>Stage 3: Instruction sheet</h2>
<p>Rather than typing commands, the threat actor pasted a URL into the chat: pastebin[.]com/AbC123xy.</p>
<h2>Indicators of Compromise</h2>
<p>Indicators of Compromise can be found here <a href="https://github.com/vendor/iocs/blob/main/campaign.txt">here</a>.</p>
<h2>References</h2>
<ul><li>https://learn.vendor.example/docs/device-code</li></ul>`);
  assert.equal(delegated(x), false);
  assert.equal(x.diagnostics?.scope_engine?.external_ioc_pointer, true);
  assert.deepEqual(members(x), []);
});

test('A. a C2 heading over a real IOC table keeps its authority', () => {
  const x = run(`<h2>Infrastructure</h2>
<h3>C2 servers</h3>
<table><tr><th>IP</th><th>Port</th><th>First seen</th></tr>
<tr><td>203.0.113[.]44</td><td>443</td><td>2026-05-01</td></tr>
<tr><td>198.51.100[.]9</td><td>8443</td><td>2026-05-02</td></tr></table>
<p>The operators rotated infrastructure weekly.</p>`);
  assert.equal(modeA(x), true);
  assert.deepEqual(members(x), ['ip:198.51.100.9', 'ip:203.0.113.44']);
});

// --- B. Delegated-scope precision guards ---------------------------------------

test('B. delegated scope: ZIP / JAR samples assert, a legitimate signed runtime does not, residue and namespaces are not hosts', () => {
  const x = run(`<h2>Payload retrieval</h2>
<p>The page pointed to a ZIP archive named Bundle.zip (SHA-256: ${H1.toUpperCase()}), hosted in the personal OneDrive of user@&lt;REDACTED&gt;[.]com on &lt;REDACTED&gt;-my[.]sharepoint.com. This is a compromised, legitimate tenant.</p>
<p>The archive extracts to a single Java payload, Bundle.jar (SHA-256: ${H2.toUpperCase()}).</p>
<p>The javaw.exe binary is the legitimate Oracle-signed OpenJDK Platform 25.0.1 build (SHA-256: ${H3.toUpperCase()}), all malicious logic is contained within the JAR.</p>
<table><tr><td>Category</td><td>Command</td><td>Detail</td></tr>
<tr><td>2nd stage</td><td>jc</td><td>In-memory Java compile and run via javax.tools</td></tr></table>
<p>The loader retrieves a domain list from an Internet Archive file named list.txt, then attempts to download the second stage from each domain through /${'7'.repeat(31)}f.</p>
${POINTER_IOC_SECTION}`);
  assert.equal(delegated(x), true);
  assert.deepEqual(members(x), [`sha256:${H1}`, `sha256:${H2}`]);
  assert.equal(has(x, 'domain', 'my.sharepoint.com'), false);
  assert.equal(has(x, 'domain', 'javax.tools'), false);
});

test('B. runtime namespaces are code; real hosts with the same last label are not', () => {
  assert.equal(isRuntimeNamespace(['javax', 'tools']), true);
  assert.equal(isRuntimeNamespace(['java', 'net', 'urlclassloader']), true);
  assert.equal(isRuntimeNamespace(['system', 'net', 'http']), true);
  assert.equal(isRuntimeNamespace(['java', 'com']), false);
  assert.equal(isRuntimeNamespace(['evil', 'tools']), false);
  assert.equal(isRuntimeNamespace(['system', 'example']), false);
});

// --- C. Role-labelled enumerations in IOC sections -----------------------------

test('C. "operator-side IPs observed: X and Y" in an IOC section asserts both; legitimate / victim lists do not', () => {
  const x = run(`<h2>Operator activity</h2>
<p>The operator polled the token endpoint from a cloud ASN.</p>
<h2>Indicators of Compromise</h2>
<p>Indicators of Compromise can be found in our repository.</p>
<ul>
<li>AS64500 is an active operator-side ASN observed in this campaign. Specific operator-side IPs observed: 203.0.113.10 (token-acquisition phase) and 203.0.113.11 (sustained refresh-token reuse phase).</li>
<li>Legitimate Microsoft IPs observed: 198.51.100.20 and 198.51.100.21 (sign-in service).</li>
<li>Victim IPs observed: 192.0.2.30 (corporate egress).</li>
</ul>`);
  assert.equal(modeA(x), true);
  assert.deepEqual(members(x), ['ip:203.0.113.10', 'ip:203.0.113.11']);
});

// --- D. Contact headings and lookalike roles -----------------------------------

test('D. "Contact Form Engagement" is narrative; the lookalike domains it names are asserted, the imitated brand is not', () => {
  assert.equal(classifySectionRole('Contact Form Engagement') === SECTION_ROLES.REFERENCES, false);
  assert.equal(classifySectionRole('Contact us'), SECTION_ROLES.REFERENCES);
  assert.equal(classifySectionRole('Contact'), SECTION_ROLES.REFERENCES);
  const x = run(`<h2>Contact Form Engagement</h2>
<p>The lookalike domain, brandsourcing-lookalike[.]example was registered 15 days prior to the outreach, impersonating realbrand[.]example.</p>
<p>The disposable email used to register "otherbrand-dlstribution[.]example", is also tied to several other lookalike domains registered in August.</p>
<p>The actor also referenced the genuine site, which is a lookalike of realbrand[.]example only by name.</p>
${POINTER_IOC_SECTION}`);
  assert.equal(delegated(x), true);
  assert.deepEqual(members(x), ['domain:brandsourcing-lookalike.example', 'domain:otherbrand-dlstribution.example']);
});

test('D. a "Contact us" footer still suppresses its addresses', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr><tr><td>Domain</td><td>c2-node[.]example</td></tr></table>
<h2>Contact us</h2>
<p>Reach our research team at research-desk.vendor.example for sample sharing.</p>`);
  assert.deepEqual(members(x), ['domain:c2-node.example']);
});

// --- E. Digest field names -----------------------------------------------------

test('E. camelCase digest keys are read as words; algorithm tokens keep their own reading', () => {
  const k = (label) => classifyHexDigest(`"${label}": "${H4}"`, H4).kind;
  assert.equal(k('accessTokenHash'), DIGEST_KINDS.CREDENTIAL);
  assert.equal(k('refreshTokenHash'), DIGEST_KINDS.CREDENTIAL);
  assert.equal(k('sessionKeyHex'), DIGEST_KINDS.CRYPTO_KEY);
  assert.equal(k('fileSha256'), DIGEST_KINDS.FILE);
  assert.equal(k('payloadSha256'), DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`ImpHash: ${H4}`, H4).kind, DIGEST_KINDS.SIMILARITY);
  assert.equal(classifyHexDigest(`BuildID[sha1]=${'8'.repeat(39)}a`, `${'8'.repeat(39)}a`).kind, DIGEST_KINDS.BUILD_ID);
  assert.equal(labelWords('accessTokenHash'), 'access Token Hash');
});

// --- F. Key-value hash rows in the delegated scope -----------------------------

test('F. delegated scope: "SHA256 | <hex>" key-value rows assert; a legitimate file overview does not', () => {
  const x = run(`<h2>Stage 1 dropper</h2>
<h3>File Overview</h3>
<table><tr><td>PROPERTY</td><td>VALUE</td></tr><tr><td>Filename</td><td>Setup.exe</td></tr>
<tr><td>SHA256</td><td>${H1.toUpperCase()}</td></tr><tr><td>Code Signing</td><td>Unsigned</td></tr></table>
<h2>Sideloading host</h2>
<h3>File Overview</h3>
<table><tr><td>PROPERTY</td><td>VALUE</td></tr><tr><td>Filename</td><td>Host.exe</td></tr>
<tr><td>SHA256</td><td>${H2.toUpperCase()}</td></tr><tr><td>Description</td><td>Legitimate Microsoft-signed Resource Compiler</td></tr></table>
${POINTER_IOC_SECTION}`);
  assert.equal(delegated(x), true);
  assert.deepEqual(members(x), [`sha256:${H1}`]);
});

// --- G. Cloudflare email obfuscation -------------------------------------------

test('G. data-cfemail addresses decode to the publisher text; anything else is left untouched', () => {
  // key 0x3f XOR "a@b.co"
  const hex = '3f' + Buffer.from('a@b.co').toString('hex').match(/../g).map((h) => (parseInt(h, 16) ^ 0x3f).toString(16).padStart(2, '0')).join('');
  assert.equal(decodeCloudflareEmail(hex), 'a@b.co');
  assert.equal(decodeCloudflareEmail('zz'), null);
  const html = `<td><a href="/cdn-cgi/l/email-protection" class="__cf_email__" data-cfemail="${hex}">[email&#160;protected]</a>[.]com</td>`;
  assert.equal(decodeCloudflareEmails(html), '<td>a@b.co[.]com</td>');
  const notEmail = `<span data-cfemail="3f4142">[email&#160;protected]</span>`;
  assert.equal(decodeCloudflareEmails(notEmail), notEmail);
});
