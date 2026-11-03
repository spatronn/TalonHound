/**
 * 70-report audit (35700–35769) regressions (tl-candidates-v55 /
 * tl-table-v18 / tl-type-resolver-v23 / tl-section-tree-v15).
 *
 * Generic shapes of the confirmed extraction defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * FP-1 A dotted quad glued to a User-Agent product token ("Chrome/149.0.0.1")
 *      is a browser version, not an address.
 * FP-2 A search-query field before a grouped condition ("host.services: (…
 *      AND …)") is a field name, not a host under the .services TLD.
 * FP-3 A hex run that is the generated suffix of a word identifier
 *      ("anonymous-<32 hex>" account names) is not an MD5.
 * FP-4 A masked IPv4 address ("1.226.82.xxx") is never a domain under .xxx.
 * FP-5 A 64-hex value under an "MD5" column header is one SHA-256, never two
 *      glued MD5s.
 * FN-1 WordPress typography ("8×255[.]com") keeps the hostname "8x255.com".
 * FN-2 "MD5 :<hex>" (spaced label glued to the value) is that digest.
 * FN-3 A same-level "<Family> infrastructure" sibling of the open IOC heading
 *      over an Indicator | Description table continues the inventory.
 * FN-4 "Suspected source infrastructure" / "… source IPs" headings title the
 *      publisher's address inventory (Source address | Handling tables).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { TABLE_SEMANTICS_VERSION, parseIndicatorCell } from './tableSemantics.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { SECTION_ROLES, classifySectionRole } from './indicatorScope.js';
import { ipv4VersionContext } from './ipv4VersionContext.js';
import { refangObservable, refangTextForExtraction } from './defang.js';
import { hexRunIsIdentifierSuffix } from './sourceOccurrence.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/seventy-report-audit/';

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}

const persisted = (c) => ({
  ...c,
  has_original_document_occurrence: true,
  review_status: 'pending',
  evidence: buildCandidateEvidenceRecord(c)
});
const members = (x) =>
  x.candidates
    .filter((c) => isReportIndicatorMember(persisted(c)))
    .map((c) => `${c.candidate_type}:${c.normalized_value}`)
    .sort();
const has = (x, type, value) => x.candidates.some((c) => c.candidate_type === type && c.normalized_value === value);

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v55');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v18');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v23');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v15');
});

// --- FP-1: User-Agent product versions ----------------------------------------

test('FP-1 unit. a dotted quad after a User-Agent product token is a version', () => {
  const ua = 'Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136';
  const start = ua.indexOf('149.0.0.1');
  assert.deepEqual(ipv4VersionContext(ua, start, start + '149.0.0.1'.length), { kind: 'version', cue: 'user_agent_product' });
  const c2 = 'The implant connected to 149.0.0.1 over TCP.';
  const s2 = c2.indexOf('149.0.0.1');
  assert.equal(ipv4VersionContext(c2, s2, s2 + 9), null);
});

test('FP-1. a User-Agent string in prose yields no IPv4 candidate', () => {
  const x = run(`<h2>Network activity</h2>
<p>Requests used this header:</p>
<p>Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136</p>
<p>The loader then contacted 203.0.113.77 for tasking.</p>`);
  assert.equal(has(x, 'ip', '149.0.0.1'), false);
  assert.equal(has(x, 'ip', '203.0.113.77'), true);
});

// --- FP-2: search-query field names --------------------------------------------

test('FP-2. a Censys-style query field is not a domain', () => {
  const x = run(`<h2>Hunting</h2>
<p>host.service_count&lt;= 4 AND host.services: (banner_hash_sha256:"abc" AND port=443) AND host.services: (port=22 AND software.vendor="OpenBSD")</p>
<p>Operators also used c2-panel.example-bad.services for staging.</p>`);
  assert.equal(has(x, 'domain', 'host.services'), false);
  assert.equal(has(x, 'domain', 'c2-panel.example-bad.services'), true);
});

// --- FP-3: identifier suffixes --------------------------------------------------

test('FP-3 unit. a hex run after "<word>-" is an identifier suffix; algorithm labels are not', () => {
  const h = '30b17a249a34fdf5d2be64b3dfcc8494';
  const t1 = `account anonymous-${h} (user id 1)`;
  assert.equal(hexRunIsIdentifierSuffix(t1, t1.indexOf(h), t1.indexOf(h) + 32), true);
  const t2 = `MD5-${h}`;
  assert.equal(hexRunIsIdentifierSuffix(t2, 4, 36), false);
  const t3 = `sample ${h}.bin`;
  assert.equal(hexRunIsIdentifierSuffix(t3, 7, 39), false);
});

test('FP-3. AMO-style anonymous account names under an IOC heading are not MD5s', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<ul>
<li>AMO developer account: anonymous-30b17a249a34fdf5d2be64b3dfcc8494 (user id 20229996)</li>
<li>Extension SHA-256: 311c49974f28d33947b8b74d78b48f51855eacac182d519a4fe1daa6af7f30e9</li>
<li>Payload MD5: 0bbd08af95f877f1d568b03de2eb76b4</li>
</ul>`);
  assert.equal(has(x, 'md5', '30b17a249a34fdf5d2be64b3dfcc8494'), false);
  assert.ok(members(x).includes('sha256:311c49974f28d33947b8b74d78b48f51855eacac182d519a4fe1daa6af7f30e9'), members(x).join(','));
  assert.ok(members(x).includes('md5:0bbd08af95f877f1d568b03de2eb76b4'), members(x).join(','));
});

// --- FP-4: masked IPv4 ------------------------------------------------------------

test('FP-4. masked IPv4 addresses are not .xxx domains', () => {
  const x = run(`<h2>Targets</h2>
<table><tr><th>A</th><th>B</th></tr>
<tr><td>1.226.82.xxx</td><td>10.0.x.x</td></tr></table>`);
  assert.equal(x.candidates.some((c) => /x$/.test(String(c.normalized_value)) && c.candidate_type === 'domain'), false);
});

// --- FP-5 / FN-2: table digest cells ------------------------------------------------

test('FP-5 / FN-2 unit. a 64-hex value under an MD5 header stays one SHA-256; "MD5 :<hex>" parses', () => {
  const sha = '220e11c678bcba151545ce19398e08b8802103bfbbc11696f3301ea8fa38190c';
  const one = parseIndicatorCell(sha, { type: 'md5' });
  assert.deepEqual(one.values.map((v) => `${v.candidate_type}:${v.normalized_value}`), [`sha256:${sha}`]);
  // Two glued MD5s of a different total length still split (tl-table-v15).
  const glued = parseIndicatorCell('a'.repeat(32) + 'b'.repeat(32) + 'c'.repeat(32), { type: 'md5' });
  assert.equal(glued.values.length, 3);
  const spaced = parseIndicatorCell('MD5 :207b3c83c0460d5ed9091036af2b357a', null);
  assert.deepEqual(spaced.values.map((v) => `${v.candidate_type}:${v.normalized_value}`), ['md5:207b3c83c0460d5ed9091036af2b357a']);
});

test('FP-5 / FN-2. IOC table rows keep the publisher digests', () => {
  const sha = '220e11c678bcba151545ce19398e08b8802103bfbbc11696f3301ea8fa38190c';
  const x = run(`<h2>Indicators of Compromise (IOCs)</h2>
<table>
<tr><th>MD5/File name</th><th>Details</th></tr>
<tr><td>${sha}</td><td>JS File</td></tr>
<tr><td>138f29a9190acad9c392cc6fe37104b8</td><td>loader.ps1</td></tr>
</table>
<table>
<tr><th>Name</th><th>IOC</th></tr>
<tr><td>Setup_x.js</td><td>MD5 : 4d6b9efc22ec229be58b90c7991c02dd</td></tr>
<tr><td>Payload_x.js</td><td>MD5 :207b3c83c0460d5ed9091036af2b357a</td></tr>
</table>`);
  const m = members(x);
  assert.ok(m.includes(`sha256:${sha}`), m.join(','));
  assert.equal(m.some((v) => v === 'md5:220e11c678bcba151545ce19398e08b8'), false);
  assert.ok(m.includes('md5:4d6b9efc22ec229be58b90c7991c02dd'), m.join(','));
  assert.ok(m.includes('md5:207b3c83c0460d5ed9091036af2b357a'), m.join(','));
});

// --- FN-1: WordPress multiplication sign -------------------------------------------

test('FN-1. "8×255[.]com" is the hostname 8x255.com; prose dimensions are untouched', () => {
  assert.equal(refangObservable('8×255[.]com'), '8x255.com');
  assert.equal(refangTextForExtraction('a 1920×1080 screenshot'), 'a 1920×1080 screenshot');
  const x = run(`<h2>Indicators</h2>
<table><tr><th>Domain</th></tr><tr><td>8×255[.]com</td></tr><tr><td>example-bet[.]site</td></tr></table>`);
  assert.ok(members(x).includes('domain:8x255.com'), members(x).join(','));
  assert.equal(has(x, 'domain', '255.com'), false);
});

// --- FN-3: inventory tail sibling ----------------------------------------------------

test('FN-3. "<Family> infrastructure" sibling of the IOC heading continues the inventory', () => {
  const x = run(`<h2>Appendix</h2>
<h3>Indicators of Compromise</h3>
<table><tr><th>SHA-256</th><th>Role</th></tr>
<tr><td>f796eb9ecf516e4f1fafcf89200d9f7d8ddd234f705e63f1bc8fc3ef583f0248</td><td>Dropper</td></tr></table>
<h3>Leechbot infrastructure</h3>
<table><tr><th>Indicator</th><th>Description</th></tr>
<tr><td>www[.]lure-register[.]com</td><td>Lure registration</td></tr>
<tr><td>198[.]51[.]100[.]36:8085</td><td>HTTP API endpoint</td></tr>
</table>
<h2>Questions or feedback?</h2>
<p>Contact our team at research-team.example for more.</p>`);
  const m = members(x);
  assert.ok(m.includes('domain:www.lure-register.com'), m.join(','));
  assert.ok(m.includes('ip:198.51.100.36'), m.join(','));
});

test('FN-3 negative. a narrative sibling heading still closes the IOC scope', () => {
  const x = run(`<h2>Appendix</h2>
<h3>Indicators of Compromise</h3>
<table><tr><th>SHA-256</th><th>Role</th></tr>
<tr><td>f796eb9ecf516e4f1fafcf89200d9f7d8ddd234f705e63f1bc8fc3ef583f0248</td><td>Dropper</td></tr></table>
<h3>How the campaign evolved over time</h3>
<p>Victims were redirected through legit-cdn-provider.com before the payload ran.</p>`);
  assert.equal(members(x).includes('domain:legit-cdn-provider.com'), false);
});

// --- FN-4: suspected source infrastructure headings ----------------------------------

test('FN-4 unit. suspected source / scan-node infrastructure and source-IP headings', () => {
  for (const h of ['03. SUSPECTED SOURCE INFRASTRUCTURE', '02. Suspected scan-node infrastructure', '01. Observed techniques and source IPs', 'Attacker infrastructure']) {
    assert.equal(classifySectionRole(h), SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE, h);
  }
  for (const h of ['Infrastructure analysis', 'Source IPs observed in the logs suggest scanning', 'Cloud infrastructure costs', 'Attack Infrastructure Discovery', 'Attacker infrastructure analysis']) {
    assert.notEqual(classifySectionRole(h), SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE, h);
  }
});

test('FN-4. Source address | Handling rows under a suspected-infrastructure heading are Indicators', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>IPv4</th><th>Priority</th></tr><tr><td>203.0.113.10</td><td>MONITOR &amp; HUNT</td></tr></table>
<h2>03. Suspected source infrastructure</h2>
<p>Suspected source addresses associated with the activity. Treat as BLOCK / MONITOR.</p>
<table><tr><th>#</th><th>Source address</th><th>Handling</th></tr>
<tr><td>1</td><td>198.51.100.31</td><td>BLOCK / MONITOR</td></tr>
<tr><td>2</td><td>198.51.100.36</td><td>BLOCK / MONITOR</td></tr>
</table>`);
  const m = members(x);
  assert.ok(m.includes('ip:198.51.100.31'), m.join(','));
  assert.ok(m.includes('ip:198.51.100.36'), m.join(','));
});
