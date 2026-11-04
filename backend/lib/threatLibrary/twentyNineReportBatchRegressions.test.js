/**
 * Twenty-nine-report batch audit regressions (35575–35605): tl-candidates-v54,
 * tl-table-v17, tl-type-resolver-v22, tl-ioc-source-scope-v4. Shapes of the
 * confirmed production defects with the publishers' own row wording.
 *
 * A. A table under "Legitimate File Hashes (SHA-256)" lists benign files, even
 *    a row "Legitimate Signed Binary, Abused for Sideloading" (35587).
 * B. "?client=[redacted]" ends the URL, so the IOC-table URL and its prose
 *    mention are one identity (35590).
 * C. "public IP address identification services:" introduces IP-echo
 *    providers, even under a C&C heading (35597).
 * D. "Certificate CN only, placeholder name. Do not block as a domain" is not
 *    an Indicator; "check before blocking" still is (35602).
 * E. "AS207043 (dedik[.]io) | ASN | Hosting …" names the ASN operator (35603).
 * F. "abused legitimate infrastructure, not itself malicious" / "not
 *    operator-specific" rows are context; a "Handle | Repository | Role"
 *    attribution table under the IOC heading is provenance (35605).
 * G. "log.events.vc0" (a file name) never yields the host "log.events" (35586).
 * H. A publisher month folder of slug-named inventories: only the files
 *    named after this article are its pack (35576).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION, trimUrlBoundary } from './observableTypeResolver.js';
import { TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { IOC_SOURCE_SCOPE_VERSION, reportSlugForeignFiles } from './iocSources/campaignScope.js';
import { applyCampaignFileSelection } from './iocSources/inspect.js';


const SOURCE = 'https://research.example/blog/twenty-nine-report/';

function run(html, source = SOURCE) {
  const r = extractCanonicalDocumentFromHtml(html, { url: source, finalUrl: source, httpStatus: 200 });
  assert.equal(r.ok, true, 'html extract ok');
  return extractReportCandidates({ source_type: 'url', source_url: source }, r.document).candidates;
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

const BODY = '<h2>Analysis</h2><p>The operators ran a multi-stage intrusion against technology targets during the quarter.</p>'
  + '<p>They staged payloads on rented servers and rotated infrastructure every few days.</p>';
const SHA_MAL = '5837bc26a73cfb46ffd466cf889f03ce2f6a48f1f3fd42ec8be22189d51cab1e';
const SHA_LEGIT = '2d99e9d732ff9304d97c7856b052ca520ae689fec1ce86df724de741913afa4b';
const SHA_ABUSED = 'd71a119b4950ee88dd36205176d989a64df5248ac268591d4bbb78621a73acbd';

test('versions: tl-candidates-v54, tl-table-v17, tl-type-resolver-v22, tl-ioc-source-scope-v4', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v57');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v18');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v24');
  assert.equal(IOC_SOURCE_SCOPE_VERSION, 'tl-ioc-source-scope-v8');
});

test('A. "Legitimate File Hashes" table: every row is a benign file, the malicious table stays Indicators', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of Compromise (IOCs)</h2>
<h4>Malicious File Hashes (SHA-256)</h4>
<table><tr><th>File / Description</th><th>SHA-256</th></tr>
<tr><td>BlkScrDl.dll (Malicious DLL)</td><td>${SHA_MAL}</td></tr></table>
<h4>Legitimate File Hashes (SHA-256)</h4>
<table><tr><th>File / Description</th><th>SHA-256</th></tr>
<tr><td>WinLpcDl.dll (Legitimate Radmin component)</td><td>${SHA_LEGIT}</td></tr>
<tr><td>Nitro_Scan2PDFApp.exe (Legitimate Signed Binary, Abused for Sideloading)</td><td>${SHA_ABUSED}</td></tr></table>
<p>Table 3: Legitimate File Indicators</p>
</article>`);
  assert.equal(member(find(cands, 'sha256', SHA_MAL)), true);
  assert.equal(member(find(cands, 'sha256', SHA_LEGIT)), false);
  assert.equal(member(find(cands, 'sha256', SHA_ABUSED)), false);
});

test('B. "[redacted]" ends a URL like an <id> placeholder; table value and prose mention share one identity', () => {
  assert.equal(trimUrlBoundary('https://iran.dashboard.1drvms.store/errors/sessionerrors/expire?client=[redacted]'),
    'https://iran.dashboard.1drvms.store/errors/sessionerrors/expire?client=');
  assert.equal(trimUrlBoundary('https://h.example/a?b=[REDACTED'), 'https://h.example/a?b=');
  // An ordinary bracketed path segment is left to the template rules.
  assert.equal(trimUrlBoundary('https://h.example/a[1]/b'), 'https://h.example/a[1]/b');
  const cands = run(`<article>${BODY}
<p>The email included a link to hxxps://iran.dashboard.1drvms[.]store/errors/sessionerrors/expire?client=[redacted] for credential harvesting.</p>
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>hxxps://iran.dashboard.1drvms[.]store/errors/sessionerrors/expire?client=[redacted]</td><td>URL</td><td>Credential harvesting page</td></tr></table>
</article>`);
  const urls = cands.filter((c) => c.candidate_type === 'url' && c.normalized_value.includes('1drvms'));
  assert.deepEqual(urls.map((c) => c.normalized_value), ['https://iran.dashboard.1drvms.store/errors/sessionerrors/expire?client=']);
  assert.equal(member(urls[0]), true);
});

test('C. IP-echo services after "public IP address identification services:" are providers under a C&C heading', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators</h2><p>See the table below.</p>
<h5>C&amp;C identity and registration</h5>
<p>It obtains this public IP from public IP address identification services:</p>
<ul><li>hxxps://api.ipify[.]org?format=json</li><li>hxxps://ipinfo[.]io/json</li></ul>
<p>It then sends this identifier as a HTTP POST request to the endpoint /api/extensions/register.</p>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>checrity[.]com</td><td>Domain</td><td>ShadowPad C&amp;C domain</td></tr></table>
</article>`);
  assert.equal(member(find(cands, 'domain', 'checrity.com')), true);
  for (const c of cands.filter((x) => /ipify|ipinfo/.test(x.normalized_value))) {
    assert.equal(member(c), false, c.normalized_value);
  }
});

test('D. "placeholder name. Do not block" row is context; "check before blocking" stays an Indicator', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of Compromise</h2>
<h3>Table 2: Added by our inventory</h3>
<table><tr><th>Type</th><th>Value</th><th>Note</th></tr>
<tr><td>IPv4</td><td>80.78.27[.]252</td><td>C2 hostname + Hestia panel. Different service and SSH key since July; check before blocking</td></tr>
<tr><td>Host</td><td>painel.installscenter[.]com</td><td>8083 and 8443</td></tr>
<tr><td>Host</td><td>painel.seu-dominio[.]com</td><td>Certificate CN only, placeholder name. Do not block as a domain</td></tr></table>
</article>`);
  assert.equal(member(find(cands, 'ip', '80.78.27.252')), true);
  assert.equal(member(find(cands, 'domain', 'painel.installscenter.com')), true);
  assert.equal(member(find(cands, 'domain', 'painel.seu-dominio.com')), false);
});

test('E. "AS<n> (host)" names the ASN operator, not an Indicator', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Notes</th></tr>
<tr><td>31[.]77[.]220[.]141</td><td>IP</td><td>Staging server. Hosted the payload</td></tr>
<tr><td>AS218731 (qwins[.]co)</td><td>ASN</td><td>Hosting for the operator's server</td></tr>
<tr><td>AS207043 (dedik[.]io)</td><td>ASN</td><td>Hosting for the earlier staging server</td></tr></table>
</article>`);
  assert.equal(member(find(cands, 'ip', '31.77.220.141')), true);
  assert.equal(member(find(cands, 'domain', 'qwins.co')), false);
  assert.equal(member(find(cands, 'domain', 'dedik.io')), false);
});

test('F. abused-legitimate / not-operator-specific rows and a Handle | Repository table are not Indicators', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of Compromise</h2>
<h3>Network Infrastructure</h3>
<table><tr><th>Indicator</th><th>Type</th><th>Context</th></tr>
<tr><td>154.86[.]119.60</td><td>IPv4</td><td>Operator server, open directory, payload staging</td></tr>
<tr><td>easy4ipcloud[.]com:8800</td><td>Domain:port</td><td>Dahua P2P relay endpoint; abused legitimate infrastructure, not itself malicious</td></tr>
<tr><td>dahuaddns[.]com / quickddns[.]com</td><td>Domain</td><td>Dahua DDNS, serial enumeration targets; abused legitimate infrastructure</td></tr>
<tr><td>rbc[.]ru</td><td>TLS subject</td><td>A shared proxy-tool default certificate on 11,000+ unrelated addresses, not operator-specific</td></tr>
<tr><td>vk[.]com/wall-163997495</td><td>URL</td><td>VKontakte community link hardcoded in the operator's Telegram notifications</td></tr></table>
<h3>Dahua P2P SDK Relay Material</h3>
<p>Upstream Attribution Handles</p>
<table><tr><th>Handle</th><th>Repository</th><th>Role</th></tr>
<tr><td>thebadinteger</td><td>github.com/thebadinteger/p2pwn</td><td>p2pwn: active use confirmed; authorship not established</td></tr>
<tr><td>ipxobd</td><td>github.com/ipxobd/CCTV-Scanner</td><td>Fingerprinting scanner, confirmed unrelated authorship</td></tr>
<tr><td>"Purple Ghosts"</td><td>MIT copyright</td><td>Publisher name on the upstream relay tool's licence</td></tr>
<tr><td>t.me/asleep_cg</td><td>Telegram</td><td>Channel printed in the brute-force engine's startup banner</td></tr></table>
<p>Table 7. Handles credited across the toolkit. Attribution of use, not of authorship.</p>
</article>`);
  assert.equal(member(find(cands, 'ip', '154.86.119.60')), true);
  assert.equal(member(find(cands, 'url', 'vk.com/wall-163997495')), true);
  for (const d of ['easy4ipcloud.com', 'dahuaddns.com', 'quickddns.com', 'rbc.ru']) {
    assert.equal(member(find(cands, 'domain', d)), false, d);
  }
  for (const u of cands.filter((c) => c.candidate_type === 'url' && /github\.com|t\.me/.test(c.normalized_value))) {
    assert.equal(member(u), false, u.normalized_value);
  }
});

test('G. a dotted file name whose last label carries a digit is not a host', () => {
  const cands = run(`<article>${BODY}
<h2>Analysis of activity</h2>
<p>Attempted username extraction from log.events.vc0 with results written to /tmp/pu.txt.</p>
<p>The host used for this operation, 108.165.147[.]64, is an Evoxt VPS.</p>
</article>`);
  assert.equal(find(cands, 'domain', 'log.events'), undefined);
  assert.ok(find(cands, 'ip', '108.165.147.64'));
});

test('H. month folder of slug-named inventories: only this article\'s files are its pack', () => {
  const report = 'https://blog.talosintelligence.com/uat-8837/';
  const paths = [
    '2026/01/UAT-7290.json',
    '2026/01/uat-7290.txt',
    '2026/01/uat-8099-new-persistence-mechanisms-and-regional-focus-keyword.txt',
    '2026/01/uat-8099-new-persistence-mechanisms-and-regional-focus.json',
    '2026/01/uat-8837.json',
    '2026/01/uat-8837.txt'
  ];
  assert.deepEqual([...reportSlugForeignFiles(paths, report)].sort(), paths.slice(0, 4).sort());
  const rows = paths.map((path) => ({ path, selected: true, parse_status: 'ok' }));
  const scoped = applyCampaignFileSelection(rows, paths.map((path) => ({ path, ok: true })), { reportUrl: report });
  assert.deepEqual(scoped.fileRows.filter((f) => f.selected !== false).map((f) => f.path), ['2026/01/uat-8837.json', '2026/01/uat-8837.txt']);
  assert.deepEqual(scoped.parseResults.map((r) => r.path), ['2026/01/uat-8837.json', '2026/01/uat-8837.txt']);
  // A "<slug>-keyword.txt" companion file is still this article's.
  const own = 'https://blog.talosintelligence.com/uat-8099-new-persistence-mechanisms-and-regional-focus/';
  assert.deepEqual([...reportSlugForeignFiles(paths, own)].sort(), ['2026/01/UAT-7290.json', '2026/01/uat-7290.txt', '2026/01/uat-8837.json', '2026/01/uat-8837.txt']);
  // Undecided: a campaign folder whose files carry no slug, or a single file.
  assert.equal(reportSlugForeignFiles(['f/README.md', 'f/samples.sha256', 'f/domains.txt'], report), null);
  assert.equal(reportSlugForeignFiles(['2026/04/powmix-botnet-targets-czech-workforce.txt'], 'https://blog.talosintelligence.com/powmix-botnet-targets-czech-workforce/'), null);
  // Every file named after this article → nothing deselected.
  assert.equal(reportSlugForeignFiles(['2026/01/uat-8837.json', '2026/01/uat-8837.txt'], report), null);
});
