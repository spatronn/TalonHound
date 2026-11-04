/**
 * Fifty-two-report batch audit regressions (tl-candidates-v49,
 * tl-section-tree-v12, tl-table-v17, tl-type-resolver-v22).
 *
 * A. An "Acknowledgments" heading under the IOC heading closes IOC scope: the
 *    citation links under it are references (35522, 35523).
 * B. "Reference IoCs" (Securelist) heads an indicator list, not a bibliography
 *    (35539); a plain "References" heading still closes scope.
 * C. Values the publisher's markup glued into one IOC-table cell split where
 *    the boundary is certain: hashes, URLs, IPv4 runs; domains never (35528).
 * D. A digest the description cell labels ("SHA-256: <hex>") is a value of its
 *    row; "Sent as POST body" rows are request content (35527).
 * E. "1.2.3.0 (Railway.com)" and "trusted services like Railway.com" name a
 *    provider, not an Indicator (35526).
 * F. A "Suspicious DLL … signed by …" row is not a legitimate signed component (35532).
 * G. A redacted "/XXXXX" path segment makes a URL a template (35529).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { TABLE_SEMANTICS_VERSION, parseDeclaredType, parseIndicatorCell } from './tableSemantics.js';


const SOURCE = 'https://www.microsoft.com/en-us/security/blog/2026/04/16/example-report/';

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

test('versions: tl-candidates-v55, tl-section-tree-v15, tl-table-v18, tl-type-resolver-v23', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v58');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v16');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v18');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v25');
});

test('A. Acknowledgments under the IOC heading closes scope: citation links are references', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><th>Domain</th><th>IP address</th><th>Port</th><th>Purpose</th></tr>
<tr><td>uw04webzoom[.]us</td><td>188.227.196[.]252</td><td>443</td><td>Payload staging</td></tr>
<tr><td>termsliva[.]com</td><td></td><td></td><td>Hosting lure script</td></tr></table>
<h3>Acknowledgments</h3>
<p>Existing blogs with similar behavior tracked:</p>
<p>https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering</p>
<p>https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis</p>
<p>https://x.com/malwrhunterteam/status/2008831892616081508</p>
<h3>Learn more</h3><p>For the latest security research, check out the blog.</p>
</article>`);
  assert.equal(member(find(cands, 'domain', 'uw04webzoom.us')), true);
  assert.equal(member(find(cands, 'ip', '188.227.196.252')), true);
  assert.equal(member(find(cands, 'domain', 'termsliva.com')), true);
  for (const u of [
    'https://cloud.google.com/blog/topics/threat-intelligence/unc1069-targets-cryptocurrency-ai-social-engineering',
    'https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis',
    'https://x.com/malwrhunterteam/status/2008831892616081508'
  ]) {
    const c = find(cands, 'url', u);
    assert.ok(!c || member(c) === false, `${u} is a citation, not an Indicator`);
  }
});

test('B. "Reference IoCs" lists indicators; a "References" heading still closes scope', () => {
  const cands = run(`<article>${BODY}
<h2>Reference IoCs</h2>
<p>Additional information about the wiper, including indicators of compromise, is available to customers of the reporting service.</p>
<p>0b83ce69d16f5ecd00f4642deb3c5895</p>
<p>c6d0f67db6a7dbf1f9394d98c1e13670</p>
<h2>References</h2>
<p>b41d0cd22d5b3e3bdb795f81421a11cb</p>
</article>`, 'https://securelist.com/example-wiper/119472/');
  assert.equal(member(find(cands, 'md5', '0b83ce69d16f5ecd00f4642deb3c5895')), true);
  assert.equal(member(find(cands, 'md5', 'c6d0f67db6a7dbf1f9394d98c1e13670')), true);
  const ref = find(cands, 'md5', 'b41d0cd22d5b3e3bdb795f81421a11cb');
  assert.ok(!ref || member(ref) === false, 'a value under References stays context');
});

const H = (seed) => seed.repeat(64 / seed.length);

test('C. glued cell values split only where the boundary is certain', () => {
  const h1 = H('a1');
  const h2 = H('b2');
  const h3 = H('c3');
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><td><strong>Indicators</strong></td><td><strong>Type</strong></td><td><strong>Description</strong></td></tr>
<tr><td>${h1}${h2}${h3}</td><td>SHA 256</td><td>Weaponized executables disguised as workplace applications.</td></tr>
<tr><td>hxxps[://]waynelimck[.]com/bid/MsTeams[.]exehxxps[://]adb-pro[.]design/Adobe/download[.]phphxxps[://]pixeldrain[.]com/api/file/CiEwUUGq?download</td><td>URLs</td><td>Malicious URLs delivering weaponized software.</td></tr>
<tr><td>136[.]0[.]157[.]51154[.]16[.]171[.]203173[.]195[.]100[.]7766[.]150[.]196[.]166</td><td>IP address</td><td>Attacker-controlled IP addresses delivering backdoor ScreenConnect</td></tr>
<tr><td>turn[.]zoomworkforce[.]usrightrecoveryscreen[.]topsmallmartdirectintense[.]comr9[.]virtualonlineserver[.]orgapp[.]ovbxbzuaiopp[.]onlineserver[.]denako-cin[.]cccold-na-phx-7[.]gofile[.]ioabsolutedarkorderhqx[.]comapp[.]amazonwindowsprime[.]compub-a6b1edca753b4d618d8b2f09eaa9e2af[.]r2[.]devcold-na-phx-8[.]gofile[.]ioserver[.]yakabanskreen[.]topserver[.]nathanjhooskreen[.]topread[.]pibanerllc[.]de</td><td>Domain</td><td>Attacker-controlled domains delivering backdoor ScreenConnect</td></tr>
<tr><td>Pacdashed[.]com</td><td>Domain</td><td>Attacker-controlled domain delivering backdoor Tactical RMM</td></tr>
</table></article>`);
  for (const h of [h1, h2, h3]) assert.equal(member(find(cands, 'sha256', h)), true, 'each glued digest is an Indicator');
  for (const u of ['https://waynelimck.com/bid/MsTeams.exe', 'https://adb-pro.design/Adobe/download.php', 'https://pixeldrain.com/api/file/CiEwUUGq?download']) {
    assert.equal(member(find(cands, 'url', u)), true, `${u} split out`);
  }
  for (const ip of ['136.0.157.51', '154.16.171.203', '173.195.100.77', '66.150.196.166']) {
    assert.equal(member(find(cands, 'ip', ip)), true, `${ip} split out`);
  }
  assert.equal(member(find(cands, 'domain', 'pacdashed.com')), true);
  // The glued domain cell has no certain boundary: nothing is invented from it.
  for (const c of cands.filter((x) => x.candidate_type === 'domain')) {
    assert.ok(!/zoomworkforce|pibanerllc|yakabanskreen/.test(c.normalized_value) || !member(c), `no guessed domain ${c.normalized_value}`);
  }
});

test('C2. a redirect target inside a URL and a non-multiple hex run are never split', () => {
  const url = parseIndicatorCell('https://t.example/r?u=https://evil.example/x', parseDeclaredType('URL'));
  assert.deepEqual(url.values.map((v) => v.normalized_value), ['https://t.example/r?u=https://evil.example/x']);
  const odd = parseIndicatorCell(H('d4') + 'abcdef', parseDeclaredType('SHA-256'));
  assert.ok(!odd.values.some((v) => v.normalized_value === H('d4')), 'a 70-char run is not two digests');
  // 1.2.3.1 + 11.2.3.4 or 1.2.3.11 + 1.2.3.4: two readings → no split.
  const ambiguous = parseIndicatorCell('1.2.3.111.2.3.4', parseDeclaredType('IP address'));
  assert.ok(!ambiguous.values.some((v) => ['1.2.3.1', '11.2.3.4', '1.2.3.11', '1.2.3.4'].includes(v.normalized_value)), 'more than one reading → no split');
  const unique = parseIndicatorCell('1.2.3.45.6.7.8', parseDeclaredType('IP address'));
  assert.deepEqual(unique.values.map((v) => v.normalized_value), ['1.2.3.4', '5.6.7.8']);
});

test('D. description-labeled digests are row values; POST-body rows are request content', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>Sfrclak[.]com</td><td>C2 domain</td><td>Resolves to 142.11.206[.]73.</td></tr>
<tr><td>%TEMP%\\6202033.ps1</td><td>Windows PowerShell payload</td><td>Downloaded from C2, self-deleting SHA-256: ${H('e5')} SHA-256: ${H('f6')}</td></tr>
<tr><td>/tmp/ld.py</td><td>Linux loader</td><td>SHA-256: ${H('a7')}</td></tr>
<tr><td>packages.npm.org/product1</td><td>npm identifier (Windows)</td><td>Sent as POST body to C2</td></tr>
</table></article>`);
  assert.equal(member(find(cands, 'domain', 'sfrclak.com')), true);
  for (const h of [H('e5'), H('f6'), H('a7')]) assert.equal(member(find(cands, 'sha256', h)), true, 'labeled digest is an Indicator');
  const body = find(cands, 'url', 'packages.npm.org/product1');
  assert.ok(!body || member(body) === false, 'a POST body string is not infrastructure');
});

test('E. hosting-provider annotations and "trusted services like" are providers', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise (IOC)</h2>
<table><tr><td>The threat actor’s authentication infrastructure is built on well-known, trusted services like Railway.com (a popular Platform-as-a-Service (PaaS)), Cloudflare, and DigitalOcean.</td><td>Type</td><td>Description</td></tr>
<tr><td>162.220.232.0 (Railway.com)</td><td>IP Range</td><td>Threat actor infrastructure observed with sign-in</td></tr>
<tr><td>89.150.45.0 (HZ Hosting)</td><td>IP Range</td><td>Threat actor infrastructure observed with sign-in</td></tr>
</table></article>`);
  assert.equal(member(find(cands, 'ip', '162.220.232.0')), true);
  assert.equal(member(find(cands, 'ip', '89.150.45.0')), true);
  const railway = find(cands, 'domain', 'railway.com');
  assert.ok(railway, 'railway.com extracted');
  assert.equal(member(railway), false, 'the PaaS provider is not an Indicator');
});

test('E2. negative: an operator domain beside an IP in prose stays an Indicator', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<p>The loader beacons to the C2 server evil-relay[.]net hosted on 203.0.113[.]77.</p>
</article>`);
  assert.equal(member(find(cands, 'domain', 'evil-relay.net')), true);
});

test('F. a "Suspicious DLL … signed by …" row is an Indicator; a legitimate signed row is not', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>${H('9c')}</td><td>SHA-256</td><td>Suspicious DLL file loaded by the above executables; also signed by Taiyuan Lihua Near Information Technology Co., Ltd. (dwmapi.dll)</td></tr>
<tr><td>${H('8d')}</td><td>SHA-256</td><td>Legitimate executable signed by Microsoft Corporation (host.exe)</td></tr>
</table></article>`);
  assert.equal(member(find(cands, 'sha256', H('9c'))), true);
  const legit = find(cands, 'sha256', H('8d'));
  assert.ok(legit, 'legitimate row extracted');
  assert.equal(member(legit), false, 'a legitimate signed component stays context');
});

test('G. a redacted /XXXXX path segment is a template, not a URL Indicator', () => {
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>• hxxps[://]vscodesettingtask[.]vercel[.]app/api/settings/XXXXX<br>• hxxps[://]coredeal2[.]vercel[.]app/api/auth</td><td>URL</td><td>Consolidated URLs across delivery and staging.</td></tr>
</table></article>`);
  assert.ok(!member(find(cands, 'url', 'https://vscodesettingtask.vercel.app/api/settings/XXXXX')));
  assert.equal(member(find(cands, 'url', 'https://coredeal2.vercel.app/api/auth')), true);
});

test('H. promote gate: actor-controlled / attacker\'s server / served malware / ioc_* lists are operational evidence', async () => {
  const { publicPromoteEligibility } = await import('./promotion.js');
  const cands = run(`<article>${BODY}
<h2>Attack chain</h2>
<p>The nested Google URL in the email body points to actor-controlled domain scanuae[.]com. This domain acts as a redirector.</p>
<p>If clicked, this domain redirected to tax-statments2025[.]com, which in turn served a malware executable named 1099-FR2025.exe.</p>
<p>The loader is downloaded later, from the attacker’s server at 69[.]67[.]173[.]30/b.</p>
<pre>let ioc_domains = dynamic(["uw05webzoom.us", "uw03webzoom.us"]);</pre>
<pre>let watched_domains = dynamic(["neutral-list.example"]);</pre>
<p>Victims also browsed travel-portal[.]example during the week.</p>
<h2>Indicators of compromise</h2>
<table><tr><th>Indicator</th><th>Type</th></tr>
<tr><td>uw04webzoom[.]us</td><td>Domain</td></tr></table>
</article>`);
  const eligible = (c) => publicPromoteEligibility({
    ...c,
    has_original_document_occurrence: true,
    review_status: 'context_only',
    evidence: buildCandidateEvidenceRecord(c)
  }).promotable;
  for (const [type, v] of [['domain', 'scanuae.com'], ['domain', 'tax-statments2025.com'], ['url', '69.67.173.30/b'], ['domain', 'uw05webzoom.us']]) {
    const c = find(cands, type, v);
    assert.ok(c, `${v} extracted`);
    assert.equal(member(c), false, `${v} is not a member by itself`);
    assert.equal(eligible(c), true, `${v} is promotable`);
  }
  for (const v of ['neutral-list.example', 'travel-portal.example']) {
    const c = find(cands, 'domain', v);
    assert.ok(!c || eligible(c) === false, `${v} is not promotable`);
  }
});

test('I. a defanged mixed-case host in prose / a plain-text pack stays a domain (v50)', async () => {
  const { plainTextToCanonicalDocument } = await import('./urlIngest.js');
  const { extractCandidatesWithDiagnostics } = await import('./candidateExtraction.js');
  const doc = plainTextToCanonicalDocument([
    '54e18978c6405f56cd59ba55a62291436639f21cf325ae509f0599b15e8f7f53',
    'txjIQslrRIg[.]MSwINSOFTUPDLoaD[.]DesiGN',
    'YHDJTyLNsMWVuU[.]DEEPinSPeCTioNsyStEM[.]OnLiNe',
    'Loader.Program.Main'
  ].join('\n\n'), {});
  const cands = extractCandidatesWithDiagnostics(doc, {}).candidates;
  assert.ok(find(cands, 'domain', 'txjiqslrrig.mswinsoftupdload.design'), 'defanged mixed-case host is a domain');
  assert.ok(find(cands, 'domain', 'yhdjtylnsmwvuu.deepinspectionsystem.online'));
  assert.ok(!find(cands, 'domain', 'loader.program.main'), 'an undefanged code identifier is still not a domain');
});

test('J. PDF appendix: inverted inferred levels and "<sha256> (<label>)" runs stay in the IOC inventory (35552)', async () => {
  const { createCanonicalDocument } = await import('./canonicalDocument.js');
  const { THREAT_LIBRARY_PDF_EXTRACTOR_VERSION } = await import('./pdfIngest.js');
  const h = (c) => c.repeat(64);
  let n = 0;
  const blk = (type, text, extra = {}) => ({ id: `p9-b${(n += 1)}`, type, page: 9, text, ...extra });
  const blocks = [
    blk('heading', 'ATTRIBUTION ASSESSMENT', { level: 3 }),
    blk('paragraph', 'The operators reused the same tooling across several intrusions in the region during the year.'),
    blk('heading', 'INDICATORS OF COMPROMISE', { level: 4 }),
    blk('heading', 'Domains', { level: 3 }),
    blk('list_item', 'evil-relay[.]example'),
    blk('heading', 'Hashes', { level: 3 }),
    blk('heading', 'Laplas', { level: 3 }),
    blk('list_item', `${h('a')} (Laplas TLS)`),
    blk('heading', 'Chvost', { level: 3 }),
    blk('paragraph', `${h('b')} (chvost (2022 plaintext TCP, C:\Users\w)) ${h('c')} (chvost (2024 TLS x64)) ${h('d')} (chvost (2025 TLS x86,`),
    blk('paragraph', 'replaced 0528))'),
    blk('heading', 'GitHub usernames', { level: 3 }),
    blk('paragraph', 'GoBuster7777 and xzj4 published the loaders.'),
    blk('heading', 'Notes', { level: 3 }),
    blk('paragraph', `The sample ${h('e')} (sibling build) is discussed in prose only and should not be read as a row of the appendix.`)
  ];
  const doc = createCanonicalDocument({ title: 'paper', blocks, meta: { extractor: THREAT_LIBRARY_PDF_EXTRACTOR_VERSION, adapter: 'pdf' } });
  const cands = extractReportCandidates({ source_type: 'pdf', source_url: null }, doc).candidates;
  for (const c of ['a', 'b', 'c', 'd']) assert.equal(member(find(cands, 'sha256', h(c))), true, `appendix hash ${c} is an Indicator`);
  assert.equal(member(find(cands, 'domain', 'evil-relay.example')), true);
  const prose = find(cands, 'sha256', h('e'));
  assert.ok(!prose || member(prose) === false, 'a prose hash after the appendix closed is not an inventory row');
});

test('I2. the real Talos pack shape (one value per line, single newlines) keeps the defanged mixed-case hosts', async () => {
  const { plainTextToCanonicalDocument } = await import('./urlIngest.js');
  const { extractCandidatesWithDiagnostics } = await import('./candidateExtraction.js');
  const doc = plainTextToCanonicalDocument([
    '54e18978c6405f56cd59ba55a62291436639f21cf325ae509f0599b15e8f7f53 ',
    'CJiTDrpwnnA[.]MswINsoFTUPDLoad[.]deSigN ',
    'txjIQslrRIg[.]MSwINSOFTUPDLoaD[.]DesiGN ',
    'hxxp[://]CJiTDrpwnnA[.]MswINsoFTUPDLoad[.]deSigN/x111111 '
  ].join('\n'), {});
  const cands = extractCandidatesWithDiagnostics(doc, {}).candidates;
  assert.ok(find(cands, 'domain', 'txjiqslrrig.mswinsoftupdload.design'), 'a pack-only mixed-case host is a domain');
  assert.ok(find(cands, 'domain', 'cjitdrpwnna.mswinsoftupdload.design'));
});

test('K. in a "<digest> (<label>)" run each digest takes its own label (35552)', () => {
  const h = (c) => c.repeat(64);
  const cands = run(`<article>${BODY}
<h2>Indicators of compromise</h2>
<h3>Hashes</h3>
<p>Dual-use tooling staged by the actor (Ligolo, Cobalt Strike, certs) ${h('1')} (Cobalt Strike beacon (staged on C2)) ${h('2')} (Ligolo TLS certificate) ${h('3')} (Ligolo-mp agent (custom build))</p>
</article>`);
  assert.equal(member(find(cands, 'sha256', h('1'))), true, 'beacon hash is a file IOC despite the "certs" lead-in');
  assert.equal(member(find(cands, 'sha256', h('3'))), true, 'agent hash is not the previous row certificate');
  assert.ok(!member(find(cands, 'sha256', h('2'))), 'the certificate fingerprint is not a file-hash Indicator');
});

test('C3. split IPs from a glued IOC-table cell survive the merge step (35528 refresh)', async () => {
  const { mergeAiCandidateUpdates } = await import('./extractionStages.js');
  const r = extractCanonicalDocumentFromHtml(`<article>${BODY}
<h2>Indicators of compromise</h2>
<table><tr><td>Indicators</td><td>Type</td><td>Description</td></tr>
<tr><td>136[.]0[.]157[.]51154[.]16[.]171[.]203</td><td>IP address</td><td>Attacker-controlled IP addresses delivering backdoor ScreenConnect</td></tr>
<tr><td>Pacdashed[.]com</td><td>Domain</td><td>Attacker-controlled domain delivering backdoor Tactical RMM</td></tr>
</table></article>`, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  const ex = extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
  const merged = mergeAiCandidateUpdates(ex.candidates, { candidate_updates: [] }, { document: ex.document });
  for (const ip of ['136.0.157.51', '154.16.171.203']) {
    assert.ok(find(merged, 'ip', ip), `${ip} kept after merge`);
  }
});
