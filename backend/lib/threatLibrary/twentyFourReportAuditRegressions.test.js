/**
 * Twenty-four-report audit regressions (tl-candidates-v40 / tl-table-v12 /
 * tl-type-resolver-v17 / tl-section-tree-v9 / tl-quality-v14 /
 * tl-ioc-source-scope-v3). Generic shapes of the confirmed defects of the
 * 2026-10-26 Huntress batch, each with its negative control:
 *
 * A. A mixed IOC-table cell (file paths, a plural "MD5s:" label, several
 *    hashes; or a path with spaces) yields every labelled hash.
 * B. "host:port" endpoints are the host (a domain Indicator) with the port on
 *    the occurrence; a file name with a port stays a file name.
 * C. An IOC heading whose own section is only a lead-in continues into its
 *    same-level indicator-class siblings ("## Network"); "Primary IOCs" is an
 *    IOC heading; unrelated siblings never inherit authority.
 * D. Hosts-file sinkhole lines, account identifiers, spoofed sender domains
 *    and truncated copies of a listed URL are not Indicators; a listed C2
 *    domain beside them, a file hash, a defanged non-spoofed address domain
 *    and a different path stay Indicators.
 * E. A row that calls its URL a lure is asserted although it names the
 *    hosting service legitimate; prose that calls a site legitimate keeps it
 *    Context Only.
 * F. A folder IOC Source file whose metadata row names another article is
 *    deselected; a file that names this report is kept.
 *
 * Values are public IOCs from the audited reports or documentation shapes.
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { parseIndicatorCell, TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { classifySectionRole } from './indicatorScope.js';
import { classifyHexDigest, DIGEST_KINDS } from './digestSemantics.js';
import { validateUrlCandidate, OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { assessExtractionQuality, EXTRACTION_QUALITY_VERSION, QUALITY_CODES } from './extractionQuality.js';
import { IOC_SOURCE_SCOPE_VERSION, inventoryBacklinkScope, inventoryReportBacklink } from './iocSources/campaignScope.js';
import { applyCampaignFileSelection } from './iocSources/inspect.js';
import { foldSchemeLessLinkedUrls } from './iocSources/extract.js';
import { parseIocSourceContent } from './iocSources/parseContent.js';
import {
  LINKED_SOURCE_SCOPE_MISMATCH_CODE,
  summarizeLinkedIocSources,
  withLinkedSourceQuality
} from './iocSources/linkedSourceStatus.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = 'https://vendor-research.example/blog/twenty-four-report-audit/';

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
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const find = (out, value) => out.candidates.find((c) => String(c.normalized_value).toLowerCase() === value.toLowerCase());
const member = (out, value) => {
  const c = find(out, value);
  return Boolean(c) && isReportIndicatorMember(persisted(c));
};
const members = (out) => out.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
const cell = (parts) => parts.map((p) => `<p>${p}</p>`).join('');
const iocTable = (rows, heading = 'Indicators of Compromise (IOCs)', level = 2) => `<h${level}>${heading}</h${level}>
<table><tr><th>Item</th><th>Description</th></tr>
${rows.map(([v, d]) => `<tr><td>${v}</td><td><p>${d}</p></td></tr>`).join('\n')}
</table>`;

test('versions: tl-candidates-v40, tl-table-v12, tl-type-resolver-v17, tl-section-tree-v9, tl-quality-v14, tl-ioc-source-scope-v3', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v45');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v13');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v19');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v10');
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v14');
  assert.equal(IOC_SOURCE_SCOPE_VERSION, 'tl-ioc-source-scope-v3');
});

// --- A. Mixed multi-value cells -------------------------------------------

test('A: file paths + plural "MD5s:" label + several hashes in one cell → every hash (33332 NJRAT row)', () => {
  const hashes = ['2a0834560ed3770fc33d7a42f8229722', '57b9c56ef97a7ada98257b23577bf5e3', '60a0f58001ea7be538cd42b651924cc7'];
  const out = run(iocTable([
    [cell(['%TEMP%\\licensechecker.exe', '%TEMP%\\rockstar.exe', '%TEMP%\\any.ran.exe', 'MD5s:', ...hashes]), 'Copies of NJRAT and associated launchers'],
    [cell(['Gta6installer.exe', 'MD5: a15e280a3fd65dfaa243bbe2dbf45e97']), 'Initial installation executable']
  ]));
  for (const h of [...hashes, 'a15e280a3fd65dfaa243bbe2dbf45e97']) assert.equal(member(out, h), true, h);
  // The file identities stay context, never network Indicators.
  assert.equal(member(out, '%TEMP%\\licensechecker.exe'), false);
  assert.equal(member(out, 'any.ran.exe'), false);
});

test('A: a path with spaces / [RANDOM FILE NAME] placeholder does not discard the labelled hash (33332 DCRAT row)', () => {
  const out = run(iocTable([
    [cell(['%TEMP%\\rockstargames.exe', '%TEMP%\\P3usMXh1h4.bat', 'C:\\Users\\Default\\Local Settings\\[RANDOM FILE NAME].exe', 'MD5:', '8da3fe3664d81226b0fb2a50a0537d4f']), 'Copy of DCRAT and associated installation files']
  ]));
  assert.equal(member(out, '8da3fe3664d81226b0fb2a50a0537d4f'), true);
});

test('A (negative): an unlabelled digest in a mixed prose remainder is still only reported, not emitted', () => {
  // A leading file identity + a prose remainder (decomposed mixed cell).
  const r = parseIndicatorCell('%TEMP%\\loader.exe connects to the operator and drops 8da3fe3664d81226b0fb2a50a0537d4f later on', null);
  assert.ok(r.values[0].cell_residual, 'remainder reported');
  assert.ok(!r.values.some((v) => v.normalized_value === '8da3fe3664d81226b0fb2a50a0537d4f'));
  // A labelled one in the same kind of unparseable remainder is a value.
  const labelled = parseIndicatorCell('%TEMP%\\loader.exe Local Settings MD5: 8da3fe3664d81226b0fb2a50a0537d4f', null);
  assert.ok(labelled.values.some((v) => v.candidate_type === 'md5' && v.normalized_value === '8da3fe3664d81226b0fb2a50a0537d4f'));
});

// --- B. host:port ----------------------------------------------------------

test('B: "host:port" cells are domain Indicators with the port kept (33332 ngrok, 33351 NetSupport C2)', () => {
  const out = run(iocTable([
    [cell(['35.157.111[.]131', '7.tcp.eu.ngrok[.]io:12684.']), 'IP and ngrok addresses that NJRAT connects to'],
    ['poronto[.]com:688', 'NetSupport RAT C2'],
    ['giovettiadv[.]com:688', 'NetSupport RAT C2']
  ]));
  for (const d of ['7.tcp.eu.ngrok.io', 'poronto.com', 'giovettiadv.com']) {
    const c = find(out, d);
    assert.ok(c, d);
    assert.equal(c.candidate_type, 'domain', d);
    assert.equal(member(out, d), true, d);
  }
  assert.ok(find(out, 'poronto.com').occurrences.some((o) => o.port === 688));
  assert.equal(member(out, '35.157.111.131'), true);
});

test('B (negative): a file name with a port, an out-of-range port and a time are not domains', () => {
  for (const text of ['loader.exe:1234', 'evil-host.net:70000', '10:30']) {
    const r = parseIndicatorCell(text, null);
    assert.ok(!r.values.some((v) => v.candidate_type === 'domain' && v.is_ioc !== false), text);
  }
});

// --- C. Section-tree authority --------------------------------------------

const leadInSiblings = (afterNetwork) => `
<h2>Detection and response</h2><p>Hunt for the behaviours described above.</p>
<h2>Indicators of Compromise (IOCs)</h2>
<p>Network indicators and file hashes are provided below.</p>
<h2>Network</h2>
<table><tr><th>Item</th><th>Description</th></tr>
<tr><td>agenticsora[.]com</td><td>Delivery C2</td></tr>
<tr><td>85.206.161[.]241:8443</td><td>RAT C2</td></tr>
<tr><td>main.southcarolinacounselor[.]com/modules/wallets</td><td>Seed drop</td></tr>
</table>
<h2>File hashes (SHA-256)</h2>
<table><tr><th>File</th><th>SHA-256</th></tr>
<tr><td>Agent RAT</td><td>3ae26ed89d3a1a140edc89ca78513aba2895789ed0d0f64cad6605b6f2347c7e</td></tr>
</table>
${afterNetwork}`;

test('C: a lead-in-only IOC heading continues into same-level indicator-class siblings (33344)', () => {
  const out = run(leadInSiblings(''));
  for (const v of ['agenticsora.com', '85.206.161.241', 'main.southcarolinacounselor.com/modules/wallets',
    '3ae26ed89d3a1a140edc89ca78513aba2895789ed0d0f64cad6605b6f2347c7e']) {
    assert.equal(member(out, v), true, v);
  }
});

test('C (negative): the chain ends at the first non-indicator-class sibling; no authority leakage', () => {
  const out = run(leadInSiblings(`<h2>MITRE ATT&amp;CK</h2>
<table><tr><th>Tactic</th><th>Technique</th></tr><tr><td>Execution</td><td>T1059.004</td></tr></table>
<h2>Conclusion</h2><p>The operator also staged files on 203.0.113[.]77 before the intrusion.</p>`));
  assert.equal(member(out, 'agenticsora.com'), true);
  assert.equal(member(out, '203.0.113.77'), false);
});

test('C (negative): an IOC heading with its own inventory does not adopt a later same-level "Network …" sibling', () => {
  const out = run(`${iocTable([['agenticsora[.]com', 'Delivery C2']])}
<h2>Network security recommendations</h2>
<table><tr><th>Item</th><th>Description</th></tr><tr><td>45.11.57[.]9</td><td>Address the operator scanned from</td></tr></table>`);
  assert.equal(member(out, 'agenticsora.com'), true);
  assert.equal(member(out, '45.11.57.9'), false);
});

test('C: "Primary IOCs" is an IOC heading; narrative "Primary indicators …" sentences are not (33345)', () => {
  assert.equal(classifySectionRole('Primary IOCs'), 'ioc_appendix');
  assert.equal(classifySectionRole('Primary Indicators of Compromise'), 'ioc_appendix');
  assert.equal(classifySectionRole('Primary indicators suggest a Chinese-speaking operator'), null);
  const out = run(`<h2>Primary IOCs</h2>
<table><tr><th>Indicator</th><th>Description</th></tr>
<tr><td>download-app[.]us</td><td>Domain, ClaudeDesktop.exe Redirect</td></tr>
<tr><td>26bae4d7012bf59847ab4036a065419c3d4ca47e020479f55b3b2c6d0d21394a</td><td>SHA256 libcef.dll</td></tr>
<tr><td>fd826215add30c1319eefa291b6eaf8ddfa7720cfe816c49aef6fe8a88de7939</td><td>SHA256 SSLConf.exe (BENIGN)</td></tr>
</table>`);
  assert.equal(member(out, 'download-app.us'), true);
  assert.equal(member(out, '26bae4d7012bf59847ab4036a065419c3d4ca47e020479f55b3b2c6d0d21394a'), true);
  // The publisher's BENIGN row stays Context Only.
  assert.equal(member(out, 'fd826215add30c1319eefa291b6eaf8ddfa7720cfe816c49aef6fe8a88de7939'), false);
});

// --- D. False-positive shapes -----------------------------------------------

test('D: hosts-file sinkhole lines are context; the C2 row of the same table stays an Indicator (33332)', () => {
  const out = run(iocTable([
    [cell(['0.0.0.0 app.adjust.com', '0.0.0.0 telemetry.malwarebytes.com', '0.0.0.0 ws.mcafee.com']), 'Entries added to the host file by DCRAT'],
    ['a0700877.xsph[.]ru (141.8.197[.]42)', 'Domain and IP address that DCRAT connects to']
  ]));
  for (const d of ['app.adjust.com', 'telemetry.malwarebytes.com', 'ws.mcafee.com']) {
    assert.equal(member(out, d), false, d);
    assert.equal(find(out, d)?.policy_decision, 'context_only_hosts_file_entry', d);
  }
  assert.equal(member(out, 'a0700877.xsph.ru'), true);
  assert.equal(member(out, '141.8.197.42'), true);
  assert.equal(member(out, '0.0.0.0'), false);
  const q = assessExtractionQuality({ blocks: out.document.blocks, candidates: out.candidates, diagnostics: out.diagnostics });
  assert.ok(q.warnings.some((w) => w.code === QUALITY_CODES.HOSTS_FILE_ENTRIES_CONTEXT));
});

test('D: a hex identifier the row labels an account tag is not a malware hash; a file MD5 still is (33339)', () => {
  assert.equal(classifyHexDigest('5568cd69c754b392121f1dbb8f900fda', '5568cd69c754b392121f1dbb8f900fda',
    { rowDescription: 'Malicious Cloudflare tunnel account tag' }).kind, DIGEST_KINDS.IDENTIFIER);
  assert.equal(classifyHexDigest('bot ID 5568cd69c754b392121f1dbb8f900fda', '5568cd69c754b392121f1dbb8f900fda').kind, DIGEST_KINDS.IDENTIFIER);
  assert.equal(classifyHexDigest('MD5 of tunnel.exe: 5568cd69c754b392121f1dbb8f900fda', '5568cd69c754b392121f1dbb8f900fda').kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest('x', '5568cd69c754b392121f1dbb8f900fda',
    { rowDescription: 'Loader that fetches the campaign ID from C2' }).kind, DIGEST_KINDS.FILE);
  const out = run(iocTable([
    ['23.234.100[.]105', 'Intruder IPv4 (Tzulo VPN)'],
    ['5568cd69c754b392121f1dbb8f900fda', 'Malicious Cloudflare tunnel account tag']
  ]));
  assert.equal(member(out, '23.234.100.105'), true);
  assert.equal(member(out, '5568cd69c754b392121f1dbb8f900fda'), false);
});

test('D: the domain of a spoofed sender address is not an Indicator; a non-spoofed defanged address is unchanged (33348)', () => {
  const out = run(`<h2>Indicators of Compromise (IoCs)</h2>
<h5>Host and campaign artifacts</h5>
<table><tr><th>Item</th><th>Description</th></tr>
<tr><td>boots &lt;hello[@]boots[.]com&gt;</td><td>Spoofed sender impersonating Boots UK.</td></tr>
<tr><td>212.93.152[.]37</td><td>Actor source IP.</td></tr>
</table>`);
  assert.equal(member(out, 'boots.com'), false);
  assert.equal(member(out, '212.93.152.37'), true);
  // RansomHub shape: an attacker contact address listed in an IOC section.
  const other = run(`<h2>Indicators of Compromise</h2>
<p>Email addresses used by the affiliates:</p>
<ul><li>brahma2023[@]onionmail[.]org</li></ul>`);
  const before = find(other, 'onionmail.org');
  assert.ok(before, 'domain candidate exists');
  assert.notEqual(before.policy_decision, 'context_only_email_domain');
});

test('D: a truncated copy of a table-listed URL is context; the listed URL and a different path stay Indicators (33351)', () => {
  const out = run(`<h2>Configuration and C2 communication</h2>
<p>C2 base URL: hxxps://trindastal[.]com/8250d149-9bf8-566d-9d7d-ea925eae0a4</p>
<p>Fallback: hxxps://trindastal[.]com/gate</p>
${iocTable([['hxxps://trindastal[.]com/8250d149-9bf8-566d-9d7d-ea925eae0a4c/', 'CastleLoader C2 endpoint']])}`);
  assert.equal(member(out, 'https://trindastal.com/8250d149-9bf8-566d-9d7d-ea925eae0a4c/'), true);
  const typo = find(out, 'https://trindastal.com/8250d149-9bf8-566d-9d7d-ea925eae0a4');
  assert.ok(typo);
  assert.equal(member(out, typo.normalized_value), false);
  assert.equal(typo.policy_decision, 'context_only_truncated_duplicate');
  // A URL that is not a mid-segment truncation is untouched by the rule.
  assert.notEqual(find(out, 'https://trindastal.com/gate')?.policy_decision, 'context_only_truncated_duplicate');
});

test('D: unfilled <token> placeholders make template URLs, even when the closing ">" was cut', () => {
  assert.equal(validateUrlCandidate('https://agenticsora.com/loader/agent/<token').reason, 'template_placeholder');
  assert.equal(validateUrlCandidate('http://agenticsora.com/curl/%3Ctoken').reason, 'template_placeholder');
  assert.equal(validateUrlCandidate('https://agenticsora.com/loader/agent/abc123').ok, true);
});

// --- E. Legitimate-service language -----------------------------------------

test('E: a row that calls its URL a lure is asserted although the hosting service is legitimate (33340)', () => {
  const out = run(iocTable([
    ['docsend[.]com/view/evdfym2aj5tend76', 'Lure link on legitimate dropbox service.'],
    ['docsend[.]online/download/drivers', 'Fake download domain serving the counterfeit DocSend installer.']
  ]));
  assert.equal(member(out, 'docsend.com/view/evdfym2aj5tend76'), true);
  assert.equal(member(out, 'https://docsend.online/download/drivers') || member(out, 'docsend.online/download/drivers'), true);
});

test('E (negative): a legitimate component row and a legitimate site in prose stay Context Only', () => {
  const out = run(`${iocTable([
    ['d0a4dc0b2e28d8d9e16d64f6ab0e7b53db0e8d3a6d61b1d9a3ccc0f1b9c6b9a1', 'Legitimate Microsoft binary used to sideload the loader. Not malicious.'],
    ['ccmihr-c2[.]net', 'C2 server']
  ])}
<h2>Analysis</h2><p>The kit sends a "verification code" lure, then the victim signs in at the legitimate microsoft.com/devicelogin page.</p>`);
  assert.equal(member(out, 'd0a4dc0b2e28d8d9e16d64f6ab0e7b53db0e8d3a6d61b1d9a3ccc0f1b9c6b9a1'), false);
  assert.equal(member(out, 'microsoft.com/devicelogin'), false);
  assert.equal(member(out, 'ccmihr-c2.net'), true);
});

// --- F. Linked IOC Source campaign scope -----------------------------------

const META_PHISH_CSV = 'type,data,info\ndescription,https://www.huntress.com/blog/meta-business-manager-phishing, Indicators associated with a phishing threat\ndomain,aussiecleaningservices[.]com,landing page\n';
const MAC_DRAIN_CSV = '\uFEFFtype,data,info\ndescription,https://www.huntress.com/blog/mac-crypto-draining-malware, Indicators associated with a macOS stealer malware\nip,77.221.152[.]34,malware host\n';

test('F: an inventory metadata row names its report; a data row of type url is never a back-link', () => {
  assert.equal(inventoryReportBacklink(META_PHISH_CSV, '2026/2026-07/fbphish.csv'), 'https://www.huntress.com/blog/meta-business-manager-phishing');
  assert.equal(inventoryReportBacklink('type,data\nurl,https://evil.example/x\n', 'iocs.csv'), null);
  assert.equal(inventoryReportBacklink(META_PHISH_CSV, 'README.adoc'), null);
  const report = { reportUrl: 'https://www.huntress.com/blog/mac-crypto-draining-malware' };
  assert.equal(inventoryBacklinkScope(MAC_DRAIN_CSV, 'a.csv', report).verdict, 'matches');
  assert.equal(inventoryBacklinkScope(META_PHISH_CSV, 'b.csv', report).verdict, 'other_report');
  assert.equal(inventoryBacklinkScope('type,data\nip,1.2.3.4\n', 'c.csv', report).verdict, 'undeclared');
});

test('F: a folder file that belongs to another article is deselected; this report\'s file is kept (sources 198 / 199)', () => {
  const report = { reportUrl: 'https://www.huntress.com/blog/mac-crypto-draining-malware' };
  const files = [{ path: '2026-07/20260707_fbphish-IOCs.csv', parse_status: 'ok', selected: true }, { path: '2026-07/mac.csv', parse_status: 'ok', selected: true }];
  const parses = [
    { path: files[0].path, ok: true, backlink_scope: inventoryBacklinkScope(META_PHISH_CSV, files[0].path, report) },
    { path: files[1].path, ok: true, backlink_scope: inventoryBacklinkScope(MAC_DRAIN_CSV, files[1].path, report) }
  ];
  const scoped = applyCampaignFileSelection(files, parses);
  assert.deepEqual(scoped.deselected, ['2026-07/20260707_fbphish-IOCs.csv']);
  assert.equal(scoped.fileRows.find((f) => f.path.endsWith('mac.csv')).selected, true);
  assert.equal(scoped.fileRows.find((f) => f.path.includes('fbphish')).selected, false);
  assert.deepEqual(scoped.parseResults.map((p) => p.path), ['2026-07/mac.csv']);
});

test('F: extraction never re-lists a folder whose files were all deselected, and scopes uninspected folders', () => {
  const src = fs.readFileSync(path.join(here, 'iocSources', 'extract.js'), 'utf8');
  const guard = src.indexOf("if (files.length && !selected.length)");
  const relist = src.indexOf('if (!files.length && gh)');
  assert.ok(guard > 0 && relist > guard, 'fail-closed guard precedes folder re-listing');
  assert.match(src.slice(guard, relist), /campaign_scope_unresolved/);
  assert.match(src, /inventoryBacklinkScope\(fetched\.body, file\.path, reportScope\)/);
});

test('F: an ip_path CSV row is a URL, and a scheme-less pack URL folds onto the report\'s absolute URL (src 197)', async () => {
  const csv = 'type,data,info\ndescription,https://www.huntress.com/blog/defcon-phishing-google-doc-malware,x\n' +
    'ip_path,192.253.248[.]181/api/v1/getscpt/,Persistence attempt\nurl,docsend[.]online/download/drivers,Fake download\n' +
    'url,eu03hub[.]com/get_file?file=2Ec6QYynajHw,Manager.zip\n';
  const parsed = await parseIocSourceContent({ body: csv, buffer: Buffer.from(csv), contentType: 'text/csv', url: 'https://raw.githubusercontent.com/o/r/main/x.csv', path: 'x.csv', sourcePublicId: 's', reportScope: {} });
  assert.equal(parsed.ok, true);
  const ids = parsed.candidates.map((c) => `${c.candidate_type}:${c.normalized_value}`);
  assert.ok(ids.includes('url:192.253.248.181/api/v1/getscpt/'), ids.join(' '));
  assert.ok(!ids.includes('ip:192.253.248.181'), 'the path is not dropped to a bare IP');
  const prior = [
    { candidate_type: 'url', normalized_value: 'https://docsend.online/download/drivers' },
    { candidate_type: 'url', normalized_value: 'http://192.253.248.181/api/v1/getscpt/' }
  ];
  const folded = foldSchemeLessLinkedUrls(parsed.candidates, prior).map((c) => c.normalized_value);
  assert.ok(folded.includes('https://docsend.online/download/drivers'));
  assert.ok(folded.includes('http://192.253.248.181/api/v1/getscpt/'));
  assert.ok(!folded.includes('docsend.online/download/drivers'), 'no duplicate scheme-less identity');
  // No absolute spelling known: kept as written.
  assert.ok(folded.includes('eu03hub.com/get_file?file=2Ec6QYynajHw'));
  // Two different schemes known: ambiguous, kept as written.
  const amb = foldSchemeLessLinkedUrls([{ candidate_type: 'url', normalized_value: 'x.example/a/b' }],
    [{ candidate_type: 'url', normalized_value: 'http://x.example/a/b' }, { candidate_type: 'url', normalized_value: 'https://x.example/a/b' }]);
  assert.equal(amb[0].normalized_value, 'x.example/a/b');
});

test('F: a linked source that leads to other reports overlays a read-time scope-mismatch warning', () => {
  const summary = summarizeLinkedIocSources([
    { lifecycle_status: 'unsupported', error_code: 'campaign_scope_unresolved', other_report_files: 1 },
    { lifecycle_status: 'extracted', error_code: null, other_report_files: 0 }
  ]);
  assert.equal(summary.scope_mismatch, 1);
  const q = withLinkedSourceQuality({ status: 'clean', warnings: [], counts: { high: 0, warning: 0, info: 0 } }, summary);
  assert.ok(q.warnings.some((w) => w.code === LINKED_SOURCE_SCOPE_MISMATCH_CODE && w.severity === 'warning'));
  const clean = withLinkedSourceQuality({ status: 'clean', warnings: [] }, summarizeLinkedIocSources([{ lifecycle_status: 'extracted' }]));
  assert.ok(!clean.warnings.some((w) => w.code === LINKED_SOURCE_SCOPE_MISMATCH_CODE));
});
