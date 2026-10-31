/**
 * Thirty-two-report batch audit regressions, reports 34415–34446
 * (tl-candidates-v44). Generic shapes of the confirmed defects of the
 * 2026-10-29 audit, each with its negative control:
 *
 * D1. A scheme whose defang bracket splits the authority marker
 *     ("http[:/]/217[.]156[.]50[.]228[:]8185/…") refangs, so the IOC-table URL
 *     is a candidate and an Indicator (tl-defang-v5).
 * D2. A typed IOC-table row whose provider noun is qualified by the operation
 *     its sibling rows attribute infrastructure to ("CaptiveCrunch DNS
 *     Resolver" among "CaptiveCrunch AitM infrastructure" rows), or that carries
 *     a bare "C2" role label ("ChocoShell C2 / … Resolver"), stays an
 *     Indicator; a category-qualified provider row ("Blockchain provider") of
 *     the same kind of table stays a provider relation.
 * D3. A structural row naming the value as the resolver used "for domain
 *     resolution" ("DOH for domain resolution using https://dns.google/…")
 *     under a C2-channel list is a provider relation, not an Indicator; a C2
 *     row in the same list stays an Indicator.
 *
 * Values are public IOCs from the audited reports or documentation shapes.
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { refangObservable, refangTextForExtraction, looksDefanged } from './defang.js';
import { tableRowProviderOwnedByOperation } from './indicatorScope.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/thirty-two-report-batch/';

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

test('versions: tl-candidates-v45', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v48');
});

// --- D1. Split-bracket scheme defang ------------------------------------------

test('D1: "http[:/]/" refangs to http:// in tokens and text', () => {
  assert.equal(refangObservable('http[:/]/217[.]156[.]50[.]228[:]8185/LoqnOOuuIsTIYfkrdsfL/eUelHAyY.exe'),
    'http://217.156.50.228:8185/LoqnOOuuIsTIYfkrdsfL/eUelHAyY.exe');
  assert.equal(refangObservable('hxxps[:/]/evil[.]example/a'), 'https://evil.example/a');
  assert.equal(refangTextForExtraction('fetched from http[:/]/evil[.]example/x.exe today'),
    'fetched from http://evil.example/x.exe today');
  assert.equal(looksDefanged('http[:/]/evil[.]example/x'), true);
});

test('D1 control: a split bracket without two slashes or without a dotted host stays untouched', () => {
  assert.equal(refangTextForExtraction('http[:/]evil[.]example'), 'http[:/]evil.example');
  assert.equal(refangTextForExtraction('see http[:/]/docs for details'), 'see http[:/]/docs for details');
  // The existing bracket forms are unchanged.
  assert.equal(refangObservable('http[://]107[.]189[.]25[.]189[:]49259/receive'), 'http://107.189.25.189:49259/receive');
  assert.equal(refangObservable('hxxps[:]//evil[.]example/a'), 'https://evil.example/a');
});

const MARCO_IOC_TABLE = `<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>IOC</th><th>Type</th></tr></thead><tbody>
<tr><td>http[:/]/217[.]156[.]50[.]228[:]8185/LoqnOOuuIsTIYfkrdsfL/eUelHAyY.exe</td><td>Downloading URL</td></tr>
<tr><td>34deb6594098545d7ffb98844f0790bf</td><td>ZIP</td></tr>
<tr><td>http[://]107[.]189[.]25[.]189[:]49259/receive</td><td>C2 server</td></tr>
</tbody></table>`;

test('D1: the split-bracket IOC-table URL is an Indicator (34445)', () => {
  const out = run(MARCO_IOC_TABLE);
  assert.equal(member(out, 'http://217.156.50.228:8185/LoqnOOuuIsTIYfkrdsfL/eUelHAyY.exe'), true);
  assert.equal(member(out, 'http://107.189.25.189:49259/receive'), true);
  assert.equal(member(out, '34deb6594098545d7ffb98844f0790bf'), true);
});

// --- D2. Operation-owned resolver rows ---------------------------------------

const CAPTIVE_TABLE = `<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>IOC</th><th>Type</th><th>Description</th></tr></thead><tbody>
<tr><td>ms365-device[.]com</td><td>Domain</td><td>CaptiveCrunch device code flow (DCF) redirect domain</td></tr>
<tr><td>31.57.243[.]154</td><td>IP Address</td><td>CaptiveCrunch AitM infrastructure</td></tr>
<tr><td>38.146.28[.]132</td><td>IP Address</td><td>CaptiveCrunch DNS Resolver</td></tr>
<tr><td>107.189.26[.]194</td><td>IP Address</td><td>ChocoShell C2 / CaptiveCrunch DNS Resolver</td></tr>
<tr><td>213.145.86[.]112</td><td>IP Address</td><td>ChocoShell C2 server</td></tr>
</tbody></table>`;

test('D2: a resolver row owned by the operation named in sibling rows is an Indicator (34422)', () => {
  const out = run(CAPTIVE_TABLE);
  assert.equal(member(out, '38.146.28.132'), true, 'CaptiveCrunch DNS Resolver');
  assert.equal(member(out, '107.189.26.194'), true, 'ChocoShell C2 / CaptiveCrunch DNS Resolver');
  assert.equal(member(out, '31.57.243.154'), true);
  assert.equal(member(out, 'ms365-device.com'), true);
});

const PROVIDER_TABLE = `<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>Indicator</th><th>Type</th><th>Description</th><th>Purpose</th></tr></thead><tbody>
<tr><td>bsc-dataseed[.]binance[.]org</td><td>domain</td><td>Blockchain provider</td><td>C2 URL resolution</td></tr>
<tr><td>bsc-rpc[.]publicnode[.]com</td><td>domain</td><td>Blockchain provider</td><td>C2 URL resolution</td></tr>
<tr><td>8.8.8[.]8</td><td>IP Address</td><td>Google DNS Resolver</td><td>Lookups</td></tr>
<tr><td>panel-update[.]example</td><td>domain</td><td>Loader C2 server</td><td>Tasking</td></tr>
</tbody></table>`;

test('D2 control: category-qualified and third-party provider rows stay provider relations', () => {
  const out = run(PROVIDER_TABLE);
  assert.equal(member(out, 'bsc-dataseed.binance.org'), false);
  assert.equal(member(out, 'bsc-rpc.publicnode.com'), false);
  assert.equal(member(out, '8.8.8.8'), false, 'no sibling row attributes infrastructure to "Google"');
  assert.equal(member(out, 'panel-update.example'), true);
});

test('D2: tableRowProviderOwnedByOperation reads the qualifier against sibling rows', () => {
  const block = { table: { rows: [
    ['a.example', 'Domain', 'CaptiveCrunch AitM infrastructure'],
    ['1.2.3.4', 'IP Address', 'CaptiveCrunch DNS Resolver'],
    ['5.6.7.8', 'IP Address', 'Public DNS resolver'],
    ['9.9.9.9', 'IP Address', 'Quad9 DNS resolver']
  ] } };
  assert.equal(tableRowProviderOwnedByOperation(block, 1), true);
  assert.equal(tableRowProviderOwnedByOperation(block, 2), false, 'stopword qualifier');
  assert.equal(tableRowProviderOwnedByOperation(block, 3), false, 'qualifier named by no sibling row');
  assert.equal(tableRowProviderOwnedByOperation(block, 0), false, 'no provider noun');
  assert.equal(tableRowProviderOwnedByOperation({}, 0), false);
});

// --- D3. Resolver used for domain resolution --------------------------------

const PLUGX_C2_CHANNELS = `<h2>Technical analysis</h2>
<h3>PlugX backdoor analysis</h3>
<p>This PlugX sample supports the following C2 channels:</p>
<ul>
<li>TCP</li>
<li>HTTPS</li>
<li>DOH for domain resolution using https://dns.google/dns-query</li>
<li>UDP</li>
</ul>
<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>Type</th><th>Indicator</th></tr></thead><tbody>
<tr><td>C2 IP</td><td>91.193.17[.]117</td></tr>
</tbody></table>`;

test('D3: a resolver row "for domain resolution using <url>" is not an Indicator (34441)', () => {
  const out = run(PLUGX_C2_CHANNELS);
  assert.equal(member(out, 'https://dns.google/dns-query'), false);
  assert.equal(member(out, '91.193.17.117'), true);
});

const C2_CHANNEL_LIST = `<h2>Technical analysis</h2>
<p>The backdoor supports the following C2 channels:</p>
<ul>
<li>HTTPS beacon to https://update-check[.]example/api/v2</li>
<li>Domain resolution via https://resolver[.]example/dns-query (attacker-controlled DoH server)</li>
</ul>`;

test('D3 control: C2 rows and an attacker-controlled resolver row keep their assertion', () => {
  const out = run(C2_CHANNEL_LIST);
  assert.equal(member(out, 'https://update-check.example/api/v2'), true);
  assert.equal(member(out, 'https://resolver.example/dns-query'), true);
});
