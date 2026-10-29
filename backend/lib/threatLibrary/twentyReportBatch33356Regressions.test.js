/**
 * Twenty-report batch audit regressions, reports 33356–33375
 * (tl-candidates-v42 / tl-type-resolver-v19). Generic shapes of the confirmed
 * defects of the 2026-10-27 audit, each with its negative control:
 *
 * D1. An IPv6 network block in an IOC list ("2607:99c0::/32") is a CIDR
 *     Indicator, not the bare network address; a plain IPv6 address stays an
 *     address.
 * D2. A community / open-source resource the publisher recommends to defenders
 *     ("Community-driven resources like lolrmm.io help …") is a reference, not
 *     an Indicator, even in MODE B; an operational host in the same report
 *     stays an Indicator.
 * D3. A defanged `host:port` followed by more values in the same cell
 *     ("x[.]onion:443 51.89.228[.]250:21668") keeps the host as a domain
 *     Indicator; a real `key: value` assignment stays configuration.
 * D4. A bare digest list item under a heading that names a non-file digest
 *     ("### SSL Thumbprint") is not a file hash; under a sample-hash heading
 *     it is.
 * D5. A digest in a table column headed "Imphash" is not a file hash, whatever
 *     file nouns the other cells use; an "MD5" column keeps file hashes.
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
import { classifyHexDigest, DIGEST_KINDS } from './digestSemantics.js';
import { resolveDottedToken, OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/twenty-report-batch-33356/';

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

test('versions: tl-candidates-v42, tl-type-resolver-v19', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v47');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v20');
});

// --- D1. IPv6 CIDR ----------------------------------------------------------

test('D1: an IPv6 prefix in an IOC block list is a CIDR Indicator, never the bare network address (33358)', () => {
  const out = run(`<h2>Indicators of Compromise (IOCs)</h2>
<h3>CIDR blocks for perimeter blocking:</h3>
<ul><li>162.220.232[.]0/22</li><li>66.33.22.0/23</li><li>2607:99c0::/32</li></ul>`);
  const cidr = find(out, '2607:99c0::/32');
  assert.ok(cidr, 'IPv6 CIDR extracted');
  assert.equal(cidr.candidate_type, 'cidr');
  assert.ok(member(out, '2607:99c0::/32'));
  assert.equal(find(out, '2607:99c0::'), undefined, 'no truncated host address');
  assert.ok(member(out, '162.220.232.0/22'));
});

test('D1 control: a plain IPv6 address stays an ipv6 Indicator', () => {
  const out = run(`<h2>Indicators of Compromise</h2>
<ul><li>2a01:4f8:c17:1a2b::5</li><li>45.61.136[.]143</li></ul>`);
  const v6 = find(out, '2a01:4f8:c17:1a2b::5');
  assert.ok(v6);
  assert.equal(v6.candidate_type, 'ipv6');
  assert.ok(member(out, '2a01:4f8:c17:1a2b::5'));
});

// --- D2. Defender resource --------------------------------------------------

test('D2: a community resource recommended to defenders is not an Indicator in MODE B (33364)', () => {
  const out = run(`<h2>Threat actors probing detection capabilities</h2>
<p>The operator connected from 209.160.115[.]150 and staged the toolkit on the server before deploying ScreenConnect.</p>
<p>Organisations should allow-list approved tools. Community-driven resources like lolrmm.io help support this approach by providing shared visibility into commonly abused platforms.</p>`);
  assert.ok(find(out, 'lolrmm.io'), 'still a candidate');
  assert.equal(member(out, 'lolrmm.io'), false);
  assert.ok(member(out, '209.160.115.150'), 'operational IP in the same report stays an Indicator');
});

test('D2 control: abused infrastructure named in prose keeps its operational reading', () => {
  const out = run(`<h2>Delivery</h2>
<p>The loader downloaded the next stage from update-check-cdn.top, which served the encrypted payload.</p>`);
  assert.ok(member(out, 'update-check-cdn.top'));
});

// --- D3. host:port followed by another value -------------------------------

test('D3: defanged onion:port followed by IP:port values in one cell → domain Indicator (33370)', () => {
  const onion = '3zciedc3enu4muwc5adxciyk6u3juhvhvbv6bfrk2arawlvb7k7ovxad.onion';
  const out = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Description</th><th>Value</th></tr>
<tr><td>XMRIG Endpoints</td><td>3zciedc3enu4muwc5adxciyk6u3juhvhvbv6bfrk2arawlvb7k7ovxad[.]onion:443<br>51.89.228[.]250:21668<br>51.89.231[.]85:24526</td></tr>
</table>`);
  const c = find(out, onion);
  assert.ok(c, 'refanged onion host extracted');
  assert.equal(c.candidate_type, 'domain');
  assert.ok(member(out, onion));
  assert.ok(member(out, '51.89.228.250'));
  assert.equal(out.candidates.some((x) => String(x.normalized_value).includes('[.]')), false, 'no defanged leftovers');
});

test('D3: resolveDottedToken reads host:port before another value as an endpoint, key: value as config', () => {
  const endpoint = resolveDottedToken('evilhost.com', { surroundingText: 'C2 | evilhost.com:443 51.89.228.250:21668' });
  assert.equal(endpoint.kind, 'domain');
  const assignment = resolveDottedToken('agent.server.host', { surroundingText: 'agent.server.host: 10' });
  assert.equal(assignment.kind, 'technical_artifact');
  assert.equal(assignment.reason, 'config_context');
  const decimal = resolveDottedToken('evilhost.com', { surroundingText: 'ratio evilhost.com:443.5 percent' });
  assert.notEqual(decimal.reason, 'network_context', 'a port followed by .digit is not an endpoint boundary');
});

// --- D4. Heading-scoped digest list ----------------------------------------

test('D4: a bare hex list item under an "SSL Thumbprint" heading is not a file hash (33373)', () => {
  const out = run(`<h2>Indicators of Compromise</h2>
<h3>C2 IP Addresses</h3>
<ul><li>91.108.106[.]229</li></ul>
<h3>SSL Thumbprint</h3>
<ul><li>6e480d648fa1b70612f5d198a66875e28847547d</li></ul>`);
  assert.equal(member(out, '6e480d648fa1b70612f5d198a66875e28847547d'), false);
  const c = find(out, '6e480d648fa1b70612f5d198a66875e28847547d');
  assert.ok(c);
  assert.notEqual(c.candidate_type, 'sha1');
  assert.ok(member(out, '91.108.106.229'));
});

test('D4 control: a bare hex list item under a sample-hash heading stays a file hash', () => {
  const out = run(`<h2>Indicators of Compromise</h2>
<h3>SHA256 Hashes - Variant B Cluster</h3>
<ul><li>15489bcd6e4602b41c9a787ec8d7ab027d5e45d400938048bb1c702ad5937980</li></ul>`);
  assert.ok(member(out, '15489bcd6e4602b41c9a787ec8d7ab027d5e45d400938048bb1c702ad5937980'));
});

// --- D5. Imphash column -----------------------------------------------------

test('D5: digests in an "Imphash" column are not file hashes even beside sample nouns (33374)', () => {
  const out = run(`<h2>Indicators of Compromise</h2>
<h3>Import Hash (imphash) Analysis</h3>
<table><tr><th>Imphash</th><th>Cluster</th><th>Role</th></tr>
<tr><td>d42595b695fc008ef2c56aabd8efd68e</td><td>A - x64 EXE (26 samples)</td><td>Go loader EXE</td></tr>
<tr><td>d8b31f8c03e0c76ff245ed05a15ffe6c</td><td>B - x64 DLL (13 samples)</td><td>Fake MpClient.dll</td></tr>
</table>
<h3>SHA256 Hashes</h3>
<ul><li>7ed4a256e1d281cb4f194d13ff554fd4fb280dafde0a67a18115ea038ea6c87d</li></ul>`);
  assert.equal(member(out, 'd42595b695fc008ef2c56aabd8efd68e'), false);
  assert.equal(member(out, 'd8b31f8c03e0c76ff245ed05a15ffe6c'), false);
  assert.ok(member(out, '7ed4a256e1d281cb4f194d13ff554fd4fb280dafde0a67a18115ea038ea6c87d'));
});

test('D5 control: an "MD5" column with sample descriptions keeps file hashes', () => {
  const out = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>MD5</th><th>Description</th></tr>
<tr><td>2a0834560ed3770fc33d7a42f8229722</td><td>x64 EXE loader sample</td></tr>
</table>`);
  assert.ok(member(out, '2a0834560ed3770fc33d7a42f8229722'));
});

test('D5: classifyHexDigest — column header governs; file-hash header does not demote', () => {
  const v = 'd42595b695fc008ef2c56aabd8efd68e';
  const line = `Imphash | Cluster | Role ¶ ${v} | A - x64 EXE (26 samples) | Go loader EXE`;
  assert.equal(classifyHexDigest(line, v, { columnHeader: 'Imphash' }).kind, DIGEST_KINDS.SIMILARITY);
  assert.equal(classifyHexDigest(line, v, { columnHeader: 'MD5' }).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`SHA1 | ${v}`, v, { columnHeader: 'Certificate thumbprint' }).kind, DIGEST_KINDS.CERTIFICATE);
});
