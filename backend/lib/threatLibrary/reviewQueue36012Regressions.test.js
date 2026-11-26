/**
 * Review queue 36012-36053 (tl-candidates-v76): defects found auditing the 42
 * Need Review reports against their publisher pages.
 *
 * A. 36015 (Cyble): a "C2 Infrastructure" key/value table carries a
 *    "User-Agent Spoofed | Mozilla/5.0 … Chrome/143.0.0.0 …" row. The browser
 *    release became an IPv4 C2 Indicator (the User-Agent cue was read only in
 *    prose, never in rows or IOC zones).
 * B. 36015: the same table's "Hosting Provider | Namecheap, Inc.
 *    (web-hosting.com VPS) – ASN …" row made the provider's domain a C2
 *    Indicator: the service-role row label was honoured only for table_row
 *    occurrences, not for the standalone values of a key/value table.
 * C. 36025 (HivePro): an IoC URL row lists
 *    "hxxps[:]//<name>[.]blogspot[.]com/…/<file>". The elided URL is rightly a
 *    placeholder, but the host the publisher wrote in full vanished with it —
 *    attacker infrastructure with no candidate at all.
 * D. 36021 / 36052 (ASEC): a translated stage table re-spells IoC-appendix URLs
 *    in title case ("Hxxp://…/70/Img_201031[.]Png", "uc?Export=download"). Each
 *    became a second URL Indicator beside the appendix spelling.
 * E. 36012 (Seqrite): an IoC row "CDHash | <40 hex> | Code Directory Hash" became
 *    a SHA-1 sample. A code-directory hash digests the code signature, not the
 *    file (tl-digest-v10).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { ipv4UserAgentVersion } from './ipv4VersionContext.js';
import { elidedUrlHost, validateUrlCandidate } from './observableTypeResolver.js';
import { classifyHexDigest, DIGEST_KINDS } from './digestSemantics.js';

test('review queue 36012 contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v76');
});

const URL = 'https://publisher.example/advisory';
function extractHtml(body) {
  const html = `<!doctype html><html lang="en"><head><title>Review queue 36012 fixture</title></head><body><article>
<h1>Synthetic campaign analysis</h1>
<p>Background paragraph describing lure construction, delivery and operator tradecraft across several environments.</p>
${body}
</article></body></html>`;
  const x = extractCanonicalDocumentFromHtml(html, { sourceUrl: URL, url: URL, finalUrl: URL, httpStatus: 200 });
  return extractReportCandidates({ source_type: 'url', source_url: URL }, x.document || x);
}
const find = (r, type, value) => r.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const member = (r, type, value) => {
  const c = find(r, type, value);
  return Boolean(c && isReportIndicatorMember(c));
};
const urls = (r) => r.candidates.filter((c) => c.candidate_type === 'url').map((c) => c.normalized_value).sort();

const C2_TABLE = `
<h2>C2 Infrastructure</h2>
<p>The operator panel was reachable throughout the observation window.</p>
<table>
<tr><td>C2 Server</td><td>hxxp://203.0.113[.]77</td></tr>
<tr><td>Server Stack</td><td>nginx/1.24.0 on Ubuntu Linux, Flask 3.1.3 backend</td></tr>
<tr><td>Hosting Provider</td><td>Example Hosting, Inc. (vps-hosting.example VPS) – ASN 64500, Atlanta, GA, USA</td></tr>
<tr><td>Upload Endpoint</td><td>/upload</td></tr>
<tr><td>User-Agent Spoofed</td><td>Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/143.0.0.0 … Edg/143.0.0.0</td></tr>
</table>`;

test('A: a User-Agent product release in an IOC-zone row is not an address', () => {
  const r = extractHtml(C2_TABLE);
  assert.equal(member(r, 'ip', '143.0.0.0'), false);
  assert.equal(find(r, 'ip', '143.0.0.0'), null);
  assert.ok(find(r, 'technical_artifact', '143.0.0.0'), 'kept as version metadata');
  // The C2 server of the same table keeps its URL reading.
  assert.ok(find(r, 'url', 'http://203.0.113.77/'));
  // Unit: the cue is the token's own "Product/" syntax, in any block.
  const row = 'User-Agent Spoofed | Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/143.0.0.0';
  assert.deepEqual(ipv4UserAgentVersion(row, row.indexOf('143.0.0.0')), { kind: 'version', cue: 'user_agent_product' });
  const c2 = 'C2 Server | 143.0.0.1';
  assert.equal(ipv4UserAgentVersion(c2, c2.indexOf('143.0.0.1')), null);
});

test('B: a "Hosting Provider" key/value row lists the provider, not C2', () => {
  const r = extractHtml(C2_TABLE);
  assert.equal(member(r, 'domain', 'vps-hosting.example'), false);
  // A row whose label names the operator's own hosting stays an assertion.
  const own = extractHtml(`
<h2>C2 Infrastructure</h2>
<table>
<tr><td>C2 hosting</td><td>c2-panel-hosting.example</td></tr>
<tr><td>C2 Server</td><td>hxxp://203.0.113[.]78</td></tr>
</table>`);
  assert.equal(member(own, 'domain', 'c2-panel-hosting.example'), true);
});

test('C: the full host before an elided URL path is the IoC row value', () => {
  const r = extractHtml(`
<h2>Indicators of Compromise (IoCs)</h2>
<table>
<tr><th>Type</th><th>Value</th></tr>
<tr><td>URLs</td><td><span><code>hxxps[:]//stagea-blog[.]blogspot[.]com/one[.]docx[.]pdf[.]sys</code></span> <span><code>hxxps[:]//stageb-blog[.]blogspot[.]com/…/two[.]docx[.]pdf[.]sys</code></span></td></tr>
<tr><td>SHA256</td><td>${'ab'.repeat(32)}</td></tr>
</table>`);
  assert.equal(member(r, 'url', 'https://stagea-blog.blogspot.com/one.docx.pdf.sys'), true);
  assert.equal(member(r, 'domain', 'stageb-blog.blogspot.com'), true);
  // The elided URL is never reconstructed.
  assert.equal(urls(r).some((u) => u.includes('stageb-blog')), false);
  assert.equal(member(r, 'domain', 'blogspot.com'), false);
  // Unit: only an absolute URL whose elision starts after the host.
  assert.equal(validateUrlCandidate('https://stageb-blog.blogspot.com/…/two.sys').reason, 'elided_value');
  assert.equal(elidedUrlHost('hxxps[:]//stageb-blog[.]blogspot[.]com/…/two[.]sys'), 'stageb-blog.blogspot.com');
  assert.equal(elidedUrlHost('https://stage…blog.example/a.sys'), null);
  assert.equal(elidedUrlHost('stageb-blog.example/…/a.sys'), null);
  assert.equal(elidedUrlHost('http://203.0.113.9/…/a.sys'), null);
  assert.equal(elidedUrlHost('https://stageb-blog.example/a.sys'), null);
});

test('C: an elided URL in narrative prose yields no host', () => {
  const r = extractHtml('<h2>Delivery</h2><p>The loader fetched hxxps://prose-only-host[.]example/…/a.sys during stage two.</p>');
  assert.equal(member(r, 'domain', 'prose-only-host.example'), false);
});

test('D: a title-case body re-spelling of an appendix URL joins the appendix identity', () => {
  const r = extractHtml(`
<h2>Analysis</h2>
<p>The script receives the C2 server address from which it downloads the RAT.</p>
<table>
<tr><td>Stage Download C2</td><td>Hxxp://198.51.100[.]44/70/Img_2010[.]Png</td></tr>
<tr><td>Payload Download C2</td><td>Hxxp://drive.Example-Files[.]Com/uc?Export=download&amp;id=AbC123xYz</td></tr>
<tr><td>Loader C2</td><td>Hxxp://edge-node[.]example/HIsPq</td></tr>
</table>
<h2>IOC</h2>
<h3>URL</h3>
<p>http[:]//198[.]51[.]100[.]44/70/img_2010[.]png</p>
<p>https[:]//drive[.]example-files[.]com/uc?export=download&amp;id=AbC123xYz</p>
<p>https[:]//edge-node[.]example/HIsPq</p>`);
  const list = urls(r);
  assert.ok(list.includes('http://198.51.100.44/70/img_2010.png'), list.join(' '));
  assert.ok(!list.includes('http://198.51.100.44/70/Img_2010.Png'), list.join(' '));
  assert.ok(list.includes('https://drive.example-files.com/uc?export=download&id=AbC123xYz'), list.join(' '));
  assert.ok(!list.some((u) => u.includes('Export=')), list.join(' '));
  // A scheme-only difference (same letter case) stays ambiguous and as written.
  assert.ok(list.includes('http://edge-node.example/HIsPq'), list.join(' '));
  assert.ok(list.includes('https://edge-node.example/HIsPq'), list.join(' '));
  const appendix = find(r, 'url', 'http://198.51.100.44/70/img_2010.png');
  assert.equal(isReportIndicatorMember(appendix), true);
  assert.ok((appendix.parsed?.case_variant_aliases || []).length >= 1);
});

test('E: a CDHash row is a code-signing digest, never a SHA-1 sample', () => {
  const cd = 'c1'.repeat(20);
  const sample = 'e7'.repeat(32);
  const r = extractHtml(`
<h2>Indicators of Compromise (IOCs)</h2>
<table>
<tr><th>Type</th><th>Value</th><th>Description</th></tr>
<tr><td>SHA-256 Hash</td><td>${sample}</td><td>Native Mach-O stager binary</td></tr>
<tr><td>CDHash</td><td>${cd}</td><td>Code Directory Hash</td></tr>
</table>`);
  assert.equal(member(r, 'sha256', sample), true);
  assert.equal(member(r, 'sha1', cd), false);
  assert.equal(classifyHexDigest(`CDHash | ${cd}`, cd).kind, DIGEST_KINDS.CERTIFICATE);
  assert.equal(classifyHexDigest(`Code Directory hash: ${cd}`, cd).kind, DIGEST_KINDS.CERTIFICATE);
});
