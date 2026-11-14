/**
 * Import audit 35880–35889 regressions (tl-candidates-v67, tl-type-resolver-v28,
 * threat_library_html_v12, tl-published-at-v5; section tree unchanged at
 * tl-section-tree-v19).
 *
 * Generic shapes of the verified first-pass defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * FN-1 React streaming SSR (Next.js App Router): the tail rows of an IOC table
 *      arrive as `<table hidden><tbody id="S:x">` segments after the article and
 *      are moved into `<template id="P:x">` by `$RS("S:x","P:x")`. Read in
 *      source order they trailed the article outside the IOC section; they are
 *      put back where the page renders them (threat_library_html_v12).
 * FP-1 IP-echo services listed under a C2-titled analysis heading ("Host and
 *      GPU enumeration" inherits that scope): a lead-in that says the listed
 *      services are queried to learn the host's public IP names IP-echo
 *      utilities, also over one-value paragraph lines, so they are Context Only
 *      whatever scope they sit in (tl-candidates-v67).
 * NR-1 "imphash:<hex> (note)" in a line holding several "<hex> (" runs is an
 *      import hash, not an MD5 sample (tl-candidates-v67).
 * TY-1 Directory-tree listing entries ("│ ├── Makefile.pre.in") are file names,
 *      not hosts under the .in / .ac ccTLDs (tl-type-resolver-v28).
 * TY-2 A host after a percent escape ("%7Cpool.example") does not absorb the
 *      escape's hex digits (tl-candidates-v67).
 * DT-1 `<li>12 Nov 2026</li><li>20 Min Read</li>` byline items give the visible
 *      publication date; related-post cards in noise containers do not
 *      (tl-published-at-v5).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { HTML_BLOCKS_VERSION, parseHtml, resolveStreamingSegments } from './extract/htmlBlocks.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION, resolveDottedToken } from './observableTypeResolver.js';
import { PUBLICATION_DATE_EXTRACTOR_VERSION, extractVisiblePublicationDate } from './publicationDate.js';
import { annotatedDigestWindow } from './candidateHelpers.js';

const SOURCE = 'https://vendor-research.example/blog/import-audit-five/';

function runHtml(html) {
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}

function run(inner) {
  return runHtml(`<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`);
}

const persisted = (c) => ({
  ...c,
  has_original_document_occurrence: true,
  review_status: 'pending',
  evidence: buildCandidateEvidenceRecord(c)
});
const idOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const members = (x) => x.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map(idOf).sort();
const byValue = (x, v) => x.candidates.filter((c) => c.normalized_value === v);

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v67');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v19');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v28');
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v12');
  assert.equal(PUBLICATION_DATE_EXTRACTOR_VERSION, 'tl-published-at-v5');
});

// --- FN-1: React streaming SSR segments --------------------------------------

const row = (v, t, d) => `<tr><td><p>${v}</p></td><td><p>${t}</p></td><td><p>${d}</p></td></tr>`;

function streamedPage({ withInstructions = true } = {}) {
  return `<!doctype html><html lang="en"><head><title>Streamed</title></head><body><main>
<article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
<h2>Analysis</h2>
<p>The loader beacons to its staging server and pulls a second stage over HTTPS.</p>
<h2>E. Network indicators</h2>
<table><thead><tr><th>Indicator</th><th>Type</th><th>Description</th></tr></thead>
<tbody>${row('hxxps://198.51.100[.]10/s', 'URL', 'Stager download path')}<template id="P:5"></template></tbody></table>
<h2>F. MITRE ATT&amp;CK mapping</h2>
<p>Mapped to ATT&amp;CK Enterprise; techniques come from the description of the cluster.</p>
</article></main>
<table hidden><tbody id="S:5">${row('198.51.100[.]10', 'IPv4', 'Stager hosting and beacon endpoint')}${row('lookalike-signin[.]example', 'Domain', 'Device-code phishing lookalike')}${row('203.0.113[.]77', 'IPv4', 'Primary C2 VPS')}</tbody></table>
${withInstructions ? '<script>$RS=function(a,b){};$RS("S:5","P:5")</script>' : ''}
</body></html>`;
}

test('FN-1: streamed table rows rejoin their IOC table and are Indicators', () => {
  const m = members(runHtml(streamedPage()));
  for (const id of ['url:https://198.51.100.10/s', 'ip:198.51.100.10', 'domain:lookalike-signin.example', 'ip:203.0.113.77']) {
    assert.ok(m.includes(id), `${id} missing from ${m.join(', ')}`);
  }
});

test('FN-1: the segment rows are placed inside the table, not after the article', () => {
  const r = extractCanonicalDocumentFromHtml(streamedPage(), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  const tables = r.document.blocks.filter((b) => b.type === 'table');
  const ioc = tables.find((b) => /Stager download path/.test(b.text || ''));
  assert.ok(ioc, 'IOC table missing');
  assert.equal(ioc.table.rows.length, 4);
  assert.ok(!tables.some((b) => b !== ioc && /Primary C2 VPS/.test(b.text || '')), 'segment rows left detached');
});

test('FN-1 negative: without a streaming instruction the hidden segment is not moved', () => {
  const dom = parseHtml(streamedPage({ withInstructions: false }));
  assert.equal(resolveStreamingSegments(dom).resolved, 0);
  const r = extractCanonicalDocumentFromHtml(streamedPage({ withInstructions: false }), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  const ioc = r.document.blocks.find((b) => b.type === 'table' && /Stager download path/.test(b.text || ''));
  assert.equal(ioc.table.rows.length, 1);
});

test('FN-1: a Suspense boundary fallback is replaced by its segment ($RC)', () => {
  const html = `<!doctype html><html><head><title>t</title></head><body><main><article>
<h1>Report</h1><p>Intro paragraph for the report with enough words to be content.</p>
<!--$?--><template id="B:0"></template><p>Loading…</p><!--/$-->
</article></main><div hidden id="S:0"><p>Deferred analysis paragraph naming the staging host 192.0.2.45 in prose.</p></div>
<script>$RC("B:0","S:0")</script></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  const texts = r.document.blocks.map((b) => b.text || '');
  assert.ok(texts.some((t) => /Deferred analysis paragraph/.test(t)));
  assert.ok(!texts.some((t) => /Loading…/.test(t)), 'fallback kept');
});

// --- FP-1: technique topic under a C2 heading + IP-echo lead-in ---------------

const c2Analysis = (subheading, lead) => `
<h2>Analysis</h2>
<h3>Loader analysis: anti-debugging and the encoded onion C2 domain</h3>
<p>The controller hostname is stored encoded; decoding it gives the following domain with a hardcoded port:</p>
<p>abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion:9051</p>
<h4>${subheading}</h4>
<p>The loader collects GPU information with the following command:</p>
<pre><code>nvidia-smi --query-gpu=name --format=csv,noheader</code></pre>
<table><thead><tr><th>Collection</th><th>Source</th><th>Value sent</th></tr></thead><tbody>
<tr><td>Hostname</td><td>/etc/hostname</td><td>Trimmed hostname</td></tr>
<tr><td>Public IP</td><td>IP-discovery HTTP response</td><td>Validated address</td></tr></tbody></table>
<p>${lead}</p>
<p>api.echo-one.example</p>
<p>echo-two.example/ip</p>
<p>echo-three.example</p>
<h4>Registration, HMAC authentication and heartbeats</h4>
<p>The client registers with a timestamp and an HMAC digest.</p>
<h2>Observables and indicators</h2>
<table><thead><tr><th>Observable</th><th>Type</th><th>Name</th></tr></thead><tbody>
<tr><td>${'a'.repeat(63)}1</td><td>SHA-256</td><td>loader</td></tr></tbody></table>`;

const IP_ECHO_LEAD = 'To establish the host’s public IP, the loader queries three external services in order, with a five-second deadline per attempt, stopping at the first valid response:';
const ECHO = ['domain:api.echo-one.example', 'url:echo-two.example/ip', 'domain:echo-three.example'];

test('FP-1: IP-echo services under a C2-scoped topic are not Indicators; the onion C2 stays one', () => {
  const x = run(c2Analysis('Host and GPU enumeration', IP_ECHO_LEAD));
  const m = members(x);
  for (const id of ECHO) assert.ok(!m.includes(id), `${id} became an Indicator`);
  assert.ok(m.includes('domain:abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion'), m.join(', '));
  assert.ok(m.includes(`sha256:${'a'.repeat(63)}1`));
});

test('FP-1: the IP-echo lead-in alone makes the services Context Only', () => {
  const x = run(c2Analysis('Host and GPU enumeration', IP_ECHO_LEAD));
  for (const v of ['api.echo-one.example', 'echo-three.example']) {
    const [c] = byValue(x, v);
    assert.ok(c, `${v} not extracted`);
    assert.equal(persisted(c).evidence.membership_outcome, 'context_only', v);
  }
});

test('FP-1 negative: a C2 group heading over an operator list keeps the C2 reading', () => {
  const x = run(c2Analysis('C2 servers', 'The loader connects to the following C2 servers:'));
  const m = members(x);
  assert.ok(m.includes('domain:api.echo-one.example'), m.join(', '));
  assert.ok(m.includes('domain:echo-three.example'), m.join(', '));
});

// --- NR-1: key-prefixed digest in a "<hex> (note)" run ------------------------

const IMPHASH = 'c0ffee11223344556677889900aabbcc';

test('NR-1: annotatedDigestWindow defers to a key prefix bound to the digest', () => {
  const line = `similar-to:${'d'.repeat(40)} (two samples); imphash:${IMPHASH} (goodware and malicious splits)`;
  assert.equal(annotatedDigestWindow(line, IMPHASH), null);
  // An algorithm-only prefix names no subject: the parenthetical still does.
  const sha = `sha256:${'e'.repeat(64)} (Ligolo TLS certificate) ${'f'.repeat(64)} (agent)`;
  assert.equal(annotatedDigestWindow(sha, 'e'.repeat(64)), `Ligolo TLS certificate: ${'e'.repeat(64)}`);
});

test('NR-1: an imphash query term in a pivots table is not an MD5 sample', () => {
  const x = run(`
<h2>Research pivots</h2>
<table><thead><tr><th>Step</th><th>Pivot</th><th>Query or method</th><th>Result</th></tr></thead><tbody>
<tr><td>1</td><td>Similarity</td><td>similar-to:${'d'.repeat(40)} (seed samples)</td><td>Two related scripts</td></tr>
<tr><td>2</td><td>Build-artifact pivots</td><td>imphash:${IMPHASH} (goodware and malicious splits); filename:svchost32.exe</td><td>12.0K goodware-classified files</td></tr>
</tbody></table>`);
  assert.ok(!x.candidates.some((c) => c.candidate_type === 'md5' && c.normalized_value === IMPHASH), 'imphash typed as md5');
});

// --- TY-1: directory listing entries and defanged title-case hosts ------------

test('TY-1: tree-listing entries are file names, not hosts', () => {
  for (const [tok, line] of [
    ['Makefile.pre.in', '│ ├── Makefile.pre.in'],
    ['configure.ac', '│ ├── configure.ac'],
    ['MANIFEST.in', '|-- MANIFEST.in'],
    ['setup.in', '`-- setup.in']
  ]) {
    assert.equal(resolveDottedToken(tok, { surroundingText: line }).kind, 'technical_artifact', line);
  }
});

test('TY-1 negative: a stated network relation or a defanged spelling keeps the domain reading', () => {
  assert.equal(resolveDottedToken('relay-host.in', { surroundingText: 'C2: relay-host.in' }).kind, 'domain');
  assert.equal(resolveDottedToken('relay-host[.]in', { surroundingText: '├── relay-host[.]in' }).kind, 'domain');
});

test('TY-1: a recovered toolkit tree listing yields no domain candidates', () => {
  const x = run(`<h2>Recovered files</h2><p>│ ├── CODE_OF_CONDUCT.md<br>│ ├── Makefile.pre.in<br>│ ├── README.rst<br>│ ├── configure.ac<br>│ ├── pyconfig.h.in<br>│ └── MANIFEST.in</p>`);
  const domains = x.candidates.filter((c) => c.candidate_type === 'domain').map((c) => c.normalized_value);
  assert.deepEqual(domains, []);
});

// --- TY-2: percent escape before a host ----------------------------------------

test('TY-2: a percent escape does not glue its hex digits onto the host', () => {
  const x = run(`<h2>Mining traffic</h2><p>The miner reports to its panel:</p>
<pre><code>GET /tj/x.php?data=DESKTOP-ABC%7C1985.71%7C1%7Cxmr-eu.pool-host.example%3A7029%7Crx%2F0 HTTP/1.1</code></pre>`);
  const values = x.candidates.map((c) => c.normalized_value);
  assert.ok(values.includes('xmr-eu.pool-host.example'), values.join(', '));
  assert.ok(!values.some((v) => /^7c/i.test(v)), values.join(', '));
});

// --- DT-1: sibling reading-time byline -----------------------------------------

test('DT-1: a date item followed by a reading-time item is the visible publication date', () => {
  const html = `<html><body><main><ul class="metadata"><li class="metadata__item">Threat Intelligence</li><li class="metadata__item">12 Nov 2026</li><li class="metadata__item">20<!-- --> Min Read</li></ul>
<h1>Title</h1><p>Body.</p></main>
<div class="related-blog-posts"><ul class="related-blog-posts__details"><li class="related-blog-posts__details--item">5 Nov 2026</li><li>7 Min Read</li></ul></div></body></html>`;
  const d = extractVisiblePublicationDate(html, { now: new Date('2026-11-14T00:00:00Z') });
  assert.equal(d.published_date, '2026-11-12');
  assert.equal(d.source, 'visible_date');
});

test('DT-1 negative: related-post cards alone give no publication date', () => {
  const html = `<html><body><main><h1>Title</h1><p>Body.</p></main>
<div class="related-blog-posts"><ul><li>5 Nov 2026</li><li>7 Min Read</li></ul><ul><li>29 Oct 2026</li><li>7 Min Read</li></ul></div></body></html>`;
  const d = extractVisiblePublicationDate(html, { now: new Date('2026-11-14T00:00:00Z') });
  assert.equal(d.published_date, null);
});

test('FP-1 negative: services the lead-in calls attacker-controlled keep no benign stance', async () => {
  const { annotateListStances } = await import('./indicatorScope.js');
  const mk = (lead) => [lead, 'api.echo-one.example', 'echo-three.example', 'echo-four.example']
    .map((text, i) => ({ id: `b${i}`, type: 'paragraph', text }));
  const benign = annotateListStances(mk(IP_ECHO_LEAD));
  assert.deepEqual(benign.slice(1).map((b) => b.list_stance), ['non_malicious', 'non_malicious', 'non_malicious']);
  const hostile = annotateListStances(mk('To determine the victim public IP address, the implant queries three attacker-controlled services:'));
  assert.deepEqual(hostile.slice(1).map((b) => b.list_stance || null), [null, null, null]);
});

// --- Corpus blast-radius guards (shapes found while replaying the library) ----

test('FP-1 negative: a contrastive lead-in over IOC paragraph lines keeps them Indicators', () => {
  const m = members(run(`
<h2>IOCs</h2>
<p>Throwaway domains carrying a malicious verdict at observation:</p>
<p>– lure-one[.]example</p>
<p>– lure-two[.]example</p>
<p>Dynamic-DNS kit hosts (attacker-controlled subdomains of legitimate DDNS providers — block the host, not the provider):</p>
<p>– k1[.]ddns-provider[.]example</p>
<p>– k2[.]ddns-provider[.]example</p>
<p>– k3[.]other-ddns[.]example</p>`));
  for (const id of ['domain:k1.ddns-provider.example', 'domain:k2.ddns-provider.example', 'domain:k3.other-ddns.example']) {
    assert.ok(m.includes(id), `${id} missing from ${m.join(', ')}`);
  }
});

test('FP-1 negative: a label run after a non-group label still inherits the IOC section', () => {
  const m = members(run(`
<h2>Indicators of compromise (IOCs)</h2>
<p><strong>Package versions</strong></p>
<p>sample-package 1.4.2 and 1.4.3 were published by the compromised account.</p>
<p><strong>Files</strong></p>
<p>${'b'.repeat(64)}</p>
<p>${'c'.repeat(64)}</p>
<h3>Scan for malware</h3>
<p>Try our scanner on obfuscator-sample.example and see results in minutes.</p>`));
  assert.ok(m.includes(`sha256:${'b'.repeat(64)}`), m.join(', '));
  assert.ok(!m.includes('domain:obfuscator-sample.example'), 'marketing CTA inherited the IOC section');
});
