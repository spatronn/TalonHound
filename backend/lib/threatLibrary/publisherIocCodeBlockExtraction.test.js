/**
 * Publisher IOC appendices in fenced <pre>/<code> blocks, filename+HASH rows,
 * and non-actionable loopback / localhost semantics.
 *
 * Generic fixtures only — no hardcoded production report URLs or IOC values
 * from a single campaign.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { preTextLinesOf, parseHtml, HTML_BLOCKS_VERSION } from './extract/htmlBlocks.js';
import { extractCandidatesWithDiagnostics, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import {
  buildCandidateEvidenceRecord,
  isPublisherAuthoritativeReportIocMember,
  SOURCE_ASSERTIONS
} from './evidencePolicy.js';
import { isActionableReviewIndicator } from './promotion.js';
import { isIndicatorRowShape, lineContainingObservable } from './indicatorScope.js';
import { isLoopbackOrLocalhostAddress } from './candidateValue.js';

const SOURCE = 'https://research.example/blog/publisher-codeblock-iocs/';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const H1 = sha('publisher-codeblock-sample-1');
const H2 = sha('publisher-codeblock-sample-2');
const H3 = sha('publisher-codeblock-sample-3');
const H4 = sha('publisher-codeblock-sample-4');
const H5 = sha('publisher-codeblock-sample-5');
const H6 = sha('publisher-codeblock-sample-6');
const PUBLIC_IP = '203.0.113.77';
const C2_URL_A = `http://${PUBLIC_IP}:8080/wi/grab`;
const C2_URL_B = `http://${PUBLIC_IP}:8080/w`;
const FILLER = Array.from({ length: 6 }, (_, i) =>
  `<p>Background paragraph ${i + 1} describes lure construction, delivery and operator tradecraft observed across several environments so the IOC appendix sits near the end of a long article.</p>`
).join('\n');

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>Codeblock IOC fixture</title></head><body><article>
<h1>Synthetic publisher codeblock campaign</h1>
${FILLER}
${inner}
</article></body></html>`;
}

function extract(inner, sourceUrl = SOURCE) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: sourceUrl, finalUrl: sourceUrl, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl }), document: r.document };
}

const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const reviewRow = (c) => (c ? { ...c, evidence: buildCandidateEvidenceRecord(c) } : null);
const isMember = (c) => Boolean(c) && isActionableReviewIndicator(reviewRow(c));
const membersOf = (cands) => cands.filter((c) => isMember(c));

test('contract: html v4 + candidates v15', () => {
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v4');
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v20');
});

test('preTextLinesOf keeps author newlines inside fenced code', () => {
  const dom = parseHtml(`<pre><code>_grab.py        ${H1}
inject_proxy.py ${H2}
</code></pre>`);
  const pre = dom.children.find((n) => n.name === 'pre') || dom.children[0];
  assert.deepEqual(preTextLinesOf(pre), [`_grab.py ${H1}`, `inject_proxy.py ${H2}`]);
});

test('1. publisher IOC section with filename HASH lines in <pre> extracts all SHA-256 as Indicators', () => {
  const { candidates, document, diagnostics } = extract(`
<h2>Indicators of Compromise (IOCs)</h2>
<h3>SHA-256</h3>
<pre><code>_grab.py        ${H1}
inject_proxy.py ${H2}
ext/content.js  ${H3}
wg_install.sh   ${H4}
wgkit.tar.gz    ${H5}
wg-ca.crt       ${H6}
</code></pre>`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true);
  const codeLines = document.blocks.filter((b) => b.type === 'code' && b.line_group);
  assert.ok(codeLines.length >= 6, 'each pre line becomes its own code block');
  for (const h of [H1, H2, H3, H4, H5, H6]) {
    const c = find(candidates, 'sha256', h);
    assert.ok(c, `missing hash ${h}`);
    assert.equal(c.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC, h);
    assert.equal(c.assessment, 'malicious', h);
    assert.equal(isMember(c), true, h);
    assert.ok(c.occurrences.some((o) => o.asserted === true), `${h} asserted`);
  }
  assert.equal(membersOf(candidates).filter((c) => c.candidate_type === 'sha256').length, 6);
  // Filenames beside hashes are evidence/annotations, never domain Indicators.
  for (const name of ['wg-ca.crt', 'inject_proxy.py', 'wgkit.tar.gz', 'content.js']) {
    assert.equal(isMember(find(candidates, 'domain', name)), false, `${name} must not be a domain Indicator`);
  }
});

test('2. explicit IOC section near the bottom of a long article is not lost', () => {
  const { candidates } = extract(`
${FILLER}${FILLER}
<h2>Indicators of Compromise (IOCs)</h2>
<pre><code>${PUBLIC_IP}
${C2_URL_A}
${H1}
</code></pre>`);
  assert.ok(isMember(find(candidates, 'ip', PUBLIC_IP)));
  assert.ok(isMember(find(candidates, 'url', C2_URL_A)));
  assert.ok(isMember(find(candidates, 'sha256', H1)));
});

test('3. narrative + explicit-section duplicate hash → one candidate, publisher membership kept', () => {
  const { candidates } = extract(`
<p>The dropper sample ${H1} was first seen in the loader stage.</p>
<h2>Indicators of Compromise (IOCs)</h2>
<pre><code>loader.bin ${H1}
</code></pre>`);
  const hashes = candidates.filter((c) => c.candidate_type === 'sha256' && c.normalized_value === H1);
  assert.equal(hashes.length, 1);
  assert.ok(hashes[0].occurrence_count >= 2);
  assert.equal(hashes[0].source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC);
  assert.equal(isMember(hashes[0]), true);
});

test('4. 127.0.0.1 from 127.0.0.1:8899 is Context Only, not actionable C2', () => {
  const { candidates } = extract(`
<p>The local proxy listens on 127.0.0.1:8899.</p>
<h2>Indicators of Compromise (IOCs)</h2>
<h3>C2 infrastructure</h3>
<pre><code>${PUBLIC_IP}
${C2_URL_A}
${C2_URL_B}
127.0.0.1:8899
</code></pre>`);
  const loop = find(candidates, 'ip', '127.0.0.1');
  assert.ok(loop, 'loopback still extracted as evidence');
  assert.equal(loop.reserved_address, true);
  assert.equal(loop.non_actionable_local, true);
  assert.equal(loop.assessment, 'context_only');
  assert.equal(loop.policy_decision, 'context_only_non_actionable_local');
  assert.equal(isMember(loop), false);
  assert.ok(loop.occurrences.some((o) => o.port === 8899 || String(o.surrounding_text || '').includes('8899')));
  assert.equal(loop.original_value.includes('8899') || (loop.parsed?.ports || []).includes(8899), true);

  assert.ok(isMember(find(candidates, 'ip', PUBLIC_IP)));
  assert.ok(isMember(find(candidates, 'url', C2_URL_A)));
  assert.ok(isMember(find(candidates, 'url', C2_URL_B)));
  assert.equal(find(candidates, 'url', C2_URL_A).normalized_value !== PUBLIC_IP, true);
});

test('5. 127.0.0.1 inside tls/127.0.0.1.pem is not an actionable IOC', () => {
  const { candidates } = extract(`
<pre><code>-rw-r--r-- ./tls/127.0.0.1.pem
-rw-r--r-- ./tls/localhost.pem
</code></pre>
<h2>IOCs</h2>
<pre><code>${PUBLIC_IP}</code></pre>`);
  assert.equal(find(candidates, 'ip', '127.0.0.1'), null, 'embedded path IP is not standalone');
  assert.ok(isMember(find(candidates, 'ip', PUBLIC_IP)));
});

test('6. localhost / localhost.pem must not become actionable IOC', () => {
  const { candidates } = extract(`
<p>Certificate file tls/localhost.pem is bundled with the kit.</p>
<h2>IOCs</h2>
<pre><code>localhost
${PUBLIC_IP}
</code></pre>`);
  const local = find(candidates, 'domain', 'localhost');
  if (local) {
    assert.equal(local.assessment, 'context_only');
    assert.equal(isMember(local), false);
  }
  assert.ok(isMember(find(candidates, 'ip', PUBLIC_IP)));
});

test('7. IPv6 ::1 is non-actionable local infrastructure', () => {
  assert.equal(isLoopbackOrLocalhostAddress('::1'), true);
  const { candidates } = extract(`
<h2>Indicators of Compromise (IOCs)</h2>
<pre><code>::1
${PUBLIC_IP}
</code></pre>`);
  const v6 = find(candidates, 'ipv6', '::1') || find(candidates, 'ip', '::1');
  assert.ok(v6, '::1 extracted');
  assert.equal(v6.assessment, 'context_only');
  assert.equal(isMember(v6), false);
  assert.ok(isMember(find(candidates, 'ip', PUBLIC_IP)));
});

test('8–9. public malicious IP and distinct public-IP URLs remain Indicators', () => {
  const { candidates } = extract(`
<h2>Indicators of Compromise (IOCs)</h2>
<pre><code>${PUBLIC_IP}
${C2_URL_A}
${C2_URL_B}
</code></pre>`);
  const ip = find(candidates, 'ip', PUBLIC_IP);
  const a = find(candidates, 'url', C2_URL_A);
  const b = find(candidates, 'url', C2_URL_B);
  assert.ok(isMember(ip));
  assert.ok(isMember(a));
  assert.ok(isMember(b));
  assert.equal(a.normalized_value === b.normalized_value, false);
  assert.equal(ip.normalized_value === a.normalized_value, false);
});

test('10. private RFC1918 IP remains context-only (existing reserved semantics)', () => {
  const { candidates } = extract(`
<h2>Indicators of Compromise (IOCs)</h2>
<pre><code>10.20.30.40
${PUBLIC_IP}
</code></pre>`);
  const priv = find(candidates, 'ip', '10.20.30.40');
  assert.ok(priv);
  assert.equal(priv.assessment, 'context_only');
  assert.equal(priv.reserved_address, true);
  assert.equal(isMember(priv), false);
  assert.ok(isMember(find(candidates, 'ip', PUBLIC_IP)));
});

test('11. MODE A: narrative malicious hash is not a report Indicator when publisher IOC scope exists', () => {
  const { candidates } = extract(`
<p>Analysts also saw sample ${H1} in a related loader.</p>
<h2>Indicators of Compromise (IOCs)</h2>
<pre><code>${PUBLIC_IP}
loader.bin ${H2}
</code></pre>`);
  assert.equal(isMember(find(candidates, 'sha256', H1)), false);
  assert.equal(isPublisherAuthoritativeReportIocMember(reviewRow(find(candidates, 'sha256', H1))), false);
  assert.ok(isMember(find(candidates, 'sha256', H2)));
  assert.ok(isMember(find(candidates, 'ip', PUBLIC_IP)));
});

test('12. MODE B: reports with no publisher IOC section still promote narrative malicious IPs via AI path unchanged', () => {
  const { candidates, diagnostics } = extract(`
<p>The malware beacons to ${PUBLIC_IP} every thirty seconds.</p>`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, false);
  const ip = find(candidates, 'ip', PUBLIC_IP);
  assert.ok(ip);
  // Without publisher scope, membership is not restricted by MODE A.
  assert.equal(isPublisherAuthoritativeReportIocMember(reviewRow(ip)), true);
});

test('lineContainingObservable focuses filename+HASH rows inside a multi-line block', () => {
  const block = `_grab.py ${H1}\ninject_proxy.py ${H2}\n`;
  assert.equal(lineContainingObservable(block, H1), `_grab.py ${H1}`);
  assert.equal(isIndicatorRowShape(block, H1), true);
  assert.equal(isIndicatorRowShape(block, H2), true);
});
