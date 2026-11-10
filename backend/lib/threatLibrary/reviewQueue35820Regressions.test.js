/**
 * Review-queue audit (35820–35850) regressions (tl-candidates-v62,
 * tl-table-v19).
 *
 * Generic shapes of the confirmed extraction defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * FN-1 An IOC table whose MD5s the publisher wrote as hex literals
 *      ("0xFD91…" beside IPs and URLs of the same table) asserts each MD5;
 *      the same holds for a list row that opens with the literal. A 0x run
 *      inside prose or code (a key / constant) is not a digest, a 0x run of a
 *      non-digest length is not cut down to one, and "0x" + 40 / 64 hex (an
 *      EVM address / transaction hash) is never read as SHA-1 / SHA-256.
 * FP-1 "<span>CVE-…</span><a>www.vendor.example/advisory</a>": the CVE id that
 *      adjacent inline markup glued onto a scheme-less link is not part of the
 *      resource (no "cve-…www.vendor.example" URL or domain).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { TABLE_SEMANTICS_VERSION } from './tableSemantics.js';

const SOURCE = 'https://vendor-research.example/blog/review-queue-audit-three/';

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
const identities = (x) => x.candidates.map((c) => `${c.candidate_type}:${c.normalized_value}`);

const hex = (seed, n) => seed.repeat(Math.ceil(n / seed.length)).slice(0, n);
const M1 = hex('a1', 32);
const M2 = hex('b2', 32);
const S1 = hex('c3', 40);
const H1 = hex('d4', 64);
const K1 = hex('e5', 32);

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v62');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v19');
});

// --- FN-1 ---------------------------------------------------------------------

test('FN-1: hex-literal MD5s in an IOC table are asserted like the table IPs and URLs', () => {
  const x = run(`
<h2>Indicator of compromise</h2>
<table>
<tr><th>Indicator of compromise</th><th>Description</th></tr>
<tr><td>203.0.113[.]204</td><td>Relay node</td></tr>
<tr><td>0x${M1.toUpperCase()}</td><td>Web shell implant</td></tr>
<tr><td>hxxps://drop[.]bad-bucket[.]com/v4[.]msi</td><td>Staged package</td></tr>
<tr><td>0x${M2}</td><td>Renamed archiver</td></tr>
</table>`);
  const m = members(x);
  assert.ok(m.includes('ip:203.0.113.204'), m.join(', '));
  assert.ok(m.includes(`md5:${M1}`), m.join(', '));
  assert.ok(m.includes(`md5:${M2}`), m.join(', '));
  const md5 = x.candidates.find((c) => c.normalized_value === M1);
  assert.match(String(md5.original_value || ''), /^0x/i, 'publisher spelling kept');
});

test('FN-1: a list row that opens with a hex-literal digest asserts it', () => {
  const x = run(`
<h2>Indicators of compromise</h2>
<p>MD5:</p>
<ul><li>0x${M2} – loader</li></ul>`);
  assert.ok(members(x).includes(`md5:${M2}`), members(x).join(', '));
});

test('FN-1 negative: "0x" + 40 / 64 hex is an EVM address / transaction hash, not SHA-1 / SHA-256', () => {
  const x = run(`
<h2>Indicators of compromise</h2>
<table>
<tr><th>Indicator</th><th>Description</th></tr>
<tr><td>198.51.100[.]8</td><td>C2</td></tr>
<tr><td>0x${S1}</td><td>Smart contract holding the C2 address</td></tr>
<tr><td>0x${H1}</td><td>Transaction that updated the contract</td></tr>
</table>
<ul><li>0x${S1}</li></ul>`);
  const ids = identities(x);
  assert.ok(!ids.includes(`sha1:${S1}`), ids.join(', '));
  assert.ok(!ids.includes(`sha256:${H1}`), ids.join(', '));
  assert.ok(members(x).includes('ip:198.51.100.8'), members(x).join(', '));
});

test('FN-1 negative: a 0x run inside prose or code is a constant, not a digest', () => {
  const x = run(`
<h2>Analysis</h2>
<p>The loader XORs the buffer with the key 0x${K1} before writing it to disk.</p>
<pre><code>KEY = 0x${K1}
iv = 0x${K1}</code></pre>`);
  assert.ok(!identities(x).includes(`md5:${K1}`), identities(x).join(', '));
});

test('FN-1 negative: a 0x run of a non-digest length is never cut to a digest', () => {
  const long = hex('f6', 34);
  const x = run(`
<h2>Indicators of compromise</h2>
<table>
<tr><th>Indicator</th><th>Description</th></tr>
<tr><td>198.51.100[.]7</td><td>C2</td></tr>
<tr><td>0x${long}</td><td>Unknown blob</td></tr>
</table>`);
  assert.ok(!identities(x).some((v) => /^md5:/.test(v)), identities(x).join(', '));
});

// --- FP-1 ---------------------------------------------------------------------

test('FP-1: a CVE id glued onto a scheme-less advisory link is not part of the resource', () => {
  const x = run(`
<h2>Patch links</h2>
<ul>
<li><span class="lbl">CVE-2026-109618</span><a href="https://www.vendor.example/archive/2026.php#notes">www.vendor.example/archive/2026.php#notes</a></li>
</ul>`);
  const ids = identities(x);
  assert.ok(!ids.some((v) => /cve-2026-109618www/i.test(v)), ids.join(', '));
  assert.ok(ids.includes('url:www.vendor.example/archive/2026.php#notes'), ids.join(', '));
});

test('FP-1 negative: an anchor that is the whole match is unchanged', () => {
  const x = run(`
<h2>References</h2>
<ul><li>See <a href="https://www.vendor.example/kb/123">www.vendor.example/kb/123</a> for details.</li></ul>`);
  assert.ok(identities(x).includes('url:www.vendor.example/kb/123'), identities(x).join(', '));
});
