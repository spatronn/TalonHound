/**
 * Review-queue audit (35800–35819) regressions (tl-candidates-v61,
 * tl-section-tree-v17).
 *
 * Generic shapes of the confirmed extraction defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * FN-1 An IOC inventory whose groups the publisher wrote as same-level sibling
 *      headings keeps its authority over a sibling group heading that carries a
 *      scope qualifier and a trailing colon ("<Family> hashes for one 24-hour
 *      period:"), including when its rows sit under deeper sub-headings, and over
 *      a "URI Locations:" sibling holding a URL list.
 * FP-1 "Tor and [.]onion domains" (a spaced defang naming the TLD in prose) is
 *      not the domain "and.onion": a .onion host needs a service label of at
 *      least 16 characters.
 * FP-2 A Rust source file named beside a digest in a hash table ("Loader
 *      (build.rs)") is a file name, not a domain under the .rs ccTLD; a
 *      defanged or declared .rs domain stays a domain.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { normalizeCandidateValue } from './candidateValue.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';

const SOURCE = 'https://vendor-research.example/blog/review-queue-audit-two/';

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
const values = (x) => x.candidates.map((c) => c.normalized_value);

const hex = (seed, n = 64) => seed.repeat(Math.ceil(n / seed.length)).slice(0, n);
const H1 = hex('a1');
const H2 = hex('b2');
const H3 = hex('c3');
const H4 = hex('d4');
const H5 = hex('e5');
const H6 = hex('f6');

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v61');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v17');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v26');
});

// --- FN-1 ---------------------------------------------------------------------

const SIBLING_GROUPS = `
<h2>Conclusion</h2>
<p>The operators rotate payload hosts frequently and rebuild their samples every hour.</p>
<h2>IOCs</h2>
<h3>Loader IOCs</h3>
<h3>Payload locations</h3>
<p>hxxps://payload-host[.]example-bad[.]com/default.dat</p>
<h2>File names</h2>
<p>default.dat.exe</p>
<h2>C2 URLs</h2>
<p>hxxp://relay-node[.]example-bad[.]net/route.php</p>
<h2>Loader hashes for one 24-hour period:</h2>
<p>Due to hourly build generation there are hundreds of samples; these are examples.</p>
<h3>Installers</h3>
<p>${H1}<br>${H2}</p>
<h3>Support libraries</h3>
<p>${H3}<br>${H4}</p>
<h2>Second family IOCs</h2>
<h3>Sha256 Hashes</h3>
<p>${H5}</p>
<h2>C2 Hostnames</h2>
<p>c2-one[.]example-bad[.]org</p>
<h2>URI Locations:</h2>
<p>hxxps://drop-site[.]example-bad[.]com/js/stage.exe<br>hxxp://198.51.100[.]23/stage.exe</p>
`;

test('FN-1. qualified sibling group headings keep the open IOC inventory authority', () => {
  const m = members(run(SIBLING_GROUPS));
  for (const v of [`sha256:${H1}`, `sha256:${H2}`, `sha256:${H3}`, `sha256:${H4}`]) {
    assert.ok(m.includes(v), `${v} under "<family> hashes for <period>:" is an Indicator`);
  }
  assert.ok(m.includes('url:https://drop-site.example-bad.com/js/stage.exe'), 'URI Locations: list is an Indicator');
  assert.ok(m.includes('url:http://198.51.100.23/stage.exe'));
  // Unchanged readings around the fix.
  assert.ok(m.includes(`sha256:${H5}`));
  assert.ok(m.includes('domain:c2-one.example-bad.org'));
  assert.ok(m.includes('url:http://relay-node.example-bad.net/route.php'));
});

test('FN-1 control. a qualified sibling heading over prose does not inherit authority', () => {
  const x = run(`
<h2>Indicators of Compromise</h2>
<table><tr><th>Domain</th><th>Notes</th></tr><tr><td>c2-two[.]example-bad[.]org</td><td>C2</td></tr></table>
<h2>Operator domains for one campaign:</h2>
<p>The operators also registered lookalike-bank.example-other.com earlier this year, according to a third-party writeup that we could not confirm.</p>`);
  const m = members(x);
  assert.ok(m.includes('domain:c2-two.example-bad.org'));
  assert.ok(!m.includes('domain:lookalike-bank.example-other.com'), 'a prose sentence is not an inventory');
});

// --- FP-1 ---------------------------------------------------------------------

test('FP-1. ".onion" named in prose after a word is not a domain; real onion services are', () => {
  assert.equal(normalizeCandidateValue('and.onion').ok, false);
  assert.equal(normalizeCandidateValue('http://and.onion/route.php').ok, false);
  const v3 = 'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx';
  assert.equal(v3.length, 56);
  assert.equal(normalizeCandidateValue(`${v3}.onion`).ok, true);
  assert.equal(normalizeCandidateValue('abcdefghij234567.onion').ok, true, 'v2 (16-character) label');
  assert.equal(normalizeCandidateValue(`http://${v3}.onion/route.php`).ok, true);
  // A publisher misspelling of a real service (one extra character) still names it.
  assert.equal(normalizeCandidateValue(`${v3}x.onion`).ok, true);
  assert.equal(normalizeCandidateValue('short-label.onion').ok, false);
  const x = run(`
<h2>Analysis</h2>
<p>The loader connects to its C2 through TOR and [.]onion domains, and only does so on a specific schedule.</p>
<h2>Indicators of Compromise</h2>
<p>hxxp://${v3}[.]onion/route.php</p>`);
  assert.ok(!values(x).includes('and.onion'));
  assert.deepEqual(members(x), [`url:http://${v3}.onion/route.php`]);
});

// --- FP-2 ---------------------------------------------------------------------

test('FP-2. a Rust source file beside a digest is not a .rs domain', () => {
  const x = run(`
<h2>Indicators of compromise</h2>
<h3>Payload hashes (SHA-256)</h3>
<table><tr><th>Platform</th><th>SHA-256</th></tr>
<tr><td>Linux x86_64</td><td>${H1} (crate_0.1.0)</td></tr>
<tr><td>Loader (build.rs)</td><td>${H2} (shared by two crates)</td></tr></table>
<h3>Network</h3>
<table><tr><th>Type</th><th>Indicator</th><th>Notes</th></tr>
<tr><td>Domain</td><td>update-mirror[.]rs</td><td>Stage-2 host</td></tr></table>`);
  const m = members(x);
  assert.ok(!m.includes('domain:build.rs'), 'build.rs is the hashed file, not a host');
  assert.ok(m.includes(`sha256:${H1}`) && m.includes(`sha256:${H2}`));
  assert.ok(m.includes('domain:update-mirror.rs'), 'a declared, defanged .rs domain stays a domain');
});

test('FP-2 control. the defanged mail domain of an exfil account keeps its domain reading', () => {
  const x = run(`
<h2>Indicators of Compromise</h2>
<ul><li>FTP Server: ftp[:]//ftp.exfil-mail[.]rs</li><li>FTP username: kel-bin@exfil-mail[.]rs</li></ul>`);
  const typed = x.candidates.filter((c) => c.normalized_value === 'exfil-mail.rs').map((c) => c.candidate_type);
  assert.ok(!typed.includes('technical_artifact'), 'a defanged .rs name is never a Rust file');
  assert.ok(members(x).includes('domain:ftp.exfil-mail.rs'));
});
