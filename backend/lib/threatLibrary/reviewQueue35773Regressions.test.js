/**
 * Review-queue audit (35773–35797) regressions (tl-candidates-v59 / v60).
 *
 * Generic shapes of the confirmed extraction defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * FN-1 An internationalised lookalike hostname in an IOC list ("exampłe[.]com")
 *      is one domain Indicator, stored in IDNA A-label form ("xn--…"), with the
 *      publisher's Unicode spelling kept as the original value.
 * FP-1 The ASCII matcher never reads only the tail of such a name: "brańd.com"
 *      must not yield "d.com", "exampłe.com" must not yield "e.com".
 * FN-2 A capitalised product name in a hash row's description ("AppSalt SDK",
 *      "KeyVault class") is not split into nouns: "Salt" is not a crypto salt,
 *      so the row's digest stays a file hash. Field-name spelling
 *      ("sessionKeyHex") is still read word by word.
 * FN-3 A defanged wildcard IOC-table row ("*[.]operator[.]com") asserts its
 *      base domain like the plain "*.operator.com" spelling (v60).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { normalizeCandidateValue } from './candidateValue.js';
import { DIGEST_KINDS, classifyHexDigest, labelWords } from './digestSemantics.js';

const SOURCE = 'https://vendor-research.example/blog/review-queue-audit/';

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

const H64A = 'a1'.repeat(32);
const H64B = 'b2'.repeat(32);
const H32 = 'c3'.repeat(16);

test('contract version', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v67');
});

// --- FN-1 / FP-1: internationalised hostnames ----------------------------------

test('FN-1 unit. a Unicode hostname normalizes to its A-label, original spelling kept', () => {
  const n = normalizeCandidateValue('exampłe[.]com', 'domain');
  assert.equal(n.ok, true);
  assert.equal(n.candidateType, 'domain');
  assert.equal(n.normalizedValue, 'xn--exampe-7db.com');
  assert.equal(n.originalValue, 'exampłe[.]com');
  // ASCII hostnames are unchanged.
  assert.equal(normalizeCandidateValue('evil-host[.]com', 'domain').normalizedValue, 'evil-host.com');
});

test('FN-1 / FP-1. lookalike-domain list: A-label Indicators, no ASCII tails', () => {
  const x = run(`<h2>Indicators of compromise</h2>
<h3>Phishing infrastructure</h3>
<ul><li>shop-portal[.]example-store.com</li><li>parcel-notice[.]net</li></ul>
<h3>Unicode lookalike domains</h3>
<ul><li>exampłe[.]com</li><li>brańd[.]com</li><li>stọre[.]net</li></ul>`);
  const m = members(x);
  for (const v of ['domain:xn--exampe-7db.com', 'domain:xn--brad-d2a.com', 'domain:xn--stre-hx5a.net', 'domain:parcel-notice.net']) {
    assert.ok(m.includes(v), `${v} missing from ${m.join(', ')}`);
  }
  const vals = values(x);
  for (const tail of ['e.com', 'd.com', 're.net']) assert.ok(!vals.includes(tail), `tail ${tail} extracted`);
  const c = x.candidates.find((k) => k.normalized_value === 'xn--exampe-7db.com');
  assert.match(String(c.original_value), /exampłe/);
});

test('FP-1. Unicode prose with dotted words never becomes a domain tail', () => {
  const x = run(`<h2>Analysis</h2>
<p>The lure named the brand rołex.com in its subject and linked to the operator page.</p>`);
  assert.ok(!values(x).includes('ex.com'));
});

// --- FN-2: product names in hash-row descriptions -------------------------------

test('FN-2 unit. a weak crypto noun that is only a product-name hump is not key material', () => {
  assert.equal(labelWords('accessTokenHash'), 'access Token Hash');
  const rowA = `libnative_keys.so | ${H64A} | Key storage for AppSalt SDK bundled with the dropper`;
  assert.equal(classifyHexDigest(rowA, H64A, { rowDescription: 'Key storage for AppSalt SDK bundled with the dropper' }).kind, DIGEST_KINDS.FILE);
  const rowB = `AppSalt / Proxyware | DEX | ${H32} | AppSalt class`;
  assert.equal(classifyHexDigest(rowB, H32, { rowDescription: 'AppSalt class' }).kind, DIGEST_KINDS.FILE);
  // Real key material still reads as a key.
  assert.equal(classifyHexDigest(`"sessionKeyHex": "${H64B}"`, H64B).kind, DIGEST_KINDS.CRYPTO_KEY);
  assert.equal(classifyHexDigest(`AES key: ${H64B}`, H64B).kind, DIGEST_KINDS.CRYPTO_KEY);
  assert.equal(classifyHexDigest(`"saltHex": "${H64B}"`, H64B).kind, DIGEST_KINDS.CRYPTO_KEY);
  assert.equal(classifyHexDigest(`PBKDF2 salt ${H64B}`, H64B).kind, DIGEST_KINDS.CRYPTO_KEY);
  // A capitalised structure name still splits into its key phrase.
  assert.equal(
    classifyHexDigest(`RSA-4096 public-key fingerprint, SHA-256 of DER SubjectPublicKeyInfo: ${H64B}`, H64B).kind,
    DIGEST_KINDS.CRYPTO_KEY
  );
});

test('FN-2. a malware-sample table keeps every row hash a file Indicator', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<h3>Core Malware Samples</h3>
<table><tr><th>Tool(s)</th><th>Representative SHA256</th><th>Notes</th></tr>
<tr><td>libexploit.so</td><td>${H64B}</td><td>Privilege escalator bundled with the handler</td></tr>
<tr><td>libnative_keys.so</td><td>${H64A}</td><td>Key storage for AppSalt SDK bundled with</td></tr>
</table>
<h3>Affiliate Malware</h3>
<table><tr><th>Affiliate</th><th>File Type</th><th>Representative hash</th><th>Notes</th></tr>
<tr><td>AppSalt / Proxyware</td><td>DEX</td><td>${H32}</td><td>AppSalt class</td></tr>
</table>`);
  const m = members(x);
  for (const v of [`sha256:${H64A}`, `sha256:${H64B}`, `md5:${H32}`]) assert.ok(m.includes(v), `${v} missing from ${m.join(', ')}`);
});

// --- FN-3: defanged wildcard rows -----------------------------------------------

test('FN-3. a defanged wildcard row ("*[.]operator[.]com") asserts its base domain', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Family</th><th>Notes</th></tr>
<tr><td>203[.]0[.]113[.]10</td><td>IP Address</td><td>Botnet</td><td>Hosts MQTT C2 Broker</td></tr>
<tr><td>*[.]stb-bootstrap-node[.]com</td><td>Subdomains</td><td>Botnet</td><td>Registration C2 subdomains</td></tr>
<tr><td>*.fallback-relay-host.net</td><td>Subdomains</td><td>Botnet</td><td>Fallback C2</td></tr>
</table>`);
  const m = members(x);
  for (const v of ['domain:stb-bootstrap-node.com', 'domain:fallback-relay-host.net']) assert.ok(m.includes(v), `${v} missing from ${m.join(', ')}`);
});
