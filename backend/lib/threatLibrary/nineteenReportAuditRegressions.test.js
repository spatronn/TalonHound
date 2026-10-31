/**
 * Nineteen-report batch audit regressions (tl-candidates-v46).
 *
 * A. Unit 42 Miasma IOC rows prefixed `fqdn://host` are domain Indicators.
 * B. A redaction placeholder glued onto a hostname (`[redacted]post-app.com`)
 *    is not the visible tail.
 * C. Every hash of a row described as a legitimate component is Context Only;
 *    a malicious row beside it stays an Indicator.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { annotateDocumentZones } from './documentZones.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION, resolveDottedToken } from './observableTypeResolver.js';

const MD5 = 'a'.repeat(32);
const SHA1 = 'b'.repeat(40);
const SHA256 = 'c'.repeat(64);
const MAL_MD5 = 'd'.repeat(32);
const MAL_SHA1 = 'e'.repeat(40);
const MAL_SHA256 = 'f'.repeat(64);

function run(html) {
  const url = 'https://unit42.paloaltonetworks.com/example-report/';
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true, 'html extract ok');
  const doc = annotateDocumentZones(r.document, { sourceUrl: url, sourceHost: 'unit42.paloaltonetworks.com' });
  return extractCandidatesFromDocument(doc, { sourceUrl: url });
}

function member(c) {
  return isReportIndicatorMember({
    ...c,
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true
  });
}

function find(cands, type, value) {
  const v = String(value).toLowerCase();
  return cands.find((c) => c.candidate_type === type && String(c.normalized_value || '').toLowerCase() === v);
}

test('versions: tl-candidates-v47, tl-type-resolver-v20', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v48');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v20');
});

test('A. fqdn:// IOC-table hosts are domain Indicators', () => {
  const cands = run(`<article>
<h2>Indicators of Compromise</h2>
<table>
<tr><th>Indicator</th><th>Description</th></tr>
<tr><td>fqdn://ipfs[.]io</td><td>Abused to deliver Stage-2 payloads.</td></tr>
<tr><td>fqdn://rentry[.]co</td><td>Used to exfiltrate tokens/keys.</td></tr>
<tr><td>hxxp://85.137.53[.]71:8080/api/v1/beacon</td><td>C2 beacon</td></tr>
</table>
</article>`);
  for (const host of ['ipfs.io', 'rentry.co']) {
    const c = find(cands, 'domain', host);
    assert.ok(c, `${host} extracted`);
    assert.equal(member(c), true, `${host} is an Indicator`);
  }
  const beacon = find(cands, 'url', 'http://85.137.53.71:8080/api/v1/beacon');
  assert.ok(beacon, 'http C2 URL still extracted');
  assert.equal(member(beacon), true);
});

test('B. redaction glued onto a hostname is not the visible tail', () => {
  const cands = run(`<article>
<h2>Indicators of Compromise</h2>
<ul>
<li>hxxp[:]//[redacted]post-app[.]com/[redacted]post.apk</li>
<li>[redacted]benefitsportal[.]com</li>
<li>[redacted]-login[.]com</li>
<li>evil-post-app[.]example</li>
</ul>
</article>`);
  for (const tail of ['post-app.com', 'benefitsportal.com', 'login.com']) {
    assert.equal(find(cands, 'domain', tail), undefined, `${tail} must not be derived from a redacted name`);
  }
  const real = find(cands, 'domain', 'evil-post-app.example');
  assert.ok(real, 'an unredacted domain stays');
  assert.equal(member(real), true);
});

test('C. every hash of a legitimate-file row is Context Only; a malicious sibling row stays', () => {
  const cands = run(`<article>
<h2>Indicators of Compromise</h2>
<h3>File indicators</h3>
<table>
<tr><th>Hashes</th><th>Filename</th><th>Description</th></tr>
<tr><td>${MD5} ${SHA1} ${SHA256}</td><td>WebFeatures.exe</td><td>Legitimate data importer utility from the KuGou music software suite.</td></tr>
<tr><td>${MAL_MD5} ${MAL_SHA1} ${MAL_SHA256}</td><td>libmemobook.dll</td><td>Malicious stage 1 DLL.</td></tr>
</table>
</article>`);
  for (const [type, value] of [['md5', MD5], ['sha1', SHA1], ['sha256', SHA256]]) {
    const c = find(cands, type, value);
    assert.ok(c, `${type} extracted`);
    assert.equal(member(c), false, `${type} of the legitimate file is not an Indicator`);
    assert.equal(c.assessment, 'context_only');
  }
  for (const [type, value] of [['md5', MAL_MD5], ['sha1', MAL_SHA1], ['sha256', MAL_SHA256]]) {
    const c = find(cands, type, value);
    assert.ok(c, `${type} malicious row extracted`);
    assert.equal(member(c), true, `${type} of the malicious file stays an Indicator`);
  }
});

test('D. a long filename does not hide a legitimate-file description from earlier digests', () => {
  const longName = 'Iran Strikes U.S. Military Facilities Across Gulf Region.exe';
  const cands = run(`<article>
<h2>Indicators of Compromise</h2>
<h3>File indicators</h3>
<table>
<tr><th>Hashes</th><th>Filename</th><th>Description</th></tr>
<tr><td>${MD5} ${SHA1} ${SHA256}</td><td>${longName}</td><td>Legitimate binary.</td></tr>
<tr><td>${MAL_MD5} ${MAL_SHA1} ${MAL_SHA256}</td><td>${longName}</td><td>Malicious stage 1 DLL.</td></tr>
</table>
</article>`);
  for (const [type, value] of [['md5', MD5], ['sha1', SHA1], ['sha256', SHA256]]) {
    const c = find(cands, type, value);
    assert.ok(c, `${type} extracted`);
    assert.equal(member(c), false, `${type} stays Context Only when the filename is long`);
    assert.equal(c.assessment, 'context_only');
  }
  for (const [type, value] of [['md5', MAL_MD5], ['sha1', MAL_SHA1], ['sha256', MAL_SHA256]]) {
    const c = find(cands, type, value);
    assert.ok(c, `${type} malicious row extracted`);
    assert.equal(member(c), true, `${type} of the malicious file stays an Indicator`);
  }
});

test('E. a domains lead-in does not promote a URL-path archive; a .zip host stays a domain', () => {
  const pathFile = resolveDottedToken('letgovip.zip', {
    surroundingText: 'hxxp://[redacted].com/letgovip.zip',
    declaredType: 'domain',
    form: 'list_row',
    strongZone: true,
    zone: 'explicit_ioc_section'
  });
  assert.equal(pathFile.kind, 'technical_artifact');
  const php = resolveDottedToken('mentalite.php', {
    surroundingText: 'hxxp://[redacted].com/mentalite.php',
    declaredType: 'domain',
    form: 'list_row',
    strongZone: true,
    zone: 'explicit_ioc_section'
  });
  assert.equal(php.kind, 'technical_artifact');
  const host = resolveDottedToken('evil.zip', {
    surroundingText: 'evil[.]zip',
    declaredType: 'domain',
    form: 'list_row',
    strongZone: true,
    zone: 'explicit_ioc_section'
  });
  assert.equal(host.kind, 'domain');
});
