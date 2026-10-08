/**
 * Minimized Raven-shaped MODE A fixture: long IP list, duplicate IPs, MD5
 * samples with filenames, full URLs + embedded hosts, domain, path-only and
 * filesystem paths, hex-looking auth token, username/password, mislabeled
 * hash metadata, narrative CVEs, and a narrative observable later repeated in
 * the IOC section.
 *
 * Synthetic values only — no production campaign hardcoding.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import {
  isReportIndicatorMember,
  isContextOnlyCandidate,
  countCandidateBuckets
} from './indicatorMembership.js';
import { isCredentialLabeledHex } from './indicatorScope.js';
import { FILE_EXT_HINT, OBSERVABLE_TYPE_RESOLVER_VERSION, resolveDottedToken } from './observableTypeResolver.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const frontendPath = [
  path.resolve(here, '../../test-fixtures/candidateReview.frontend.js'),
  path.resolve(here, '../../../../frontend/src/components/threatLibrary/candidateReview.js'),
  '/opt/TalonHound/frontend/src/components/threatLibrary/candidateReview.js'
].find((p) => existsSync(p));
if (!frontendPath) throw new Error('frontend candidateReview.js not found for FE parity');
const frontend = await import(pathToFileURL(frontendPath).href);
const { isReviewIndicator, isContextOnlyCandidate: feContextOnly } = frontend;

const SOURCE = 'https://research.example/lab/raven-shaped-mode-a/';
const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

const IP_A = '203.0.113.10';
const IP_B = '203.0.113.20';
const IP_C = '198.51.100.44';
const IP_DUP = '203.0.113.10'; // same as IP_A — role-labelled again
const DOMAIN = 'relay-panel.example';
const SAMPLE_A = md5('raven-shaped-sample-a');
const SAMPLE_B = md5('raven-shaped-sample-b');
const AUTH_TOKEN = md5('raven-shaped-auth-token');
const MISLABELED = md5('raven-shaped-mislabeled-hash'); // 32 hex, publisher says SHA-256
const NARRATIVE_SHA = sha256('raven-shaped-narrative-only');
const URL_A = `http://${IP_A}:443/t/ae7427`;
const URL_B = `https://${DOMAIN}/v1/artifacts/latest`;
const PATH_ONLY = '/t/ae7427';
const FS_PATH = '/var/tmp/.ux/agent.pl';

function htmlDoc() {
  const ipList = [IP_A, IP_B, IP_C, '203.0.113.30', '203.0.113.40', '203.0.113.50', '203.0.113.60', '203.0.113.70'].join('\n');
  return `<!doctype html><html lang="en"><head><title>Synthetic tunnel campaign</title></head><body><article>
<h1>Synthetic tunnel campaign</h1>
<p>Unauthenticated attackers chained CVE-2026-88771 and CVE-2026-88772 against edge appliances.</p>
<p>Operators staged a helper at ${IP_A} before the curated appendix. Narrative sample ${NARRATIVE_SHA} is not listed below.</p>
<p>Filesystem drop path observed in incident notes: ${FS_PATH}</p>
<h2>IOCs</h2>
<pre><code>IP ADDRESSES EXPLOITING EDGE
============================
${ipList}

SAMPLES
=======
 ${SAMPLE_A} :  anob4.exe      :  27.81 KB
 ${SAMPLE_B} :  f1n1z.exe      :  24.57 KB

URL
${URL_A}
${URL_B}

IP
${IP_DUP}: Main C2 / exfil host for samples
${IP_C}: Payload delivery

Domain: ${DOMAIN}

URL Paths
=========
${PATH_ONLY}
/t/861cd3

Full C2 URLs
============
http://${IP_A}:443/t/

FILE AND PATH
=============
/nsconfig/.slap/: install directory
${FS_PATH}: session manager
${URL_B}: agent download path

CREDENTIALS &amp; TOKENS
====================
Auth Token: ${AUTH_TOKEN}
Rogue Username: sec_monitor
Rogue Password: ay#39&amp;RGYvv4Xuzy
Web Shell Password: QI@UEG5PC7oRt31E
Web Shell SHA-256: ${MISLABELED}
Platypus Token: plt_2uhfcg6a7npuwiuaiakb.w6rgc3kclkuwh7nhgr2h

BEHAVORIAL/CONFIG INDICATORS
============================
Rogue superuser: sec_monitor bound with superuser privileges in ns.conf
SUID on shell: chmod 6555 /bin/sh
</code></pre>
</article></body></html>`;
}

function extract() {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `html extract failed: ${r.code}`);
  const out = extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE });
  assert.equal(out.diagnostics.document_scope.has_authoritative_indicator_scope, true, 'MODE A');
  return out;
}

function withEvidence(c) {
  return { ...c, evidence: buildCandidateEvidenceRecord(c) };
}

function members(cands) {
  return cands.map(withEvidence).filter((c) => isReportIndicatorMember(c));
}

test('contract versions for credential/config typing', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v18');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v7');
  assert.ok(FILE_EXT_HINT.has('conf'));
});

test('isCredentialLabeledHex: token vs hash label', () => {
  assert.equal(isCredentialLabeledHex(`Auth Token: ${AUTH_TOKEN}`, AUTH_TOKEN), true);
  assert.equal(isCredentialLabeledHex(`SLAPSHOT Auth Token: ${AUTH_TOKEN}`, AUTH_TOKEN), true);
  assert.equal(isCredentialLabeledHex(`Web Shell SHA-256: ${MISLABELED}`, MISLABELED), false);
  assert.equal(isCredentialLabeledHex(`Hardcoded Hash: ${MISLABELED}`, MISLABELED), false);
  assert.equal(isCredentialLabeledHex(SAMPLE_A, SAMPLE_A), false);
});

test('ns.conf / config suffix is technical_artifact even on an indicator row', () => {
  const r = resolveDottedToken('ns.conf', {
    surroundingText: 'Rogue superuser: sec_monitor bound with superuser privileges in ns.conf',
    strongZone: true,
    indicatorRow: true,
    form: 'standalone'
  });
  assert.equal(r.kind, 'technical_artifact');
  assert.equal(r.reason, 'file_extension');
});

test('Raven-shaped MODE A: Indicators = publisher-asserted supported IOCs only', () => {
  const { candidates } = extract();
  const m = members(candidates);
  const keys = new Set(m.map((c) => `${c.candidate_type}:${c.normalized_value}`));

  // IPs (unique) + samples + URLs + domain + mislabeled hash typed by value
  assert.ok(keys.has(`ip:${IP_A}`));
  assert.ok(keys.has(`ip:${IP_B}`));
  assert.ok(keys.has(`ip:${IP_C}`));
  assert.ok(keys.has(`md5:${SAMPLE_A}`));
  assert.ok(keys.has(`md5:${SAMPLE_B}`));
  assert.ok(keys.has(`md5:${MISLABELED}`), 'mislabeled SHA-256 label typed by 32-hex value as md5 Indicator');
  assert.ok(keys.has(`domain:${DOMAIN}`));
  assert.ok(keys.has(`url:${URL_A}`) || [...keys].some((k) => k.startsWith('url:') && k.includes(IP_A)));
  assert.ok([...keys].some((k) => k.startsWith('url:') && k.includes(DOMAIN)));

  // Extra / incorrect promotions
  assert.equal(keys.has(`md5:${AUTH_TOKEN}`), false, 'auth token must not become md5 Indicator');
  assert.equal(keys.has('domain:ns.conf'), false, 'ns.conf must not become domain Indicator');
  assert.equal(keys.has(`sha256:${NARRATIVE_SHA}`), false, 'narrative-only hash is not a member');
  assert.equal(keys.has(`url:${PATH_ONLY}`), false, 'path-only is not a URL Indicator');
  assert.equal(keys.has(`url:${FS_PATH}`), false, 'filesystem path is not a URL Indicator');

  // Credentials / filenames must not become network IOC types
  for (const c of m) {
    assert.notEqual(c.normalized_value, 'sec_monitor');
    assert.notEqual(c.normalized_value, 'anob4.exe');
    assert.notEqual(c.normalized_value, AUTH_TOKEN);
    assert.notEqual(c.normalized_value, 'ns.conf');
  }

  // Canonical dedup: one IP_A row
  assert.equal(candidates.filter((c) => c.candidate_type === 'ip' && c.normalized_value === IP_A).length, 1);

  // Auth token absent entirely (not just demoted)
  assert.equal(
    candidates.some((c) => c.normalized_value === AUTH_TOKEN),
    false,
    'credential hex is not extracted as a hash candidate'
  );

  // Filenames may exist as non-member context
  const fname = candidates.find((c) => c.normalized_value === 'anob4.exe');
  if (fname) {
    const row = withEvidence(fname);
    assert.equal(isReportIndicatorMember(row), false);
    assert.equal(isContextOnlyCandidate(row) || fname.source_assertion === 'non_ioc', true);
  }

  // Narrative hash may exist in All but not Indicators
  const narr = candidates.find((c) => c.normalized_value === NARRATIVE_SHA);
  if (narr) {
    const row = withEvidence(narr);
    assert.equal(isReportIndicatorMember(row), false);
    assert.notEqual(row.source_assertion, 'explicit_ioc');
  }

  // CVE candidates are never Indicator members
  for (const c of candidates.filter((x) => x.candidate_type === 'cve')) {
    assert.equal(isReportIndicatorMember(withEvidence(c)), false);
  }

  const buckets = countCandidateBuckets(candidates.map(withEvidence));
  assert.equal(buckets.indicators, m.length);
  assert.ok(buckets.all >= buckets.indicators);
});

test('Raven-shaped FE/BE membership parity on representatives', () => {
  const { candidates } = extract();
  const rows = candidates.map(withEvidence);
  const pick = (type, value) => rows.find((c) => c.candidate_type === type && c.normalized_value === value);

  const cases = [
    { c: pick('ip', IP_A), expectMember: true },
    { c: pick('md5', SAMPLE_A), expectMember: true },
    { c: pick('domain', DOMAIN), expectMember: true },
    { c: pick('md5', MISLABELED), expectMember: true },
    { c: pick('sha256', NARRATIVE_SHA), expectMember: false },
    { c: pick('domain', 'ns.conf'), expectMember: false }
  ];

  for (const { c, expectMember } of cases) {
    if (!c && expectMember === false) continue;
    assert.ok(c || expectMember === false, 'missing candidate for expected member');
    if (!c) continue;
    assert.equal(isReportIndicatorMember(c), expectMember, `${c.candidate_type}:${c.normalized_value} BE`);
    assert.equal(isReviewIndicator(c), expectMember, `${c.candidate_type}:${c.normalized_value} FE`);
    assert.equal(isContextOnlyCandidate(c), feContextOnly(c), `${c.candidate_type}:${c.normalized_value} context parity`);
  }

  // URL representative
  const url = rows.find((c) => c.candidate_type === 'url' && String(c.normalized_value).includes(IP_A));
  assert.ok(url);
  assert.equal(isReportIndicatorMember(url), true);
  assert.equal(isReviewIndicator(url), true);
});
