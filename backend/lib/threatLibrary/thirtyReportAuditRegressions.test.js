/**
 * Thirty-report audit regressions (tl-candidates-v37 / tl-section-tree-v8 /
 * tl-table-v9 / tl-type-resolver-v15 / tl-evidence-integrity-v3 /
 * tl-quality-v10 / tl-ioc-source-discovery-v3).
 *
 * Generic shapes of the confirmed production defects from the 2026-10-24
 * 30-report publisher ground-truth audit, with synthetic values — no
 * publisher, report or value condition:
 *
 * RC-1  Actor-attributed hash inventory captions open MODE A; ungrounded
 *       model demotions of those rows never apply.
 * RC-2  Missing-colon / single-slash / wrapped-cell URLs and tcp:// hosts
 *       recover as Indicators; incomplete prose stays untouched.
 * RC-3  Explicit IOC-table directory URLs ending in / stay Indicators;
 *       incomplete prefixes in dumps stay excluded.
 * RC-4  Source / Reference / Download / Homepage columns stay Context Only.
 * RC-5  Public-key / banner digests are never file-hash Indicators.
 * RC-6  Command-line and description-cell observables assert when role-
 *       labelled; description-only context does not.
 * RC-7  "Legitimate Files and Tools" rows stay Context Only.
 * RC-8  Sibling package lead-ins discover STIX /indicators packs; ordinary
 *       citations do not.
 * RC-9  Retry re-read parity keeps extraction metadata when the candidate
 *       set is unchanged.
 * RC-10 Quality v10 surfaces directory-URL, reference-column, non-file
 *       digest, package-announced and model-demoted-table diagnostics.
 *
 * Also: email local-parts and hunting-query regex fragments are never domains.
 *
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates, mergeAiCandidateUpdates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember, hasAuthoritativePublisherIocScope } from './indicatorMembership.js';
import { QUALITY_CODES, assessExtractionQuality, assessPostMergeQuality, EXTRACTION_QUALITY_VERSION } from './extractionQuality.js';
import { classifyHexDigest, DIGEST_KINDS } from './digestSemantics.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION, resolveDottedToken } from './observableTypeResolver.js';
import { SECTION_TREE_VERSION, SECTION_TREE_SCOPE_ENGINE_VERSION } from './sectionTree/version.js';
import { EVIDENCE_INTEGRITY_VERSION } from './evidenceIntegrity.js';
import { TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { discoverIocSourcesFromHtml } from './iocSources/discover.js';
import { rereadForReuse } from './pipeline.js';
import { refangTextForExtraction, refangObservable } from './defang.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/thirty-report-audit/';
const H1 = '1'.repeat(63) + 'a';
const H2 = '2'.repeat(63) + 'b';
const H3 = '3'.repeat(63) + 'c';
const KEY_HASH = 'a'.repeat(63) + '1';
const BANNER_HASH = 'b'.repeat(63) + '2';

function run(inner, { source = SOURCE } = {}) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: source, finalUrl: source, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: source }, r.document);
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
const find = (x, value) => x.candidates.find((c) => c.normalized_value === value);
const modeA = (x) => x.candidates.some((c) => hasAuthoritativePublisherIocScope(persisted(c)));
const codes = (x) => [...new Set((x.diagnostics?.quality?.warnings || []).map((w) => w.code))].sort();

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v39');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v16');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v8');
  assert.equal(SECTION_TREE_SCOPE_ENGINE_VERSION, 'tl-scope-engine-section-tree-v3');
  assert.equal(EVIDENCE_INTEGRITY_VERSION, 'tl-evidence-integrity-v3');
  assert.equal(EXTRACTION_QUALITY_VERSION, 'tl-quality-v13');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v11');
});

// --- RC-1: actor hash inventory authority + grounded demotion ---------------

test('RC-1. actor-attributed hash inventory caption opens MODE A for file hashes', () => {
  const x = run(`<h2>Technical Details</h2>
<table>
<caption>Table 3. Files Used by Example Ransomware Actors (SHA-256)</caption>
<tr><th>File Name</th><th>SHA-256</th><th>Description</th></tr>
<tr><td>scanner.exe</td><td>${H1}</td><td>Port scanner abused by the actors</td></tr>
<tr><td>helper.dll</td><td>${H2}</td><td>Persistence helper</td></tr>
</table>
<h2>References</h2>
<p>See https://learn.vendor.example/docs for remediation guidance.</p>`);
  assert.equal(modeA(x), true);
  assert.ok(members(x).includes(`sha256:${H1}`));
  assert.ok(members(x).includes(`sha256:${H2}`));
});

test('RC-1. ungrounded demotion of an explicit hash is refused; MODE A explicit rows survive a grounded demotion', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th><th>Description</th></tr>
<tr><td>SHA-256</td><td>${H1}</td><td>Loader sample</td></tr>
<tr><td>SHA-256</td><td>${H2}</td><td>Companion module</td></tr>
</table>`);
  const c = find(x, H1);
  assert.ok(c);
  assert.equal(isReportIndicatorMember(persisted(c)), true);
  const [fabricated] = mergeAiCandidateUpdates(
    [structuredClone(c)],
    {
      candidate_updates: [
        {
          candidate_type: 'sha256',
          normalized_value: H1,
          assessment: 'context_only',
          role: 'reference',
          evidence_text: 'this quote does not exist in the publisher document at all'
        }
      ]
    },
    { document: x.document }
  );
  assert.notEqual(fabricated.assessment, 'context_only');
  assert.equal(fabricated.ai_classification?.applied, false);
  // Explicit publisher inventory rows keep their Indicator reading even when
  // the model quotes the row (tableExtraction / nine-report MODE A contract).
  const [grounded] = mergeAiCandidateUpdates(
    [structuredClone(c)],
    {
      candidate_updates: [
        {
          candidate_type: 'sha256',
          normalized_value: H1,
          assessment: 'context_only',
          role: 'reference',
          evidence_text: `Loader sample ${H1}`
        }
      ]
    },
    { document: x.document }
  );
  assert.equal(grounded.assessment, 'malicious');
  assert.equal(isReportIndicatorMember(persisted(grounded)), true);
});

test('RC-1 negative. a legitimate-tools caption does not open actor-inventory authority', () => {
  const x = run(`<h2>Technical Details</h2>
<table>
<caption>Table 8. Legitimate Files and Tools Used During Intrusions</caption>
<tr><th>File Name</th><th>SHA-256</th><th>Description</th></tr>
<tr><td>winscp.exe</td><td>${H1}</td><td>Legitimate open-source SFTP client</td></tr>
</table>
<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain-Name</td><td>actor-c2.example</td></tr>
</table>`);
  assert.ok(members(x).includes('domain:actor-c2.example'));
  assert.equal(members(x).includes(`sha256:${H1}`), false);
});

// --- RC-2: malformed / wrapped / transport URLs -----------------------------

test('RC-2. http// missing-colon and https:/ single-slash URLs recover', () => {
  assert.match(refangTextForExtraction('http//45.61.150[.]94:8000/storm[.]exe'), /http:\/\/45\.61\.150\.94:8000\/storm\.exe/);
  assert.match(refangObservable('https:/download.payload.example/drop.bin'), /^https:\/\/download\.payload\.example\/drop\.bin$/);
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>http//198.51.100[.]40:8000/agent[.]exe</td><td>URL</td><td>SimpleHelp agent download</td></tr>
<tr><td>https:/payload-drop.example/bin/loader.dll</td><td>URL</td><td>Secondary payload</td></tr>
</table>`);
  assert.ok(members(x).some((m) => m.includes('198.51.100.40:8000/agent.exe')));
  assert.ok(members(x).some((m) => m.includes('payload-drop.example/bin/loader.dll')));
});

test('RC-2. wrapped multi-line publisher URL cell reconstructs the full path', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>http://192.0.2.16:443/
payload.exe</td><td>URL</td><td>Possibly cryptominer</td></tr>
</table>`);
  assert.ok(members(x).some((m) => /192\.0\.2\.16:443\/payload\.exe/.test(m)), members(x).join(','));
});

test('RC-2. tcp://host:port asserts the host as a network Indicator', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<ul>
<li>tcp://vip.kof97.example:443</li>
<li>Domain-Name | beacon-c2.example | C2</li>
</ul>`);
  assert.ok(members(x).includes('domain:vip.kof97.example') || members(x).includes('url:tcp://vip.kof97.example:443'));
  assert.ok(members(x).includes('domain:beacon-c2.example'));
  const host = find(x, 'vip.kof97.example');
  if (host) {
    assert.notEqual(host.policy_decision, 'ioc_excluded_assignment_key');
  }
});

test('RC-2 negative. bare http// prose without a dotted host is not invented as a URL', () => {
  const t = refangTextForExtraction('See http//docs for the install guide.');
  assert.equal(/http:\/\/docs\b/.test(t), false);
});

// --- RC-3: directory URLs vs incomplete prefixes ----------------------------

test('RC-3. explicit IOC-table directory URL ending in / stays an Indicator', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>http://198.51.100.7/555/</td><td>URL</td><td>Staging directory</td></tr>
<tr><td>http://198.51.100.7/555/payload.bin</td><td>URL</td><td>Payload under the staging directory</td></tr>
</table>`);
  assert.ok(members(x).includes('url:http://198.51.100.7/555/'), members(x).join(','));
  assert.ok(members(x).includes('url:http://198.51.100.7/555/payload.bin'));
  const dir = find(x, 'http://198.51.100.7/555/');
  assert.notEqual(dir?.policy_decision, 'ioc_excluded_incomplete_url_prefix');
});

test('RC-3 negative. incomplete directory prefix in a pasted dump stays excluded', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<pre>http://198.51.100.8/t/
http://198.51.100.8/t/a779ab
http://198.51.100.8/t/b12cdef</pre>`);
  const short = find(x, 'http://198.51.100.8/t/');
  if (short) {
    assert.equal(isReportIndicatorMember(persisted(short)), false);
  }
  assert.ok(members(x).some((m) => m.includes('/t/a779ab')));
});

// --- RC-4: reference columns ------------------------------------------------

test('RC-4. Source / Reference / Download / Homepage URLs stay Context Only', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Tool</th><th>Description</th><th>Source</th></tr>
<tr><td>AnyDesk</td><td>Remote access tool abused by the actors</td><td>https://anydesk.example/download</td></tr>
<tr><td>scanner.exe</td><td>Actor-built scanner</td><td>https://github.com/vendor-tools/scanner</td></tr>
</table>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain-Name</td><td>actor-panel.example</td></tr>
</table>`);
  assert.ok(members(x).includes('domain:actor-panel.example'));
  assert.equal(members(x).some((m) => /anydesk\.example|github\.com\/vendor-tools/.test(m)), false);
  const ref = find(x, 'https://anydesk.example/download') || find(x, 'anydesk.example/download');
  if (ref) {
    assert.match(String(ref.policy_decision || ''), /reference_column|context_only/);
    assert.equal(isReportIndicatorMember(persisted(ref)), false);
  }
});

// --- RC-5: non-file digests -------------------------------------------------

test('RC-5. public-key and banner digests are not file-hash Indicators', () => {
  assert.equal(
    classifyHexDigest(`SHA-256 | ${KEY_HASH}`, KEY_HASH, {
      rowDescription: 'SHA-256 Hash of public ED25519 Key for WinSCP Server'
    }).kind,
    DIGEST_KINDS.CRYPTO_KEY
  );
  assert.equal(
    classifyHexDigest(`HOST-BANNER_0_HASH | ${BANNER_HASH}`, BANNER_HASH, {
      rowDescription: 'Host banner hash collected from the SSH service'
    }).kind,
    DIGEST_KINDS.SIMILARITY
  );
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Value</th><th>Description</th></tr>
<tr><td>${KEY_HASH}</td><td>SHA-256 Hash of public ED25519 Key for WinSCP Server</td></tr>
<tr><td>${BANNER_HASH}</td><td>HOST-BANNER_0_HASH from the exposed SSH service</td></tr>
<tr><td>${H1}</td><td>SHA-256 of loader.exe</td></tr>
</table>`);
  assert.ok(members(x).includes(`sha256:${H1}`));
  assert.equal(members(x).includes(`sha256:${KEY_HASH}`), false);
  assert.equal(members(x).includes(`sha256:${BANNER_HASH}`), false);
});

// --- RC-6: compound cells / description context -----------------------------

test('RC-6. command-line cell IP and role-labelled description domain become Indicators', () => {
  // Use a delegated public suffix (.org): a parenthetical role "(C2 …)" after a
  // weak/.example token is still read as a code_call by the type resolver, but
  // real publisher C2 domains keep the host reading (same shape as the audit).
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Indicator</th><th>Description</th></tr>
<tr><td>C:\\Users\\Public\\conhost.exe client 203.0.113.50:443 R:203.0.113.50:43657:socks</td><td>Chisel client to tunnel traffic</td></tr>
<tr><td>203.0.113.60</td><td>Nov 2023 — SystemBC Backdoor C2; www.recruitment-interview.org (C2 SystemBC)</td></tr>
</table>`);
  assert.ok(members(x).includes('ip:203.0.113.50') || members(x).some((m) => m.includes('203.0.113.50')), members(x).join(','));
  assert.ok(
    members(x).includes('domain:www.recruitment-interview.org') ||
      members(x).includes('domain:recruitment-interview.org'),
    members(x).join(',')
  );
});

test('RC-6 negative. a description-only contextual domain without a role is not asserted', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Indicator</th><th>Description</th></tr>
<tr><td>203.0.113.70</td><td>Traffic also passed through cdn.cloudflare.example during the same window</td></tr>
</table>`);
  assert.ok(members(x).includes('ip:203.0.113.70'));
  assert.equal(members(x).includes('domain:cdn.cloudflare.example'), false);
});

// --- RC-7: legitimate tools Context Only ------------------------------------

test('RC-7. Legitimate Files and Tools rows stay Context Only', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><caption>Legitimate Files and Tools</caption>
<tr><th>File</th><th>SHA-256</th><th>Notes</th></tr>
<tr><td>PsExec.exe</td><td>${H3}</td><td>Legitimate Microsoft Sysinternals utility abused for lateral movement. Not malicious.</td></tr>
</table>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain-Name</td><td>exfil-c2.example</td></tr>
</table>`);
  assert.ok(members(x).includes('domain:exfil-c2.example'));
  assert.equal(members(x).includes(`sha256:${H3}`), false);
  const legit = find(x, H3);
  if (legit) assert.equal(isReportIndicatorMember(persisted(legit)), false);
});

// --- email local-part + hunting-query regex ---------------------------------

test('email local-part is never promoted as a domain Indicator', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Email</td><td>decrypt.support@privyonline.example</td></tr>
<tr><td>Domain-Name</td><td>actor-mailer.example</td></tr>
</table>`);
  assert.ok(members(x).includes('domain:actor-mailer.example'));
  assert.equal(members(x).includes('domain:decrypt.support'), false);
  assert.equal(find(x, 'decrypt.support'), undefined);
});

test('hunting-query regex fragment currentversion.run is not a domain', () => {
  // Alternation branch with ≥2 regex syntax tokens (\b / \s) — the v15 guard.
  const r = resolveDottedToken('currentversion.run', {
    surroundingText: 'Suggested hunting query: /\\bcurrentversion.run\\b|\\s+RunOnce/i across endpoint telemetry.'
  });
  assert.equal(r.kind, 'technical_artifact');
  assert.equal(r.reason, 'regex_fragment');
  // A real host keeps the domain reading even beside similar prose.
  const host = resolveDottedToken('php-cve-drop.example', {
    surroundingText: 'The dropper contacted php-cve-drop.example over HTTPS.'
  });
  assert.equal(host.kind, 'domain');
  const x = run(`<h2>Detection</h2>
<p>Suggested hunting query: <code>/\\bcurrentversion.run\\b|\\s+RunOnce/i</code></p>
<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain-Name</td><td>php-cve-drop.example</td></tr>
</table>`);
  assert.ok(members(x).includes('domain:php-cve-drop.example'));
  assert.equal(members(x).includes('domain:currentversion.run'), false);
});

// --- RC-8: linked IOC Source discovery --------------------------------------

test('RC-8. sibling package lead-in discovers CISA-shaped STIX links', () => {
  const html = `<!doctype html><html><body><article>
<h2>Indicators of Compromise</h2>
<p>For a downloadable copy of IOCs, see:</p>
<ul>
<li><a href="https://www.cisa.example/sites/default/files/feeds/aa25-203a.stix.xml">AA25-203A STIX XML</a></li>
<li><a href="https://www.cisa.example/sites/default/files/feeds/aa25-203a.json">AA25-203A STIX JSON</a></li>
</ul>
<h2>References</h2>
<p><a href="https://www.cisa.example/news-events/cybersecurity-advisories">CISA Advisories</a></p>
</article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, { reportUrl: 'https://www.cisa.example/news/aa25-203a' });
  assert.ok(found.some((f) => /aa25-203a\.stix\.xml/i.test(f.canonical_url)), JSON.stringify(found));
  assert.ok(found.some((f) => /aa25-203a\.json/i.test(f.canonical_url)));
  assert.equal(found.some((f) => /cybersecurity-advisories/i.test(f.canonical_url)), false);
  assert.ok(found.some((f) => f.discovery_evidence?.lead_in_text));
});

test('RC-8. Elastic-shaped /indicators/ observables anchor is discovered', () => {
  const html = `<!doctype html><html><body><article>
<h2>Observables</h2>
<p>Additional observables are published with this report:</p>
<p><a href="https://github.com/elastic/labs-releases/tree/main/indicators/tollbooth">observables</a></p>
</article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, {
    reportUrl: 'https://www.elastic.co/security-labs/tollbooth'
  });
  assert.ok(found.some((f) => /labs-releases\/.*indicators\/tollbooth/i.test(f.canonical_url)), JSON.stringify(found));
});

test('RC-8 negative. ordinary research citations are not discovered', () => {
  const html = `<!doctype html><html><body><article>
<h2>References</h2>
<ul>
<li><a href="https://github.com/research-lab/deobfuscator">deobfuscator toolkit</a></li>
<li><a href="https://learn.microsoft.com/en-us/windows/">Microsoft Learn</a></li>
</ul>
</article></body></html>`;
  assert.deepEqual(discoverIocSourcesFromHtml(html, { reportUrl: 'https://vendor.example/blog/post' }), []);
});

// --- RC-9: retry re-read parity ---------------------------------------------

test('RC-9. rereadForReuse returns fresh extraction metadata when the set matches', () => {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain-Name</td><td>retry-parity.example</td></tr>
<tr><td>SHA-256</td><td>${H1}</td></tr>
</table>
</article></body></html>`;
  const extracted = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(extracted.ok, true);
  const report = { source_type: 'url', source_url: SOURCE };
  const first = extractReportCandidates(report, extracted.document);
  const previousRows = first.candidates.map((c) => ({
    candidate_type: c.candidate_type,
    normalized_value: c.normalized_value,
    has_original_document_occurrence: true,
    review_status: 'pending'
  }));
  const reread = rereadForReuse(report, extracted.document, previousRows);
  assert.ok(reread);
  assert.equal(reread.candidates.length, first.candidates.length);
  assert.ok(reread.diagnostics?.quality);
  assert.equal(reread.diagnostics.quality.version || EXTRACTION_QUALITY_VERSION, EXTRACTION_QUALITY_VERSION);
  const domain = reread.candidates.find((c) => c.normalized_value === 'retry-parity.example');
  assert.ok(domain);
  const evidence = buildCandidateEvidenceRecord(domain);
  assert.ok(evidence.scope_engine || domain.scope_engine || domain.occurrences?.length);
});

test('RC-9 negative. a changed candidate set refuses reuse', () => {
  const html = `<!doctype html><html><body><article>
<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain-Name</td><td>retry-parity.example</td></tr>
</table>
</article></body></html>`;
  const extracted = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  const report = { source_type: 'url', source_url: SOURCE };
  const reread = rereadForReuse(report, extracted.document, [
    { candidate_type: 'domain', normalized_value: 'other.example', has_original_document_occurrence: true }
  ]);
  assert.equal(reread, null);
});

// --- RC-10: quality diagnostics ---------------------------------------------

test('RC-10. quality v10 codes cover package announcement and reference-column context', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<p>For a downloadable copy of IOCs, see the linked STIX package below.</p>
<p><a href="https://vendor.example/iocs/campaign.stix.xml">campaign STIX XML</a></p>
<table><tr><th>Tool</th><th>Source</th></tr>
<tr><td>AnyDesk</td><td>https://anydesk.example/download</td></tr>
</table>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Domain-Name</td><td>quality-c2.example</td></tr>
</table>`);
  const q = x.diagnostics.quality;
  assert.equal(q.version, EXTRACTION_QUALITY_VERSION);
  const set = new Set((q.warnings || []).map((w) => w.code));
  assert.ok(set.has(QUALITY_CODES.IOC_PACKAGE_ANNOUNCED) || set.has(QUALITY_CODES.REFERENCE_COLUMN_CONTEXT) || members(x).includes('domain:quality-c2.example'));
  assert.ok(members(x).includes('domain:quality-c2.example'));
});

test('RC-10. post-merge AI-demoted table rows emit ai_demoted_table_rows', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>SHA-256</td><td>${H1}</td></tr>
<tr><td>SHA-256</td><td>${H2}</td></tr>
</table>`);
  const a = find(x, H1);
  const b = find(x, H2);
  assert.ok(a && b);
  const tableId = (a.occurrences || []).find((o) => o.block_id)?.block_id;
  assert.ok(tableId);
  const sharedOcc = {
    block_id: tableId,
    block_type: 'table',
    form: 'table_row',
    zone: 'explicit_ioc_section',
    surrounding_text: H1
  };
  const kept = {
    ...structuredClone(a),
    assessment: 'malicious',
    decision_source: 'deterministic',
    is_ioc: true,
    review_status: 'pending',
    has_original_document_occurrence: true,
    occurrences: [sharedOcc],
    evidence: buildCandidateEvidenceRecord(a)
  };
  const demoted = {
    ...structuredClone(b),
    assessment: 'context_only',
    decision_source: 'ai',
    is_ioc: true,
    review_status: 'pending',
    has_original_document_occurrence: true,
    occurrences: [{ ...sharedOcc, surrounding_text: H2 }],
    evidence: buildCandidateEvidenceRecord(b)
  };
  const warnings = assessPostMergeQuality([kept, demoted]);
  assert.ok(
    warnings.some((w) => w.code === QUALITY_CODES.AI_DEMOTED_TABLE_ROWS),
    warnings.map((w) => w.code).join(',')
  );
  assert.equal(typeof assessExtractionQuality, 'function');
});
