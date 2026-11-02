/**
 * Hunt Need-Review false-negative regressions (tl-candidates-v54 /
 * tl-table-v17 / tl-section-tree-v14).
 *
 * Generic shapes of five confirmed extraction false negatives, with
 * synthetic values — no publisher, report or value condition:
 *
 * FN-1 A wildcard host in an IOC table cell ("*.example.st") asserts its
 *      registrable apex; public / shared-platform suffixes and file globs do not.
 * FN-2 tcp:// / udp:// / tls:// endpoints in an IOC table cell assert their
 *      host (like fqdn://), keeping the port as occurrence provenance.
 * FN-3 A plain domain in a certificate Common Name column of an IOC table is
 *      a domain observable of the row.
 * FN-4 A hash the IOC table truncates with an ellipsis links to the unique
 *      full digest elsewhere in the report instead of becoming a shorter
 *      digest; an unmatched / ambiguous truncation reads as before.
 * FN-5 "IOCs and Observables" style headings open an IOC scope, so firm
 *      C2 / staging / case-observed rows of the infrastructure table assert,
 *      while rows the publisher describes as a historical resolution of
 *      another name stay context.
 *
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { TABLE_SEMANTICS_VERSION, findTruncatedDigests, parseIndicatorCell } from './tableSemantics.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { SECTION_ROLES, classifySectionRole } from './indicatorScope.js';
import { isPublicOrSharedPlatformSuffix } from './observableTypeResolver.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/hunt-false-negatives/';

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
const isMember = (x, value) => {
  const c = find(x, value);
  return c ? isReportIndicatorMember(persisted(c)) : false;
};

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v54');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v17');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v14');
});

// --- FN-1: wildcard apex ------------------------------------------------------

test('FN-1 unit. a whole-cell wildcard yields its registrable apex', () => {
  const parsed = parseIndicatorCell('*.wild-c2-one.st', { type: 'domain', endpoint: false });
  assert.equal(parsed.values.length, 1);
  assert.equal(parsed.values[0].candidate_type, 'domain');
  assert.equal(parsed.values[0].normalized_value, 'wild-c2-one.st');
  assert.equal(parsed.values[0].wildcard_apex, true);
  // Defanged spelling.
  const defanged = parseIndicatorCell('*[.]wild-c2-two[.]com', null);
  assert.equal(defanged.values[0]?.normalized_value, 'wild-c2-two.com');
});

test('FN-1 negative. suffix, shared-platform and file-glob wildcards assert no apex', () => {
  assert.equal(isPublicOrSharedPlatformSuffix('co.uk'), true);
  assert.equal(isPublicOrSharedPlatformSuffix('trycloudflare.com'), true);
  assert.equal(isPublicOrSharedPlatformSuffix('wild-c2-one.st'), false);
  for (const cell of ['*.co.uk', '*.trycloudflare.com', '*.tar.gz', '*.exe', '*.*.wild-c2-one.st']) {
    const parsed = parseIndicatorCell(cell, { type: 'domain', endpoint: false });
    assert.equal(
      parsed.values.some((v) => v.wildcard_apex === true),
      false,
      `${cell} must not assert an apex`
    );
  }
});

test('FN-1. wildcard C2 domains in an explicit IOC table are Indicators of their apex', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table>
<tr><th>Indicator</th><th>Type</th><th>Description</th></tr>
<tr><td>*.wild-c2-one.st</td><td>Domain</td><td>C2 domain</td></tr>
<tr><td>*.wild-c2-two.com</td><td>Domain</td><td>C2 domain</td></tr>
</table>`);
  assert.ok(members(x).includes('domain:wild-c2-one.st'), members(x).join(','));
  assert.ok(members(x).includes('domain:wild-c2-two.com'), members(x).join(','));
  assert.equal(
    x.candidates.some((c) => String(c.normalized_value).includes('*')),
    false,
    'the wildcard label is never part of an identity'
  );
});

// --- FN-2: tcp:// endpoints in IOC tables ------------------------------------------

test('FN-2 unit. tcp:// / udp:// / tls:// cells name their host and keep the port', () => {
  const dns = parseIndicatorCell('tcp://alpha-beta-gamma[.]trycloudflare[.]com:443', null);
  assert.equal(dns.values.length, 1);
  assert.equal(dns.values[0].candidate_type, 'domain');
  assert.equal(dns.values[0].normalized_value, 'alpha-beta-gamma.trycloudflare.com');
  assert.equal(dns.values[0].port, 443);
  assert.equal(dns.values[0].endpoint_scheme, 'tcp');
  const ip = parseIndicatorCell('udp://91.215.85.20:5353', null);
  assert.equal(ip.values[0]?.candidate_type, 'ip');
  assert.equal(ip.values[0]?.normalized_value, '91.215.85.20');
  assert.equal(ip.values[0]?.port, 5353);
  const tls = parseIndicatorCell('tls://relay-node.example-c2.net:8443', null);
  assert.equal(tls.values[0]?.normalized_value, 'relay-node.example-c2.net');
  // A path makes it something else: no host is invented from it.
  const path = parseIndicatorCell('tcp://relay-node.example-c2.net:8443/stage', null);
  assert.equal(path.values.some((v) => v.endpoint_scheme === 'tcp'), false);
});

test('FN-2. tcp:// endpoints of an explicit IOC table are Indicators, not context', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table>
<tr><th>Indicator</th><th>Description</th></tr>
<tr><td>tcp://alpha-beta-gamma.trycloudflare.com:443</td><td>Reverse-shell C2 endpoint</td></tr>
<tr><td>tcp://delta-epsilon-zeta.trycloudflare.com:443</td><td>Second reverse-shell C2 endpoint</td></tr>
</table>`);
  assert.ok(members(x).includes('domain:alpha-beta-gamma.trycloudflare.com'), members(x).join(','));
  assert.ok(members(x).includes('domain:delta-epsilon-zeta.trycloudflare.com'), members(x).join(','));
  const host = find(x, 'alpha-beta-gamma.trycloudflare.com');
  assert.ok(host.parsed?.ports?.includes(443), 'the port stays occurrence provenance');
});

// --- FN-3: certificate Common Name column ----------------------------------------------

test('FN-3. a domain in a TLS certificate Common Name column is a domain Indicator', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table>
<tr><th>IP Address</th><th>TLS Cert Common Name</th><th>Description</th></tr>
<tr><td>91.215.85.44</td><td>cn-example-one.com</td><td>Staging server</td></tr>
<tr><td>91.215.85.45</td><td>Example Org Inc</td><td>Second server</td></tr>
</table>`);
  assert.ok(members(x).includes('ip:91.215.85.44'), members(x).join(','));
  assert.ok(members(x).includes('ip:91.215.85.45'), members(x).join(','));
  assert.ok(members(x).includes('domain:cn-example-one.com'), members(x).join(','));
  const cn = find(x, 'cn-example-one.com');
  assert.equal(cn.table_rows?.[0]?.certificate_cn, true);
  // A non-domain Common Name never becomes a candidate.
  assert.equal(
    x.candidates.some((c) => /example org/i.test(String(c.normalized_value))),
    false
  );
});

test('FN-3 negative. a certificate thumbprint column and an issuer column stay attributes', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table>
<tr><th>IP Address</th><th>Certificate Issuer</th><th>Description</th></tr>
<tr><td>91.215.85.46</td><td>issuer-ca-example.com</td><td>Staging server</td></tr>
</table>`);
  assert.ok(members(x).includes('ip:91.215.85.46'), members(x).join(','));
  assert.equal(find(x, 'issuer-ca-example.com'), undefined);
});

// --- FN-4: truncated hash vs full body digest ---------------------------------------

const FULL = 'e76f54b7b98ba3a08f39392e6886a9cb5c1d0e2f3a4b69788796a5b4c3d2e1f0';
const PREFIX = FULL.slice(0, 32);

test('FN-4 unit. findTruncatedDigests reads only ellipsis-cut hex prefixes', () => {
  const cut = findTruncatedDigests(`SHA256: ${PREFIX}...`);
  assert.equal(cut.length, 1);
  assert.equal(cut[0].prefix, PREFIX);
  assert.equal(cut[0].label_length, 64);
  // A complete labelled digest followed by an ellipsis is not a truncation.
  assert.deepEqual(findTruncatedDigests(`MD5: ${PREFIX}...`), []);
  // Short prefixes and elisions inside a digest identify nothing.
  assert.deepEqual(findTruncatedDigests('e76f54b7…0be392ed8'), []);
  assert.equal(findTruncatedDigests(`${FULL.slice(0, 20)}…`)[0]?.prefix, FULL.slice(0, 20));
});

test('FN-4 unit. parseIndicatorCell marks the look-alike digest of a truncation', () => {
  const parsed = parseIndicatorCell(`SHA256: ${PREFIX}...`, null);
  assert.equal(parsed.truncated_digests?.length, 1);
  const lookalike = parsed.values.find((v) => v.normalized_value === PREFIX);
  assert.ok(lookalike?.truncated_digest, 'the md5-shaped prefix is marked, not asserted');
});

test('FN-4. a truncated IOC-table digest links to the unique full body digest', () => {
  const x = run(`<h2>Implant analysis</h2>
<table>
<tr><th>Property</th><th>Value</th></tr>
<tr><td>SHA-256</td><td>${FULL}</td></tr>
<tr><td>File type</td><td>ELF executable</td></tr>
</table>
<h2>Indicators of Compromise</h2>
<table>
<tr><th>Filename</th><th>Type</th><th>Context</th></tr>
<tr><td>httd</td><td>Go ELF</td><td>SHA256: ${PREFIX}...</td></tr>
</table>`);
  assert.equal(find(x, PREFIX), undefined, 'the truncated prefix is never a shorter digest');
  const full = find(x, FULL);
  assert.ok(full, 'full digest candidate exists');
  assert.ok(
    (full.occurrences || []).some((o) => o.truncated_digest === true),
    'the IOC-table row is an occurrence of the full digest'
  );
  assert.equal(full.original_value, FULL, 'the digest keeps its own spelling');
  assert.ok(members(x).includes(`sha256:${FULL}`), members(x).join(','));
});

test('FN-4 negative. a truncation with no matching full digest reads as before', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table>
<tr><th>Filename</th><th>Type</th><th>Context</th></tr>
<tr><td>httd</td><td>Go ELF</td><td>SHA256: ${PREFIX}...</td></tr>
</table>`);
  assert.equal(find(x, FULL), undefined, 'no digest is invented');
});

test('FN-4 negative. an ambiguous truncation links to neither full digest', () => {
  const other = PREFIX + '0'.repeat(32);
  const x = run(`<h2>Implant analysis</h2>
<table>
<tr><th>Property</th><th>Value</th></tr>
<tr><td>SHA-256 (first sample)</td><td>${FULL}</td></tr>
<tr><td>SHA-256 (second sample)</td><td>${other}</td></tr>
</table>
<h2>Indicators of Compromise</h2>
<table>
<tr><th>Filename</th><th>Type</th><th>Context</th></tr>
<tr><td>httd</td><td>Go ELF</td><td>SHA256: ${PREFIX}...</td></tr>
</table>`);
  for (const value of [FULL, other]) {
    assert.equal(
      (find(x, value)?.occurrences || []).some((o) => o.truncated_digest === true),
      false,
      'ambiguous prefix must not link'
    );
  }
});

// --- FN-5: closed-pair IOC heading + historical resolution pivots --------------------

test('FN-5 unit. closed IOC-term pairs head an IOC inventory; narrative headings do not', () => {
  assert.equal(classifySectionRole('IOCs and Observables'), SECTION_ROLES.IOC_APPENDIX);
  assert.equal(classifySectionRole('IOCs and network observables'), SECTION_ROLES.IOC_APPENDIX);
  assert.equal(classifySectionRole('Indicators & Artifacts'), SECTION_ROLES.IOC_APPENDIX);
  assert.equal(classifySectionRole('Mixed benign and malicious observables near IOC inventory'), null);
  assert.equal(classifySectionRole('IOCs and why they matter for this campaign'), null);
  assert.equal(classifySectionRole('Why IOCs and observables matter'), null);
});

test('FN-5 negative. a row that only mentions past resolution still asserts its address', () => {
  const x = run(`<h2>Appendix: Indicators of Compromise</h2>
<table>
<tr><th>Indicator</th><th>Notes</th></tr>
<tr><td>91.215.85.30</td><td>Open-directory staging server; historically resolved C2 domains via vpn-example.com since 2023</td></tr>
</table>`);
  assert.ok(members(x).includes('ip:91.215.85.30'), members(x).join(','));
});

test('FN-5. firm C2 / staging / case-observed table rows assert; historical resolution pivots stay context', () => {
  const x = run(`<h2>IOCs and Observables</h2>
<p>Table 1: Network infrastructure</p>
<table>
<tr><th>Indicator</th><th>ASN</th><th>Provider</th><th>Country</th><th>Context</th></tr>
<tr><td>91.215.85.10</td><td>AS64500</td><td>Example Hosting</td><td>Estonia</td><td>Primary staging, C2 and tunnelling server.</td></tr>
<tr><td>91.215.85.11</td><td>AS64500</td><td>Example Hosting</td><td>Estonia</td><td>Case-observed intrusion-set infrastructure.</td></tr>
<tr><td>91.215.85.12</td><td>AS64500</td><td>Example Hosting</td><td>Estonia</td><td>Staging server associated with installer.msi.</td></tr>
<tr><td>45.12.34.56</td><td>AS64501</td><td>Other Hosting</td><td>Germany</td><td>Historical resolution for pivot-one[.]com.</td></tr>
</table>`);
  assert.ok(members(x).includes('ip:91.215.85.10'), members(x).join(','));
  assert.ok(members(x).includes('ip:91.215.85.11'), members(x).join(','));
  assert.ok(members(x).includes('ip:91.215.85.12'), members(x).join(','));
  assert.equal(isMember(x, '45.12.34.56'), false, 'a historical-resolution pivot is not auto-promoted');
  const pivot = find(x, '45.12.34.56');
  assert.ok(pivot, 'the pivot is kept as context, never dropped');
  assert.equal(pivot.policy_decision, 'context_only_resolution_column');
});
