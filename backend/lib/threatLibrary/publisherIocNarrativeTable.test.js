/**
 * MODE A: a narrative multi-column IP grid (public third-party endpoints,
 * scanned hosts, etc.) must not become publisher Indicators merely because
 * every cell parses as an IP. Explicit Hosts / Files under an IOC heading
 * remain the Indicator set; duplicates collapse; MODE B stays intact.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { interpretIocTable } from './tableSemantics.js';
import { annotateDocumentZones } from './documentZones.js';
import { buildCandidateEvidenceRecord, isPublisherAuthoritativeReportIocMember } from './evidencePolicy.js';
import { isActionableReviewIndicator, isContextOnlyCandidate } from './promotion.js';

const SOURCE = 'https://research.example/blog/narrative-endpoint-grid/';

const HOST_A = '203.0.113.10';
const HOST_B = '203.0.113.20';
const HOST_C = '198.51.100.30';
const STUN = [
  '5.39.72.109',
  '20.14.234.56',
  '64.131.63.217',
  '74.125.250.129',
  '77.72.169.210',
  '77.72.169.211',
  '81.187.30.115',
  '82.113.193.63',
  '139.162.62.29'
];

function sha(seed) {
  return crypto.createHash('sha256').update(String(seed)).digest('hex');
}

const HASHES = Array.from({ length: 21 }, (_, i) => sha(`file-${i}`));
const DUP_HASH = HASHES[12];

function defangIp(ip) {
  return String(ip).replace(/\./g, '[.]');
}

function reviewRow(c) {
  return { ...c, evidence: buildCandidateEvidenceRecord(c) };
}

function isMember(c) {
  return Boolean(c) && isActionableReviewIndicator(reviewRow(c));
}

function extract(html) {
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `html extract failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }), document: r.document };
}

function fortinetShapedHtml({ includeIocSection = true, stunFirst = true } = {}) {
  const stunRows = [];
  for (let i = 0; i < STUN.length; i += 3) {
    stunRows.push(
      `<tr><td>${defangIp(STUN[i])}</td><td>${defangIp(STUN[i + 1])}</td><td>${defangIp(STUN[i + 2])}</td></tr>`
    );
  }
  const narrative = `
<h1>Synthetic backdoor abuses public endpoint infrastructure</h1>
<h2>Incidents</h2>
<p>The threat actor delivered the payload from ${defangIp(HOST_A)} by exploiting CVE-2022-36553.</p>
<p>Later download sources included ${defangIp(HOST_B)} and ${defangIp(HOST_C)}.</p>
<table>
<tr><th>CVE ID</th><th>Vendor</th><th>Entry Point</th><th>Attack Type</th></tr>
<tr><td>CVE-2022-36553</td><td>Example</td><td>cgi</td><td>Command Injection</td></tr>
<tr><td>CVE-2024-23625</td><td>Example</td><td>UPnP</td><td>Code Injection</td></tr>
</table>
<h2>Malware Analysis</h2>
<p>The implant sends STUN binding requests to public endpoints. These third-party
services should not be automatically classified as attacker-controlled infrastructure.</p>
<table>
${stunRows.join('\n')}
</table>
<p>Figure: STUN binding with public endpoints</p>
<h2>Conclusion</h2>
<p>Public third-party services contacted for NAT traversal are contextual evidence.</p>
`;

  const ioc = includeIocSection
    ? `
<h2>IOCs</h2>
<h3>Hosts</h3>
<p>${defangIp(HOST_A)}</p>
<p>${defangIp(HOST_B)}</p>
<p>${defangIp(HOST_C)}</p>
<h3>Files</h3>
${HASHES.map((h) => `<p>${h}</p>`).join('\n')}
<p>${DUP_HASH}</p>
`
    : '';

  // Keep both orders inside one article root so the HTML extractor retains them.
  const body = stunFirst ? `${narrative}${ioc}` : `${ioc}${narrative}`;
  return `<!doctype html><html><body><article>${body}</article></body></html>`;
}

test('dense headerless IP grid is not a self-proving explicit IOC table', () => {
  const interp = interpretIocTable({
    id: 'stun',
    table: {
      headers: null,
      rows: [
        [defangIp(STUN[0]), defangIp(STUN[1]), defangIp(STUN[2])],
        [defangIp(STUN[3]), defangIp(STUN[4]), defangIp(STUN[5])],
        [defangIp(STUN[6]), defangIp(STUN[7]), defangIp(STUN[8])]
      ]
    }
  });
  assert.equal(interp.kind, 'ioc_table');
  assert.equal(interp.explicit, false);
  assert.equal(interp.dense_observables, true);
  assert.equal(interp.reason, 'dense_without_type_or_header');
});

test('typed / header-labelled tables still self-prove without an IOC heading', () => {
  const typed = interpretIocTable({
    id: 'typed',
    table: {
      headers: null,
      rows: [
        ['IP', defangIp(HOST_A)],
        ['SHA256', HASHES[0]]
      ]
    }
  });
  assert.equal(typed.explicit, true, 'type column still proves the table');
  const labelled = interpretIocTable({
    id: 'labelled',
    table: {
      headers: ['Indicator', 'Description'],
      rows: [
        [defangIp(HOST_A), 'download source'],
        [defangIp(HOST_B), 'download source']
      ]
    }
  });
  assert.equal(labelled.explicit, true, 'header-labelled indicator column still proves the table');
});

test('zone annotate: narrative dense IP table stays report_body; IOC Hosts/Files stay authoritative', () => {
  const r = extractCanonicalDocumentFromHtml(fortinetShapedHtml(), {
    url: SOURCE,
    finalUrl: SOURCE,
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const annotated = annotateDocumentZones(r.document, { sourceUrl: SOURCE });
  const stunTable = annotated.blocks.find(
    (b) => b.type === 'table' && b.ioc_table && String(b.ioc_table.reason || '').includes('dense')
  );
  assert.ok(stunTable, 'stun-like table present');
  assert.notEqual(stunTable.zone, 'explicit_ioc_section');
  assert.equal(stunTable.ioc_table.explicit, false);
  const iocHeading = annotated.blocks.find((b) => b.type === 'heading' && /^IOCs$/i.test(String(b.text || '').trim()));
  assert.ok(iocHeading);
  assert.equal(iocHeading.zone, 'explicit_ioc_section');
});

test('MODE A Fortinet-shaped report: Indicators = 3 hosts + 21 unique hashes; STUN grid excluded', () => {
  const { candidates, diagnostics } = extract(fortinetShapedHtml());
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true);

  const members = candidates.filter(isMember);
  const memberIps = members.filter((c) => c.candidate_type === 'ip').map((c) => c.normalized_value).sort();
  const memberHashes = members.filter((c) => c.candidate_type === 'sha256').map((c) => c.normalized_value).sort();

  assert.deepEqual(memberIps, [HOST_A, HOST_B, HOST_C].sort());
  assert.equal(memberHashes.length, 21);
  assert.deepEqual(memberHashes, [...HASHES].sort());
  assert.equal(members.length, 24);

  for (const ip of STUN) {
    const row = candidates.find((c) => c.candidate_type === 'ip' && c.normalized_value === ip);
    assert.ok(row, `${ip} retained as candidate`);
    assert.equal(isMember(row), false, `${ip} must not be a report Indicator`);
    assert.equal(isPublisherAuthoritativeReportIocMember(reviewRow(row)), false);
    assert.notEqual(row.source_assertion, 'explicit_ioc');
    // May be Context Only (MODE A narrative demotion) or All-only body_mention;
    // never an actionable Indicator.
    assert.equal(
      isContextOnlyCandidate(reviewRow(row)) || row.source_assertion === 'body_mention',
      true,
      `${ip} stays contextual / All-only`
    );
  }

  const hostA = candidates.find((c) => c.normalized_value === HOST_A);
  assert.ok(hostA);
  assert.equal(isMember(hostA), true);
  assert.ok(hostA.occurrence_count >= 2, 'narrative + explicit IOC occurrences collapse');
  assert.match(String(hostA.source_assertion), /^explicit_/);

  const dup = candidates.filter((c) => c.normalized_value === DUP_HASH);
  assert.equal(dup.length, 1);
  assert.equal(isMember(dup[0]), true);
  assert.ok(dup[0].occurrence_count >= 2);
});

test('MODE A: IOC section before narrative STUN grid still excludes the grid (order independence)', () => {
  const { candidates } = extract(fortinetShapedHtml({ stunFirst: false }));
  const members = candidates.filter(isMember);
  assert.equal(members.length, 24);
  for (const ip of STUN) {
    const row = candidates.find((c) => c.normalized_value === ip);
    assert.equal(isMember(row), false, ip);
  }
  assert.equal(isMember(candidates.find((c) => c.normalized_value === HOST_A)), true);
});

test('MODE B: prose-only C2 topic without curated rows does not open publisher scope', () => {
  // Dense narrative grids must not change MODE B: a prose-only C2 topic
  // heading is still not a curated section (same contract as overextraction suite).
  const { candidates, diagnostics } = extract(`
<h2>C2 infrastructure</h2>
<p>The implant beacons to ${defangIp(HOST_A)} and later downloads a stage from ${defangIp(HOST_B)}.</p>
<h2>Network activity</h2>
<p>A secondary callback was observed at ${defangIp(HOST_C)}.</p>`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, false);
  for (const ip of [HOST_A, HOST_B, HOST_C]) {
    const row = reviewRow(candidates.find((c) => c.normalized_value === ip));
    assert.ok(row, ip);
    assert.equal(isPublisherAuthoritativeReportIocMember(row), true, `${ip} MODE B membership gate open`);
  }
});
