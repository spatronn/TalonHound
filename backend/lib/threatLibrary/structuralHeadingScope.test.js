/**
 * Structural IOC scope hardening (tl-zones-v10 / tl-candidates-v27):
 *
 * Risk A — a bold/short paragraph that names C2 must face the same indicator-
 * content confirmation as a real HTML heading. Technical API examples alone
 * must not open an authoritative c2_section.
 *
 * Risk B — a sibling heading such as "Receiving a command" is a topic
 * boundary, not an artifact-type sub-list that inherits the previous C2
 * section's authority.
 *
 * No vendor allowlists: the same Graph URL listed in an IOC section remains
 * an Indicator; a URL only in technical prose does not inherit authority.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { annotateDocumentZones, THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import { createCanonicalDocument } from './canonicalDocument.js';

const SOURCE = 'https://research.example/blog/structural-heading-scope/';
const GRAPH = 'https://graph.microsoft.com/v1.0/organization';
const RELAY = 'relay-node-17.net';
const PATH_URL = 'https://example.test/callback';

test('structural heading scope contracts', () => {
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v16');
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v47');
});

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>Structural heading scope</title></head><body><article>
<p>Background paragraph describing the framework and its controller architecture across several environments.</p>
${inner}
</article></body></html>`;
}

function extract(inner) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  const zoned = annotateDocumentZones(r.document, { sourceUrl: SOURCE });
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }), document: r.document, zoned };
}

const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value);
const persisted = (c) => ({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const isMember = (c) => Boolean(c) && isReportIndicatorMember(persisted(c));
const memberKeys = (cands) =>
  cands
    .filter(isMember)
    .map((c) => `${c.candidate_type}:${c.normalized_value}`)
    .sort();
const zoneOf = (zoned, re) => zoned.blocks.find((b) => re.test(String(b.text || '')))?.zone ?? null;
const reasonOf = (zoned, re) => zoned.blocks.find((b) => re.test(String(b.text || '')))?.zone_reason ?? null;

const TECH_ONLY = `
<p>The malware validates authentication using:</p>
<pre>GET ${GRAPH}</pre>
`;

test('bold C2 heading + technical API examples only: no authoritative IOC scope', () => {
  const { candidates, zoned } = extract(`
<p><strong>Microsoft-hosted services for C2</strong></p>
${TECH_ONLY}
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  assert.equal(zoneOf(zoned, /^Microsoft-hosted services for C2$/), 'report_body');
  assert.equal(reasonOf(zoned, /^Microsoft-hosted services for C2$/), 'indicator_heading_unconfirmed');
  assert.equal(zoneOf(zoned, /validates authentication/), 'report_body');
  const graph = find(candidates, 'url', GRAPH);
  assert.ok(graph, 'technical observable remains visible');
  assert.equal(isMember(graph), false);
  assert.ok(!String(graph.source_assertion).startsWith('explicit_'));
  assert.deepEqual(memberKeys(candidates), ['domain:evil-example.com']);
});

test('real HTML C2 heading with equivalent technical content matches bold classification', () => {
  const bold = extract(`
<p><strong>Microsoft-hosted services for C2</strong></p>
${TECH_ONLY}
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  const real = extract(`
<h2>Microsoft-hosted services for C2</h2>
${TECH_ONLY}
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  assert.equal(zoneOf(bold.zoned, /validates authentication/), zoneOf(real.zoned, /validates authentication/));
  assert.equal(isMember(find(bold.candidates, 'url', GRAPH)), false);
  assert.equal(isMember(find(real.candidates, 'url', GRAPH)), false);
  assert.deepEqual(memberKeys(bold.candidates), memberKeys(real.candidates));
});

test('bold C2 heading with actual IOC structure preserves publisher Indicators', () => {
  const { candidates, zoned } = extract(`
<p><strong>Command and control infrastructure</strong></p>
<ul><li>${RELAY.replace(/\./g, '[.]')}</li><li>198[.]51[.]100[.]20</li></ul>
<h2>Conclusion</h2>
<p>Done.</p>`);
  assert.equal(zoneOf(zoned, /^Command and control infrastructure$/), 'c2_section');
  assert.equal(zoneOf(zoned, /relay-node-17/), 'c2_section');
  assert.equal(isMember(find(candidates, 'domain', RELAY)), true);
  assert.equal(isMember(find(candidates, 'ip', '198.51.100.20')), true);
});

test('C2 heading followed by unrelated sibling terminates previous authority', () => {
  const { candidates, zoned } = extract(`
<h2>Command and control infrastructure</h2>
<ul><li>evil-relay[.]example</li></ul>
<h2>Receiving a command</h2>
<p>The malware makes a GET request to: ${GRAPH}</p>
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  assert.equal(reasonOf(zoned, /^Receiving a command$/), 'heading_reset');
  assert.equal(zoneOf(zoned, /makes a GET request/), 'report_body');
  assert.equal(isMember(find(candidates, 'domain', 'evil-relay.example')), true);
  assert.equal(isMember(find(candidates, 'url', GRAPH)), false);
});

test('sibling heading titled Receiving a command is a heading boundary', () => {
  const d = createCanonicalDocument({
    title: 'Sibling boundary',
    language: 'en',
    blocks: [
      { id: 'h1', type: 'heading', level: 2, text: 'Command and control infrastructure' },
      { id: 'r1', type: 'list_item', text: 'listed-c2[.]net' },
      { id: 'h2', type: 'heading', level: 2, text: 'Receiving a command' },
      { id: 'p', type: 'paragraph', text: `The implant requests ${GRAPH} during setup.` }
    ]
  });
  const z = annotateDocumentZones(d);
  assert.equal(z.blocks.find((b) => b.id === 'h2').zone_reason, 'heading_reset');
  assert.equal(z.blocks.find((b) => b.id === 'p').zone, 'report_body');
  assert.ok(!z.meta.scope_trace.some((t) => t.decision === 'typed_subheading' && /Receiving/.test(t.heading || '')));
});

test('nested Indicators of compromise subsections keep Indicator membership', () => {
  const { candidates, zoned } = extract(`
<h2>Indicators of compromise</h2>
<h3>Network</h3>
<ul><li>nested-one[.]net</li></ul>
<h3>Hashes</h3>
<ul><li>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</li></ul>`);
  assert.equal(zoneOf(zoned, /^nested-one/), 'explicit_ioc_section');
  assert.equal(isMember(find(candidates, 'domain', 'nested-one.net')), true);
  assert.equal(isMember(find(candidates, 'sha256', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')), true);
});

test('same URL in technical prose and explicit IOC list is one canonical Indicator', () => {
  const { candidates } = extract(`
<h2>Technical details</h2>
<h3>Command and control channel</h3>
<p>The module validates access through a GET request to ${PATH_URL} before polling.</p>
<pre>GET /v1.0/organization</pre>
<h2>Indicators of compromise</h2>
<p>${PATH_URL}</p>
<p>evil-example[.]com</p>`);
  const rows = candidates.filter((c) => c.candidate_type === 'url' && c.normalized_value === PATH_URL);
  assert.equal(rows.length, 1);
  assert.ok(rows[0].occurrences.some((o) => o.asserted === true));
  assert.equal(isMember(rows[0]), true);
});

test('URL only in technical prose is not promoted through structural leakage', () => {
  const { candidates } = extract(`
<h2>Command and control infrastructure</h2>
<ul><li>evil-relay[.]example</li></ul>
<h2>Receiving a command</h2>
<p>The malware makes a GET request to: ${GRAPH}</p>
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  assert.equal(isMember(find(candidates, 'url', GRAPH)), false);
  assert.deepEqual(memberKeys(candidates).sort(), ['domain:evil-example.com', 'domain:evil-relay.example'].sort());
});

test('narrative publisher C2 assertion remains supported', () => {
  const { candidates } = extract(`
<h2>Analysis</h2>
<p>The implant connects to panel-c2.example.net over TCP 8443 and beacons every 30 seconds.</p>
`);
  const c2 = find(candidates, 'domain', 'panel-c2.example.net');
  assert.ok(c2);
  // Outside MODE A curated sections the operational narrative stays on the AI path
  // or becomes an asserted relation per existing policy — never dropped.
  assert.notEqual(c2.assessment, undefined);
  assert.ok(c2.source_relation === 'operational_malicious' || c2.ai_needed === true || c2.assessment === 'malicious');
});

test('technical table / code under a C2-themed heading is not an IOC table authority', () => {
  const { zoned, candidates } = extract(`
<h2>Microsoft-hosted services for C2</h2>
<table><thead><tr><th>Subject format</th><th>Purpose</th></tr></thead><tbody>
<tr><td>Event ID</td><td>Operator-to-agent command</td></tr>
</tbody></table>
<pre>GET ${GRAPH}</pre>
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  assert.equal(zoneOf(zoned, /^Microsoft-hosted services for C2$/), 'report_body');
  assert.equal(isMember(find(candidates, 'url', GRAPH)), false);
});

test('h2 / h3 / strong C2 headings agree when content is technical-only', () => {
  const bodies = [
    `<h2>Outlook calendar events as a C2 channel</h2>${TECH_ONLY}`,
    `<h3>Outlook calendar events as a C2 channel</h3>${TECH_ONLY}`,
    `<p><strong>Outlook calendar events as a C2 channel</strong></p>${TECH_ONLY}`
  ];
  const zones = bodies.map((inner) => {
    const { zoned } = extract(`${inner}<h2>Indicators of compromise</h2><p>evil-example[.]com</p>`);
    return zoneOf(zoned, /validates authentication/);
  });
  assert.deepEqual(zones, ['report_body', 'report_body', 'report_body']);
});

test('non-IOC descriptive table adjacent to IOC material does not create false authority', () => {
  const { zoned, candidates } = extract(`
<h2>Command and control infrastructure</h2>
<table><thead><tr><th>Subject format</th><th>Purpose</th><th>Module behavior</th></tr></thead><tbody>
<tr><td>Event ID</td><td>Operator command</td><td>Downloads attachments</td></tr>
</tbody></table>
<p>The module validates access through a GET request to ${GRAPH}.</p>
<h2>Indicators of compromise</h2>
<ul><li>evil-example[.]com</li></ul>`);
  assert.equal(zoneOf(zoned, /^Command and control infrastructure$/), 'report_body');
  assert.equal(isMember(find(candidates, 'url', GRAPH)), false);
  assert.equal(isMember(find(candidates, 'domain', 'evil-example.com')), true);
});

test('bold sibling after a real C2 list terminates inherited authority', () => {
  const { candidates, zoned } = extract(`
<h2>Command and control infrastructure</h2>
<ul><li>evil-relay[.]example</li></ul>
<p><strong>Receiving a command</strong></p>
<p>The malware makes a GET request to: ${GRAPH}</p>
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  assert.equal(reasonOf(zoned, /^Receiving a command$/), 'heading_reset');
  assert.equal(zoneOf(zoned, /makes a GET request/), 'report_body');
  assert.equal(isMember(find(candidates, 'url', GRAPH)), false);
});

test('intro sentence under a C2 heading does not close the curated list that follows', () => {
  const { zoned, candidates } = extract(`
<h2>C2 infrastructure</h2>
<p>The following servers were used:</p>
<h3>Servers</h3>
<ul><li>relay-node-17[.]net</li><li>relay-node-18[.]net</li></ul>
<h2>Conclusion</h2><p>Done.</p>`);
  assert.equal(zoneOf(zoned, /following servers/), 'c2_section');
  assert.equal(zoneOf(zoned, /relay-node-17/), 'c2_section');
  assert.equal(isMember(find(candidates, 'domain', 'relay-node-17.net')), true);
});

test('annotated defanged IOC value lines do not terminate an IOC section', () => {
  const { zoned, candidates } = extract(`
<h2>Indicators of compromise (IOCs)</h2>
<p>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (malicious HTA stager)</p>
<p>osc-cdn[.]com (actor-used spear-phishing sender domain)</p>
<p>relay-node-17[.]net</p>`);
  assert.equal(zoneOf(zoned, /osc-cdn/), 'explicit_ioc_section');
  assert.equal(zoneOf(zoned, /relay-node-17/), 'explicit_ioc_section');
  assert.equal(isMember(find(candidates, 'domain', 'osc-cdn.com')), true);
  assert.equal(isMember(find(candidates, 'domain', 'relay-node-17.net')), true);
});

test('bold malware-family labels under File hashes keep short hash groups as Indicators', () => {
  // Securelist-shaped appendix: each family is a <strong> label + <br>-split
  // hashes. Labels are not type vocabulary; short groups (1–2 hashes) must not
  // lose publisher scope just because OBSERVABLE_LIST_MIN_ROWS recovery needs ≥3.
  const H = {
    a1: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    a2: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    b1: 'cccccccccccccccccccccccccccccccc',
    g1: 'dddddddddddddddddddddddddddddddd',
    g2: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    g3: 'ffffffffffffffffffffffffffffffff',
    g4: '11111111111111111111111111111111',
    d1: '22222222222222222222222222222222',
    d2: '33333333333333333333333333333333'
  };
  const { zoned, candidates } = extract(`
<h2>Indicators of compromise</h2>
<h3>File hashes</h3>
<p><strong>FamilyAlpha</strong><br>${H.a1}<br>${H.a2}</p>
<p><strong>FamilyBeta</strong><br>${H.b1}</p>
<p><strong>FamilyGamma</strong><br>${H.g1}<br>${H.g2}<br>${H.g3}<br>${H.g4}</p>
<p><strong>FamilyDelta</strong><br>${H.d1}<br>${H.d2}</p>
<h3>C2 IP addresses</h3>
<p>203.0.113.10<br>203.0.113.11</p>`);
  assert.equal(reasonOf(zoned, /^FamilyAlpha$/), 'subgroup_label');
  assert.equal(reasonOf(zoned, /^FamilyBeta$/), 'subgroup_label');
  assert.notEqual(reasonOf(zoned, /^FamilyAlpha$/), 'heading_reset');
  assert.ok(!zoned.meta.scope_trace?.some((t) => t.reason === 'synthetic_heading_boundary' && /FamilyAlpha/.test(t.heading || '')));
  for (const h of Object.values(H)) {
    const row = find(candidates, 'md5', h);
    assert.ok(row, `md5 ${h} extracted`);
    assert.equal(isMember(row), true, `md5 ${h} is a report Indicator`);
    assert.equal(String(row.source_assertion).startsWith('explicit_'), true, `md5 ${h} publisher assertion`);
  }
  assert.equal(isMember(find(candidates, 'ip', '203.0.113.10')), true);
  assert.equal(isMember(find(candidates, 'ip', '203.0.113.11')), true);
  assert.deepEqual(
    memberKeys(candidates).sort(),
    [
      ...Object.values(H).map((h) => `md5:${h}`),
      'ip:203.0.113.10',
      'ip:203.0.113.11'
    ].sort()
  );
});
