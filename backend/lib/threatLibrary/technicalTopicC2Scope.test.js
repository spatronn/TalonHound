/**
 * A technical-analysis topic heading that names C2 ("Outlook calendar events
 * as a C2 channel") is not a publisher-curated C2 indicator section. Its
 * subtree holds prose, code listings (line-numbered highlighter tables), HTTP
 * request examples and a descriptive table — no indicator row and no IOC
 * table — so it must not open an authoritative scope (tl-zones-v5).
 *
 * Before the fix any `<table>` in the subtree confirmed the heading, the
 * section became `c2_section`, and the prose clause "validates access through
 * a GET request to <url>" (an operational-relation marker) was then read as a
 * publisher assertion: narrative_assertion → explicit_c2 → report Indicator.
 *
 * No vendor allowlist is involved: the same Microsoft Graph URL listed in the
 * IOC section is an Indicator.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { classifyCreateEligibility } from './promotion.js';
import { annotateDocumentZones } from './documentZones.js';

const SOURCE = 'https://research.example/blog/technical-topic-c2/';
const GRAPH = 'https://graph.microsoft.com/v1.0/organization';
const PATH_URL = 'https://example.test/path';

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>Technical topic fixture</title></head><body><article>
<h1>Synthetic module abuses calendar events for C2</h1>
<h2>Introduction</h2>
<p>Background paragraph describing the framework, its controller and the plugin architecture in several environments.</p>
${inner}
</article></body></html>`;
}

/** A syntax-highlighter code listing: line-number gutter cell + code cell. */
function codeListing(lines) {
  return `<table class="code-table"><tr><td class="code-nums">${lines.map((_, i) => `<div>${i + 1}</div>`).join('')}</td>`
    + `<td class="code-lines">${lines.map((l) => `<div>${l}</div>`).join('')}</td></tr></table>`;
}

const TECHNICAL = `
<h2>Technical details</h2>
<h3>Outlook calendar events as a C2 channel</h3>
<p>The DLL contains a complete default configuration, including the tenant ID, application credentials and the target mailbox.</p>
${codeListing(['{', '"TenantId": "****-****",', '"ClientId": "****-****",', '"UserEmail": "***@*****.example"', '}'])}
<p>Using the resulting configuration, the module creates a Microsoft Graph client and validates access by requesting the tenant’s organization record through a GET request to <code>${GRAPH}</code>.</p>
<p>Attempting this request causes the identity library to obtain an OAuth application token:</p>
${codeListing(['POST https://login.microsoftonline.com/&lt;TenantId&gt;/oauth2/v2.0/token', 'client_id=&lt;ClientId&gt;', 'scope=https://graph.microsoft.com/.default'])}
<table><thead><tr><th>Subject format</th><th>Purpose</th><th>Module behavior</th></tr></thead><tbody>
<tr><td>Event ID: &lt;agent-id&gt;</td><td>Operator-to-agent command</td><td>Downloads its attachments and deletes it</td></tr>
<tr><td>Boss update ID: &lt;agent-id&gt;</td><td>Agent heartbeat</td><td>Replaces the previous heartbeat event</td></tr>
</tbody></table>
<h3>Heartbeat handling</h3>
<p>The module maintains a heartbeat event and refreshes it every hour.</p>`;

const IOC_SECTION = `
<h2>Indicators of compromise</h2>
<h3>Domains and IPs</h3>
<p>evil-example[.]com</p>
<p>192.0.2[.]10</p>`;

function extract(inner) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }), document: r.document };
}

const find = (cands, type, value) => cands.filter((c) => c.candidate_type === type && c.normalized_value === value);
const persisted = (c) => ({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const isMember = (c) => Boolean(c) && isReportIndicatorMember(persisted(c));
const memberKeys = (cands) => cands.filter(isMember).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();

test('technical C2 topic: the Graph API endpoint is discovered but is not a publisher Indicator', () => {
  const { candidates, diagnostics } = extract(`${TECHNICAL}${IOC_SECTION}`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true, 'MODE A: the report curates an IOC section');

  const [graph] = find(candidates, 'url', GRAPH);
  assert.ok(graph, 'the technical observable stays visible as a candidate');
  assert.equal(graph.source_assertion, 'body_mention');
  assert.ok(!String(graph.source_assertion).startsWith('explicit_'));
  for (const o of graph.occurrences) {
    assert.equal(o.zone, 'report_body', 'a technical-analysis topic is not an authoritative C2 section');
    assert.notEqual(o.asserted, true);
  }
  assert.equal(isMember(graph), false);

  assert.deepEqual(memberKeys(candidates), ['domain:evil-example.com', 'ip:192.0.2.10']);
});

test('technical C2 topic: model maliciousness and analyst approval never make the endpoint actionable', () => {
  const { candidates, document } = extract(`${TECHNICAL}${IOC_SECTION}`);
  const after = mergeAiCandidateUpdates(
    candidates,
    { candidate_updates: [{ candidate_type: 'url', normalized_value: GRAPH, assessment: 'malicious', role: 'command_and_control', confidence: 0.9 }] },
    { document }
  );
  const [graph] = find(after, 'url', GRAPH);
  assert.equal(isMember(graph), false);
  const eligibility = classifyCreateEligibility({ ...persisted(graph), review_status: 'approved' });
  assert.equal(eligibility.eligible, false);
  assert.equal(eligibility.outcome, 'not_applicable');
  assert.deepEqual(memberKeys(after), ['domain:evil-example.com', 'ip:192.0.2.10']);
});

test('the same Graph URL listed in the IOC section is an Indicator (structural, not an allowlist)', () => {
  const { candidates } = extract(`
<h2>Indicators of compromise</h2>
<p>${GRAPH}</p>
<p>evil-example[.]com</p>`);
  const [graph] = find(candidates, 'url', GRAPH);
  assert.ok(graph);
  assert.equal(isMember(graph), true);
  assert.ok(String(graph.source_assertion).startsWith('explicit_'));
});

test('one canonical candidate for a URL in technical prose and in the IOC section; it is an Indicator', () => {
  const { candidates } = extract(`
<h2>Technical details</h2>
<h3>Command and control channel</h3>
<p>The module validates access through a GET request to ${PATH_URL} before polling.</p>
${codeListing(['GET /v1.0/organization', 'Authorization: Bearer &lt;token&gt;'])}
<h2>Indicators of compromise</h2>
<p>${PATH_URL}</p>
<p>evil-example[.]com</p>`);
  const rows = find(candidates, 'url', PATH_URL);
  assert.equal(rows.length, 1, 'occurrences merge into one identity');
  assert.ok(rows[0].occurrences.some((o) => o.zone === 'report_body' && o.asserted !== true));
  assert.ok(rows[0].occurrences.some((o) => o.asserted === true));
  assert.equal(isMember(rows[0]), true);
});

test('a URL only in technical prose is not an Indicator when the report curates an IOC section', () => {
  const { candidates } = extract(`
<h2>Technical details</h2>
<h3>Command and control channel</h3>
<p>The module validates access through a GET request to ${PATH_URL} before polling.</p>
${codeListing(['GET /v1.0/organization', 'Authorization: Bearer &lt;token&gt;'])}
<h2>Indicators of compromise</h2>
<p>evil-example[.]com</p>`);
  const [row] = find(candidates, 'url', PATH_URL);
  assert.ok(row, 'still extracted');
  assert.equal(isMember(row), false);
  assert.deepEqual(memberKeys(candidates), ['domain:evil-example.com']);
});

test('zones: a C2 topic over code listings / descriptive tables is narrative; over an IOC table or rows it is curated', () => {
  const zonesOf = (inner) => {
    const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
    const blocks = annotateDocumentZones(r.document, { sourceUrl: SOURCE }).blocks;
    return (re) => blocks.find((b) => re.test(String(b.text || '')))?.zone ?? null;
  };
  const technical = zonesOf(TECHNICAL);
  assert.equal(technical(/validates access/), 'report_body');
  assert.equal(technical(/^Outlook calendar events/), 'report_body');

  const table = zonesOf(`
<h2>C2 infrastructure</h2>
<p>The operators used the following servers.</p>
<table><thead><tr><th>Domain</th><th>IP</th><th>First seen</th></tr></thead><tbody>
<tr><td>relay-node-17[.]net</td><td>45.155.205[.]10</td><td>May 2</td></tr>
</tbody></table>
<h2>Conclusion</h2><p>Done.</p>`);
  assert.equal(table(/operators used the following/), 'c2_section');

  const rows = zonesOf(`
<h2>C2 infrastructure</h2>
<p>The implant beacons to the servers below.</p>
<ul><li>relay-node-17[.]net</li><li>relay-node-18[.]net</li></ul>
<h2>Conclusion</h2><p>Done.</p>`);
  assert.equal(rows(/beacons to the servers/), 'c2_section');
  assert.equal(rows(/^relay-node-17/), 'c2_section');
});
