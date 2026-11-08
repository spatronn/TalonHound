/**
 * Promotion gate: publisher evidence the vocabulary missed (review-queue 35773 audit).
 *
 * Synthetic shapes of two refusals, no report id or value condition:
 *
 * P-1 A hunting query captioned as infrastructure ("Outbound connections to
 *     observed campaign infrastructure") over an inline `has_any (…)` list is
 *     a publisher role label, like a `let c2ip = dynamic([…])` list name.
 * P-2 "The threat actor deployed the same artifact set to the domain
 *     evil.example" is operational use of that exact host.
 *
 * Both stay analyst actions: never Indicator members, and promotion still
 * needs an audited corroboration. Uncaptioned queries, captions that call the
 * values legitimate, and "deployed … to the domain controller" stay refused.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { classifyPromoteEligibility } from './promotion.js';

const SOURCE = 'https://vendor-research.example/blog/captioned-hunting/';
const CORROBORATION = 'Publisher lists this host as observed campaign infrastructure of the same callback set.';

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Hunting</title></head><body><article>
<h1>Fake-download campaign</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
<h2>Indicators of compromise</h2>
<table><thead><tr><th>Indicator</th><th>Type</th><th>Component</th></tr></thead><tbody>
<tr><td>listed-callback[.]xyz</td><td>Domain</td><td>Offer-execution callback infrastructure.</td></tr>
</tbody></table>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const find = (x, v) => x.candidates.find((c) => String(c.normalized_value).toLowerCase() === v);

function hunting(caption, values) {
  return `<h2>Advanced hunting</h2>
<p>Customers can run the following advanced hunting queries to find related activity in their networks.</p>
<h3>${caption}</h3>
<pre><code>DeviceNetworkEvents
| where RemoteUrl has_any (${values.map((v) => `"${v}"`).join(', ')})
| project Timestamp, DeviceName, RemoteUrl</code></pre>`;
}

test('P-1. a hunting query captioned as campaign infrastructure is a role label for its inline values', () => {
  const x = run(hunting('Outbound connections to observed campaign infrastructure', ['rotated-callback-one.cfd', 'rotated-callback-two.xyz']));
  for (const v of ['rotated-callback-one.cfd', 'rotated-callback-two.xyz']) {
    const c = find(x, v);
    assert.ok(c, `${v} is a candidate`);
    const row = persisted(c);
    assert.equal(isReportIndicatorMember(row), false, 'never a member on its own');
    const pending = classifyPromoteEligibility(row);
    assert.equal(pending.promotable, true, JSON.stringify(pending));
    assert.equal(pending.requires_corroboration, true);
    assert.equal(pending.ok, false);
    const ok = classifyPromoteEligibility(row, { corroboration: CORROBORATION });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.basis, 'operational_evidence');
  }
});

test('P-1 negative. an uncaptioned or benign-captioned query stays refused', () => {
  const plain = run(`<h2>Advanced hunting</h2>
<pre><code>DeviceNetworkEvents
| where RemoteUrl has_any ("plain-query-host.cfd")</code></pre>`);
  const a = classifyPromoteEligibility(persisted(find(plain, 'plain-query-host.cfd')), { corroboration: CORROBORATION });
  assert.equal(a.ok, false);
  assert.equal(a.code, 'promote_insufficient_evidence');

  const benign = run(hunting('Exclude legitimate update infrastructure from results', ['update-mirror-host.net']));
  const b = classifyPromoteEligibility(persisted(find(benign, 'update-mirror-host.net')), { corroboration: CORROBORATION });
  assert.equal(b.ok, false);
  assert.equal(b.promotable, false);

  const generic = run(hunting('Network connections from Inno temporary directories', ['generic-caption-host.cfd']));
  const g = classifyPromoteEligibility(persisted(find(generic, 'generic-caption-host.cfd')), { corroboration: CORROBORATION });
  assert.equal(g.ok, false);
  assert.equal(g.code, 'promote_insufficient_evidence');
});

test('P-2. the actor deploying its artifact set to a named domain is operational use of that host', () => {
  const x = run(`<h2>Campaign tracking</h2>
<p>One notable exception was identified in which the threat actor deployed the same artifact set to the domain operator-shop.example-store.com, which resolved to a dedicated server. Unlike the compromised websites, this infrastructure appeared to be directly controlled by the operator.</p>`);
  const c = find(x, 'operator-shop.example-store.com');
  assert.ok(c);
  const row = persisted(c);
  assert.equal(isReportIndicatorMember(row), false);
  const pending = classifyPromoteEligibility(row);
  assert.equal(pending.promotable, true, JSON.stringify(pending));
  assert.equal(pending.requires_corroboration, true);
  assert.equal(classifyPromoteEligibility(row, { corroboration: CORROBORATION }).ok, true);
});

test('P-2 negative. deploying to the domain controller does not make a victim host operator infrastructure', () => {
  const x = run(`<h2>Lateral movement</h2>
<p>The threat actor deployed the ransomware binary to the domain controller fileserver-01.victim-corp.com before encryption started.</p>`);
  const c = find(x, 'fileserver-01.victim-corp.com');
  assert.ok(c);
  const d = classifyPromoteEligibility(persisted(c), { corroboration: CORROBORATION });
  assert.equal(d.ok, false);
  assert.equal(d.code, 'promote_insufficient_evidence');
});
