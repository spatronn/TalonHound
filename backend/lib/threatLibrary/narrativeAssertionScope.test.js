/**
 * Narrative IOC assertions vs. explicit IOC sections vs. ordinary mentions.
 *
 * Pins five concepts that must never collapse into one boolean:
 *   A. syntactically detected observable      → a candidate row exists
 *   B. contextually malicious observable      → model / relation decision (ai_needed)
 *   C. explicitly asserted IOC                → explicit_report_assertion, no AI
 *   D. explicit IOC table member              → explicit_tables completeness set
 *   E. promotable                             → assessment malicious|suspicious after review
 *
 * A narrative sample hash ("the HTML attachment with the MD5 hash: …") is B:
 * it reaches the model even when the publisher also curated an IOC appendix,
 * and it never enters the explicit-table completeness set. Appendix rows are C.
 * Benign / target / example / identifier mentions never become C or D.
 *
 * Synthetic fixtures only — no real report text or real indicator values.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import { partitionCandidatesForAi } from './ai/analyze.js';
import { classifyCreateEligibility } from './promotion.js';

const URL = 'https://research.example/blog/synthetic-voicemail-campaign/';
const MD5 = crypto.createHash('md5').update('synthetic-narrative-attachment').digest('hex');
const MD5_ID = crypto.createHash('md5').update('synthetic-asset-identifier').digest('hex');

const FILLER = Array.from({ length: 5 }, (_, i) =>
  `<p>Part ${i + 1} of the synthetic analysis describes the lure, the delivery chain and the operator tradecraft observed across several environments.</p>`
).join('\n');

/** Dedicated appendix: a heading + one indicator per line (defanged). */
const APPENDIX = `
<h2>Indicators of compromise (IOCs)</h2>
<p># attacker-registered domains</p>
<p>relay-voxmail[.]com</p>
<p>inbox-notice-hub[.]net</p>
<p>vm-archive-portal[.]org</p>`;

function extract(body, { appendix = true } = {}) {
  const html = `<!doctype html><html lang="en"><head><title>Synthetic campaign</title></head><body><article>
<h1>Synthetic voicemail campaign</h1>
${FILLER}
${body}
${appendix ? APPENDIX : ''}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: URL, finalUrl: URL, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: URL }), document: r.document };
}

const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const isExplicit = (c) =>
  Boolean(c) && c.assessment === 'malicious' && c.policy_decision === 'explicit_report_assertion' && c.ai_needed === false;
/** B: an IOC candidate the model still has to judge — neither asserted nor discarded. */
const isForModel = (c) =>
  Boolean(c) && c.is_ioc !== false && c.ai_needed === true && c.assessment !== 'context_only' &&
  c.policy_decision !== 'explicit_report_assertion';
/** Never a deterministic malicious IOC (context, excluded, or left to the model). */
const notAutoMalicious = (c) => !c || (c.assessment !== 'malicious' && c.policy_decision !== 'explicit_report_assertion');
const notAsserted = (c) => !c || (c.occurrences || []).every((o) => o.asserted !== true);

// ---------------------------------------------------------------------------
// Should survive
// ---------------------------------------------------------------------------

test('1. narrative malicious-attachment MD5 reaches the model even with a curated IOC appendix', () => {
  const body = `<h3>HTML attachment analysis</h3>
<p>For the purpose of analysis, we will consider the HTML attachment with the MD5 hash: ${MD5}</p>
<p>The attachment contains encoded JavaScript that redirects the victim to an attacker-controlled URL.</p>`;
  const { candidates, diagnostics } = extract(body);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true);
  const h = find(candidates, 'md5', MD5);
  assert.ok(isForModel(h), `md5 must be an AI-classified candidate, got ${h?.assessment}/${h?.policy_decision}`);
  assert.equal(h.policy_decision, 'ai_needed_prose_sample_hash');
  assert.equal(h.source_assertion, 'body_mention', 'narrative mention is not an explicit assertion');
  assert.ok(notAsserted(h));
  assert.equal(h.occurrences[0].section_heading, 'HTML attachment analysis');
  assert.match(h.evidence_text, /HTML attachment with the MD5 hash/);
  // Not part of the explicit-table completeness set (concept D).
  assert.equal(diagnostics.explicit_tables.explicit_identities, 0);
  assert.equal(diagnostics.explicit_tables.inconsistent, false);
  assert.deepEqual(partitionCandidatesForAi(candidates).toClassify.map((c) => c.normalized_value), [MD5]);
});

test('1b. the model decides the narrative hash: malicious → promotable, context_only → excluded', () => {
  const body = `<p>For the purpose of analysis, we will consider the HTML attachment with the MD5 hash: ${MD5}</p>`;
  const run = (update) => {
    const { candidates, document } = extract(body);
    const out = mergeAiCandidateUpdates(
      candidates,
      { candidate_updates: update ? [{ candidate_type: 'md5', normalized_value: MD5, ...update }] : [] },
      { document }
    );
    return find(out, 'md5', MD5);
  };

  const mal = run({ assessment: 'malicious', role: 'malware_sample', confidence: 0.85 });
  assert.equal(mal.assessment, 'malicious');
  assert.equal(mal.role, 'malware_sample');
  assert.equal(mal.decision_source, 'ai');
  assert.equal(mal.ai_needed, false);
  assert.equal(mal.document_has_authoritative_scope, true);
  assert.equal(mal.source_assertion, 'body_mention');
  assert.equal(
    classifyCreateEligibility({ ...mal, review_status: 'approved' }).eligible,
    false,
    'malicious narrative hash is not a publisher-declared report IOC'
  );
  assert.equal(classifyCreateEligibility(mal).eligible, false, 'promotion still requires analyst approval');

  const ctx = run({ assessment: 'context_only', role: 'reference', confidence: 0.6 });
  assert.equal(ctx.assessment, 'context_only', 'no completeness rule forces a narrative hash to survive');
  assert.equal(classifyCreateEligibility({ ...ctx, review_status: 'approved' }).eligible, false);

  const none = run(null);
  assert.equal(none.assessment, 'unknown');
  assert.equal(none.ai_needed, true, 'no model answer leaves it pending review, never auto-malicious');
});

test('2. narrative C2 domain ("communicates with") reaches the model, not the appendix-scope context rule', () => {
  const { candidates } = extract('<p>After execution the malware communicates with c2-relay-node[.]com over HTTPS.</p>');
  const d = find(candidates, 'domain', 'c2-relay-node.com');
  assert.ok(isForModel(d), `got ${d?.assessment}/${d?.policy_decision}`);
  assert.equal(d.source_relation, 'operational_malicious');
  assert.ok(notAsserted(d), 'an operational body clause is not an explicit assertion');
});

test('3. narrative attacker IP ("connected to … controlled by the threat actor") reaches the model', () => {
  const { candidates } = extract('<p>The payload connected to 45.61.10.30 controlled by the threat actor.</p>');
  const ip = find(candidates, 'ip', '45.61.10.30');
  assert.ok(isForModel(ip), `got ${ip?.assessment}/${ip?.policy_decision}`);
  assert.ok(notAsserted(ip));
});

test('4. IOC appendix lines are explicit assertions', () => {
  const { candidates } = extract('<p>The campaign used several lookalike domains.</p>');
  for (const d of ['relay-voxmail.com', 'inbox-notice-hub.net', 'vm-archive-portal.org']) {
    const c = find(candidates, 'domain', d);
    assert.ok(isExplicit(c), `${d}: ${c?.assessment}/${c?.policy_decision}`);
    assert.equal(c.source_assertion, 'explicit_ioc');
    assert.ok(c.occurrences.some((o) => o.asserted === true && o.zone === 'explicit_ioc_section'));
  }
});

test('5. value in narrative and appendix is one canonical explicit candidate with both occurrences', () => {
  const { candidates } = extract('<p>The redirector at relay-voxmail[.]com forwards victims to the credential phishing page.</p>');
  const all = candidates.filter((c) => c.candidate_type === 'domain' && c.normalized_value === 'relay-voxmail.com');
  assert.equal(all.length, 1);
  const c = all[0];
  assert.ok(isExplicit(c));
  const zones = new Set(c.occurrences.map((o) => o.zone));
  assert.ok(zones.has('report_body') && zones.has('explicit_ioc_section'), `zones=${[...zones]}`);
  assert.equal(c.occurrences.filter((o) => o.asserted === true).length, 1, 'only the appendix line is the assertion');
});

// ---------------------------------------------------------------------------
// Should NOT automatically survive
// ---------------------------------------------------------------------------

test('6. benign fallback redirect destination is context only', () => {
  const { candidates } = extract(
    '<p>If the URL does not contain the encoded email address, it instead redirects the user to office.com.</p>'
  );
  const c = find(candidates, 'domain', 'office.com');
  assert.ok(c, 'still detected (concept A)');
  assert.equal(c.assessment, 'context_only');
  assert.ok(notAutoMalicious(c));
  assert.ok(notAsserted(c));
});

test('6b. without an appendix a benign redirect is never deterministic malicious', () => {
  const { candidates } = extract(
    '<p>If the URL does not contain the encoded email address, it instead redirects the user to office.com.</p>',
    { appendix: false }
  );
  assert.ok(notAutoMalicious(find(candidates, 'domain', 'office.com')));
});

test('7. vendor service reference (reCAPTCHA) is not a malicious IOC', () => {
  const { candidates } = extract(
    '<p>For the CAPTCHA the page uses the Google reCAPTCHA service loaded from www.google.com/recaptcha/api.js to evade automated URL analysis.</p>'
  );
  for (const c of candidates.filter((x) => /google\.com/.test(String(x.normalized_value)))) {
    assert.ok(notAutoMalicious(c), `${c.candidate_type}:${c.normalized_value} ${c.assessment}/${c.policy_decision}`);
    assert.ok(notAsserted(c));
  }
});

test('8. targeted organization infrastructure is not an attacker IOC', () => {
  const { candidates } = extract(
    '<p>Employees of northwind-traders.com were targeted by the campaign; the From field matched the organization name.</p>'
  );
  const c = find(candidates, 'domain', 'northwind-traders.com');
  assert.ok(notAutoMalicious(c), `${c?.assessment}/${c?.policy_decision}`);
  assert.ok(notAsserted(c));
});

test('9. documentation / example URL is context only', () => {
  const { candidates } = extract('<p>For example, requests follow https://example.com/path/to/resource in the documentation.</p>');
  const c = find(candidates, 'url', 'https://example.com/path/to/resource');
  assert.ok(notAutoMalicious(c));
  if (c) assert.equal(c.assessment, 'context_only');
});

test('10. 32-hex identifier inside a URL path is never an asserted or deterministic malicious hash', () => {
  const { candidates } = extract(
    `<p>Figure 4 is served from https://cdn.static-images.net/assets/${MD5_ID}/figure4.png on the blog CDN.</p>`
  );
  const h = find(candidates, 'md5', MD5_ID);
  assert.ok(notAutoMalicious(h), `${h?.assessment}/${h?.policy_decision}`);
  assert.ok(notAsserted(h));
  assert.notEqual(h?.source_assertion, 'explicit_ioc');
});

test('10b. hash-shaped identifier in prose is never deterministic malicious', () => {
  const { candidates } = extract(`<p>Each tracking request carries the session identifier ${MD5_ID} in a cookie.</p>`);
  const h = find(candidates, 'md5', MD5_ID);
  assert.ok(notAutoMalicious(h));
  assert.ok(notAsserted(h));
});

test('11. IPv4-looking prefix inside a hostname never becomes a standalone IP', () => {
  const { candidates } = extract('<p>The redirector used 45.61.10.40.dyn-relay[.]net for the second stage.</p>');
  assert.equal(find(candidates, 'ip', '45.61.10.40'), null);
  assert.ok(find(candidates, 'domain', '45.61.10.40.dyn-relay.net'));
});

test('12. explicit table value dropped by validation stays visible; narrative values never join the asserted set', () => {
  const body = `<p>For the purpose of analysis, we consider the attachment with the MD5 hash: ${MD5}</p>
<p>If the parameter is missing, the victim is redirected to office.com.</p>
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Indicator</th><th>Indicator</th></tr></thead><tbody>
<tr><td>Domain</td><td>op-console[.]shop</td><td></td></tr>
<tr><td>Domain</td><td>45.61.10.50.host-relay.net</td><td>45.61.10.50</td></tr>
</tbody></table>`;
  const { candidates, diagnostics } = extract(body, { appendix: false });
  const t = diagnostics.explicit_tables;
  assert.equal(t.inconsistent, true);
  assert.ok(t.missing_identities.includes('ip:45.61.10.50'));
  assert.ok(t.dropped_asserted_identities.some((d) => d.value === '45.61.10.50' && d.reason === 'embedded_in_dns_hostname'));
  assert.equal(find(candidates, 'ip', '45.61.10.50'), null);
  // asserted − created is scoped to table assertions: narrative values are absent from it.
  for (const k of t.missing_identities) {
    assert.ok(!k.includes(MD5) && !k.includes('office.com'), `narrative value leaked into completeness: ${k}`);
  }
  assert.ok(isExplicit(find(candidates, 'domain', 'op-console.shop')));
  assert.ok(isForModel(find(candidates, 'md5', MD5)));
});
