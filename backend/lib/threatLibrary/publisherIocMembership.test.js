/**
 * Report IOC membership: publisher-curated IOC sections are authoritative
 * for the Indicators list. Narrative extraction / AI classification stay
 * intact. Synthetic fixtures only in the required corpus; the optional live
 * acceptance test reads a public article when the network is available.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import { partitionCandidatesForAi } from './ai/analyze.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import {
  classifyCreateEligibility,
  isActionableReviewIndicator,
  isPublisherAuthoritativeReportIocMember
} from './promotion.js';

const SOURCE = 'https://research.example/blog/publisher-membership/';
const MD5 = crypto.createHash('md5').update('membership-narrative-attachment').digest('hex');
const MD5_EXPLICIT = crypto.createHash('md5').update('membership-explicit-hash').digest('hex');
const SHA256 = crypto.createHash('sha256').update('membership-explicit-sample').digest('hex');

const FILLER = Array.from({ length: 4 }, (_, i) =>
  `<p>Background paragraph ${i + 1} describes lure construction, delivery and operator tradecraft observed in several environments.</p>`
).join('\n');

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>Membership fixture</title></head><body><article>
<h1>Synthetic membership campaign</h1>
${FILLER}
${inner}
</article></body></html>`;
}

function extract(inner, sourceUrl = SOURCE) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: sourceUrl, finalUrl: sourceUrl, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl }), document: r.document };
}

const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const reviewRow = (c) => (c ? { ...c, evidence: buildCandidateEvidenceRecord(c) } : null);
const isMember = (c) => Boolean(c) && isActionableReviewIndicator(reviewRow(c));
const membersOf = (cands) => cands.filter((c) => isMember(c));
const memberKeys = (cands) => membersOf(cands).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();

function applyAi(candidates, document, updates) {
  return mergeAiCandidateUpdates(
    candidates,
    { candidate_updates: updates },
    { document }
  );
}

const APPENDIX_DOMAINS = `
<h2>Indicators of compromise (IOCs)</h2>
<p># attacker-registered domains</p>
<p>relay-voxmail[.]com</p>
<p>inbox-notice-hub[.]net</p>`;

// ---------------------------------------------------------------------------
// P1 — explicit IOC section + narrative-only malicious hash
// ---------------------------------------------------------------------------

test('P1: narrative malicious hash stays extracted and is not a report Indicator', () => {
  const { candidates, diagnostics, document } = extract(`
<h3>HTML attachment analysis</h3>
<p>The malicious attachment has MD5 ${MD5}.</p>
${APPENDIX_DOMAINS}`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true);
  const hash = find(candidates, 'md5', MD5);
  assert.ok(hash, 'hash must remain extracted');
  assert.equal(hash.source_assertion, 'body_mention');
  assert.ok(partitionCandidatesForAi(candidates).toClassify.some((c) => c.normalized_value === MD5));

  const after = applyAi(candidates, document, [
    { candidate_type: 'md5', normalized_value: MD5, assessment: 'malicious', role: 'malware_sample', confidence: 0.9 }
  ]);
  const mal = find(after, 'md5', MD5);
  assert.equal(mal.assessment, 'malicious');
  assert.equal(isMember(mal), false);
  assert.equal(classifyCreateEligibility({ ...mal, review_status: 'approved' }).eligible, false);
  assert.ok(isMember(find(after, 'domain', 'relay-voxmail.com')));
  assert.ok(isMember(find(after, 'domain', 'inbox-notice-hub.net')));
  assert.equal(memberKeys(after).includes(`md5:${MD5}`), false);
});

// ---------------------------------------------------------------------------
// P2 / P3 / P4 — narrative C2 / IP / URL not listed in the appendix
// ---------------------------------------------------------------------------

test('P2: narrative C2 domain not listed is not a report Indicator', () => {
  const { candidates, document } = extract(`
<p>After execution the malware communicates with c2-relay-node.com as its C2.</p>
${APPENDIX_DOMAINS}`);
  const after = applyAi(candidates, document, [
    { candidate_type: 'domain', normalized_value: 'c2-relay-node.com', assessment: 'malicious', role: 'command_and_control', confidence: 0.88 }
  ]);
  const narrative = find(after, 'domain', 'c2-relay-node.com');
  assert.ok(narrative, 'narrative C2 remains extracted');
  assert.equal(narrative.assessment, 'malicious');
  assert.equal(isMember(narrative), false);
  assert.ok(isMember(find(after, 'domain', 'relay-voxmail.com')));
});

test('P3: narrative IP not listed is not a report Indicator', () => {
  const { candidates, document } = extract(`
<p>The payload connected to 45.61.10.30 controlled by the threat actor.</p>
${APPENDIX_DOMAINS}`);
  const after = applyAi(candidates, document, [
    { candidate_type: 'ip', normalized_value: '45.61.10.30', assessment: 'malicious', role: 'command_and_control', confidence: 0.87 }
  ]);
  const ip = find(after, 'ip', '45.61.10.30');
  assert.ok(ip);
  assert.equal(ip.assessment, 'malicious');
  assert.equal(isMember(ip), false);
});

test('P4: narrative URL not listed is not a report Indicator', () => {
  const { candidates, document } = extract(`
<p>After the victim opens the message the malware sends a GET request to https://payload-drop.hub.net/stage.js to retrieve the next stage.</p>
${APPENDIX_DOMAINS}`);
  const after = applyAi(candidates, document, [
    { candidate_type: 'url', normalized_value: 'https://payload-drop.hub.net/stage.js', assessment: 'malicious', role: 'payload_hosting', confidence: 0.86 }
  ]);
  const url = find(after, 'url', 'https://payload-drop.hub.net/stage.js');
  assert.ok(url, 'narrative URL remains extracted');
  assert.equal(isMember(url), false);
  assert.ok(isMember(find(after, 'domain', 'relay-voxmail.com')));
});

// ---------------------------------------------------------------------------
// P5 / P6 / P7 — same identity in narrative + explicit, order-invariant
// ---------------------------------------------------------------------------

function duplicateHashDoc(appendixFirst) {
  const narrative = `<h3>HTML attachment analysis</h3>
<p>The malicious attachment has MD5 ${MD5_EXPLICIT}.</p>`;
  const appendix = `
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Indicator</th></tr></thead><tbody>
<tr><td>MD5</td><td>${MD5_EXPLICIT}</td></tr>
<tr><td>Domain</td><td>relay-voxmail[.]com</td></tr>
</tbody></table>`;
  return appendixFirst ? `${appendix}${narrative}` : `${narrative}${appendix}`;
}

function assertDuplicateMembership(inner, label) {
  const { candidates } = extract(inner);
  const all = candidates.filter((c) => c.candidate_type === 'md5' && c.normalized_value === MD5_EXPLICIT);
  assert.equal(all.length, 1, `${label}: one canonical identity`);
  const c = all[0];
  assert.equal(c.source_assertion, 'explicit_ioc');
  const zones = new Set((c.occurrences || []).map((o) => o.zone));
  assert.ok(zones.has('report_body') && zones.has('explicit_ioc_section'), `${label}: zones=${[...zones]}`);
  assert.equal(isMember(c), true, `${label}: explicit assertion grants membership`);
}

test('P5: hash in narrative and explicit IOC table is one report member', () => {
  assertDuplicateMembership(duplicateHashDoc(false), 'P5');
});

test('P6: narrative first, explicit later — same membership as P5', () => {
  assertDuplicateMembership(duplicateHashDoc(false), 'P6');
});

test('P7: explicit first, narrative later — same membership as P5', () => {
  assertDuplicateMembership(duplicateHashDoc(true), 'P7');
});

// ---------------------------------------------------------------------------
// P8 / P9 — no IOC section: existing narrative / AI workflow
// ---------------------------------------------------------------------------

test('P8: no IOC section — malicious narrative hash may become a report Indicator', () => {
  const { candidates, diagnostics, document } = extract(`
<p>The malicious attachment has MD5 ${MD5}.</p>`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, false);
  const hash = find(candidates, 'md5', MD5);
  assert.ok(hash);
  assert.equal(hash.source_assertion, 'body_mention');
  const after = applyAi(candidates, document, [
    { candidate_type: 'md5', normalized_value: MD5, assessment: 'malicious', role: 'malware_sample', confidence: 0.9 }
  ]);
  const mal = find(after, 'md5', MD5);
  assert.equal(mal.assessment, 'malicious');
  assert.equal(isMember(mal), true);
  assert.equal(classifyCreateEligibility({ ...mal, review_status: 'approved' }).eligible, true);
});

test('P9: no IOC section — narrative C2 domain/IP remain report Indicators after AI', () => {
  const { candidates, diagnostics, document } = extract(`
<p>The malware communicates with c2-relay-node.com as its C2 and connected to 45.61.10.30.</p>`);
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, false);
  const after = applyAi(candidates, document, [
    { candidate_type: 'domain', normalized_value: 'c2-relay-node.com', assessment: 'malicious', role: 'command_and_control', confidence: 0.9 },
    { candidate_type: 'ip', normalized_value: '45.61.10.30', assessment: 'malicious', role: 'command_and_control', confidence: 0.88 }
  ]);
  assert.equal(isMember(find(after, 'domain', 'c2-relay-node.com')), true);
  assert.equal(isMember(find(after, 'ip', '45.61.10.30')), true);
});

// ---------------------------------------------------------------------------
// P10 — empty / unconfirmed IOC heading must not flip MODE A
// ---------------------------------------------------------------------------

test('P10: unconfirmed IOC heading with no publisher assertions does not become authoritative', () => {
  const { candidates, diagnostics, document } = extract(`
<h2>Indicators: what the campaign tells us about tradecraft</h2>
<p>Defenders should collect the IOCs observed during the investigation and share them internally.</p>
<p>The malware communicates with c2-relay-node.com as its C2.</p>
<h2>Conclusion</h2>
<p>Watch for this pattern.</p>`);
  assert.equal(
    diagnostics.document_scope.has_authoritative_indicator_scope,
    false,
    'existing unconfirmed-heading semantics must not switch the report into MODE A'
  );
  const after = applyAi(candidates, document, [
    { candidate_type: 'domain', normalized_value: 'c2-relay-node.com', assessment: 'malicious', role: 'command_and_control', confidence: 0.9 }
  ]);
  assert.equal(isMember(find(after, 'domain', 'c2-relay-node.com')), true);
});

// ---------------------------------------------------------------------------
// P11 — mixed-type explicit table
// ---------------------------------------------------------------------------

test('P11: explicit mixed-type table members become report Indicators', () => {
  const { candidates } = extract(`
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Indicator</th></tr></thead><tbody>
<tr><td>Domain</td><td>relay-voxmail[.]com</td></tr>
<tr><td>IPv4</td><td>45.61.10.40</td></tr>
<tr><td>URL</td><td>https://payload-drop.hub.net/gate.php</td></tr>
<tr><td>MD5</td><td>${MD5_EXPLICIT}</td></tr>
<tr><td>SHA256</td><td>${SHA256}</td></tr>
</tbody></table>`);
  const expected = [
    'domain:relay-voxmail.com',
    'ip:45.61.10.40',
    'url:https://payload-drop.hub.net/gate.php',
    `md5:${MD5_EXPLICIT}`,
    `sha256:${SHA256}`
  ].sort();
  for (const key of expected) {
    const [type, value] = key.split(/:(.+)/);
    const c = find(candidates, type, value);
    assert.ok(c, `missing ${key}`);
    assert.equal(c.source_assertion, 'explicit_ioc', key);
    assert.equal(isMember(c), true, key);
  }
});

// ---------------------------------------------------------------------------
// P12 — asserted − created remains visible
// ---------------------------------------------------------------------------

test('P12: rejected explicit table value still appears in asserted − created', () => {
  const { candidates, diagnostics } = extract(`
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Indicator</th><th>Indicator</th></tr></thead><tbody>
<tr><td>Domain</td><td>op-console[.]shop</td><td></td></tr>
<tr><td>Domain</td><td>45.61.10.50.host-relay.net</td><td>45.61.10.50</td></tr>
</tbody></table>`);
  const t = diagnostics.explicit_tables;
  assert.equal(t.inconsistent, true);
  assert.ok(t.missing_identities.includes('ip:45.61.10.50'));
  assert.ok(t.dropped_asserted_identities.some((d) => d.value === '45.61.10.50'));
  assert.equal(find(candidates, 'ip', '45.61.10.50'), null);
  assert.equal(isMember(find(candidates, 'domain', 'op-console.shop')), true);
});

// ---------------------------------------------------------------------------
// P13 — benign narrative + explicit set
// ---------------------------------------------------------------------------

test('P13: benign narrative observable is not a report Indicator', () => {
  const { candidates } = extract(`
<p>If the URL does not contain the encoded email address, it instead redirects the user to office.com.</p>
${APPENDIX_DOMAINS}`);
  const benign = find(candidates, 'domain', 'office.com');
  assert.ok(benign, 'still extracted');
  assert.equal(benign.assessment, 'context_only');
  assert.equal(isMember(benign), false);
  assert.ok(isMember(find(candidates, 'domain', 'relay-voxmail.com')));
});

// ---------------------------------------------------------------------------
// P14 / P15 — global IOC state is not report membership
// ---------------------------------------------------------------------------

test('P14: globally existing IOC that is narrative-only here is not a report member', () => {
  const row = {
    candidate_type: 'domain',
    normalized_value: 'already-known.hub.net',
    assessment: 'malicious',
    match_state: 'existing',
    review_status: 'pending',
    is_ioc: true,
    matched_ioc_id: 4401,
    source_assertion: 'body_mention',
    evidence: {
      source_assertion: 'body_mention',
      document_has_authoritative_scope: true
    }
  };
  assert.equal(isPublisherAuthoritativeReportIocMember(row), false);
  assert.equal(isActionableReviewIndicator(row), false);
  assert.equal(classifyCreateEligibility({ ...row, review_status: 'approved' }).eligible, false);
});

test('P15: same identity explicitly asserted in two reports keeps independent membership', () => {
  const shared = 'shared-c2.hub.net';
  const reportA = {
    candidate_type: 'domain',
    normalized_value: shared,
    assessment: 'malicious',
    match_state: 'new',
    is_ioc: true,
    source_assertion: 'explicit_ioc',
    evidence: { source_assertion: 'explicit_ioc', document_has_authoritative_scope: true }
  };
  const reportB = {
    ...reportA,
    evidence: { source_assertion: 'explicit_ioc', document_has_authoritative_scope: true }
  };
  assert.equal(isActionableReviewIndicator(reportA), true);
  assert.equal(isActionableReviewIndicator(reportB), true);
  const narrativeOnlyB = {
    ...reportB,
    source_assertion: 'body_mention',
    evidence: { source_assertion: 'body_mention', document_has_authoritative_scope: true }
  };
  assert.equal(isActionableReviewIndicator(narrativeOnlyB), false, 'report B membership is independent of report A');
});

// ---------------------------------------------------------------------------
// Optional live acceptance — public article, no production-logic special case
// ---------------------------------------------------------------------------

test('live article: publisher IOC section is the report Indicator set', async (t) => {
  const url = 'https://www.zscaler.com/blogs/security-research/resurgence-voicemail-themed-phishing-attacks-targeting-key-industry';
  const narrativeMd5 = 'dd0ddbc951de5cad9c8ace516c514693';
  let html;
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 20000);
    const res = await fetch(url, { signal: ac.signal, headers: { 'user-agent': 'TalonHound-test' } });
    clearTimeout(timer);
    if (!res.ok) {
      t.skip(`live fetch HTTP ${res.status}`);
      return;
    }
    html = await res.text();
  } catch (err) {
    t.skip(`live fetch unavailable: ${err?.cause?.code || err.message}`);
    return;
  }
  const parsed = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(parsed.ok, true, parsed.code);
  const { candidates, diagnostics } = extractCandidatesWithDiagnostics(parsed.document, { sourceUrl: url });
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, true);
  const hash = find(candidates, 'md5', narrativeMd5);
  assert.ok(hash, 'narrative MD5 must remain extracted as intelligence');
  assert.equal(hash.source_assertion, 'body_mention');
  const after = applyAi(candidates, parsed.document, [
    { candidate_type: 'md5', normalized_value: narrativeMd5, assessment: 'malicious', role: 'malware_sample', confidence: 0.9 }
  ]);
  const mal = find(after, 'md5', narrativeMd5);
  assert.equal(mal.assessment, 'malicious');
  assert.equal(isMember(mal), false, 'narrative MD5 is not a report Indicator');
  const explicitDomains = after.filter((c) => c.candidate_type === 'domain' && c.source_assertion === 'explicit_ioc');
  assert.equal(explicitDomains.length, 10);
  assert.deepEqual(memberKeys(after), explicitDomains.map((c) => `domain:${c.normalized_value}`).sort());
});
