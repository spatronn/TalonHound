/**
 * Publisher IOC appendix parent scope (tl-zones-v10):
 *
 * Child C2 / sample subsections may open and close independently, but the
 * parent "Indicators of compromise" appendix must survive sibling headings
 * (Loaders / Plugins / Samples) so publisher hash rows stay Indicators.
 * MODE A stays strict: narrative hashes outside the appendix remain non-members.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import {
  extractCandidatesWithDiagnostics,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember, isContextOnlyCandidate } from './indicatorMembership.js';
import {
  annotateDocumentZones,
  THREAT_LIBRARY_DOCUMENT_ZONES_VERSION
} from './documentZones.js';
import { SOURCE_ASSERTIONS } from './evidencePolicy.js';

const SOURCE = 'https://research.example/blog/appendix-parent-scope/';

test('appendix parent scope contracts', () => {
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v13');
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v30');
});

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>Appendix parent scope</title></head><body><article>
<p>Background paragraph describing the campaign architecture across several environments and timelines.</p>
${inner}
</article></body></html>`;
}

function extract(inner) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  const zoned = annotateDocumentZones(r.document, { sourceUrl: SOURCE });
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }), document: r.document, zoned };
}

const find = (cands, type, value) =>
  cands.find((c) => c.candidate_type === type && String(c.normalized_value).toLowerCase() === String(value).toLowerCase());
const persisted = (c) => ({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const isMember = (c) => Boolean(c) && isReportIndicatorMember(persisted(c));
const zoneOf = (zoned, re) => zoned.blocks.find((b) => re.test(String(b.text || '')))?.zone ?? null;
const reasonOf = (zoned, re) => zoned.blocks.find((b) => re.test(String(b.text || '')))?.zone_reason ?? null;

const H1 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const H2 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const H3 = 'cccccccccccccccccccccccccccccccc';
const H4 = 'dddddddddddddddddddddddddddddddd';
const LEGIT = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

test('A — parent IOC section survives sibling C2 / Loader / Plugins headings', () => {
  const { candidates, zoned } = extract(`
<h2>Indicators of compromise</h2>
<h3>C2</h3>
<p>evil.example</p>
<p>203.0.113.10</p>
<h3>Loader</h3>
<p>${H1}</p>
<h3>Plugins</h3>
<p>${H2}</p>`);
  assert.ok(
    ['appendix_scope_retained', 'nested_indicator_subheading', 'subgroup_label', 'heading_hint'].includes(
      reasonOf(zoned, /^Loader$/)
    ),
    `Loader reason=${reasonOf(zoned, /^Loader$/)}`
  );
  assert.notEqual(zoneOf(zoned, new RegExp(`^${H1}$`)), 'report_body');
  assert.equal(isMember(find(candidates, 'domain', 'evil.example')), true);
  assert.equal(isMember(find(candidates, 'ip', '203.0.113.10')), true);
  assert.equal(isMember(find(candidates, 'md5', H1)), true);
  assert.equal(isMember(find(candidates, 'md5', H2)), true);
});

test('B — child C2 state does not leak onto loader hashes', () => {
  const { candidates } = extract(`
<h2>Indicators of compromise</h2>
<h3>C2</h3>
<p>evil.example</p>
<h3>Loader</h3>
<p>${H1}</p>`);
  const domain = find(candidates, 'domain', 'evil.example');
  const hash = find(candidates, 'md5', H1);
  assert.equal(domain.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  assert.equal(isMember(domain), true);
  assert.notEqual(hash.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  assert.equal(hash.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC);
  assert.equal(isMember(hash), true);
});

test('C — parent IOC section terminates at a peer topic heading', () => {
  const { candidates, zoned } = extract(`
<h2>Indicators of compromise</h2>
<h3>Loader</h3>
<p>${H1}</p>
<h2>Technical analysis</h2>
<p>The loader had MD5 ${H2} during staging.</p>`);
  assert.equal(reasonOf(zoned, /^Technical analysis$/), 'heading_reset');
  assert.equal(isMember(find(candidates, 'md5', H1)), true);
  assert.equal(isMember(find(candidates, 'md5', H2)), false);
});

test('D — legitimate appendix-adjacent binary hash stays excluded from Indicators', () => {
  // Legitimate sample appears only in technical analysis with an explicit
  // "Legitimate Binary" label — not as a publisher IOC appendix row.
  const { candidates } = extract(`
<h2>Technical analysis</h2>
<p>C:\\ProgramData\\Symantec\\RasTls.exe - Legitimate Binary (MD5 ${LEGIT})</p>
<h2>Indicators of compromise</h2>
<h3>PlugX loader</h3>
<p>ef59aad625eebda8650aec5820d6ce69 RasTls.dll</p>`);
  assert.equal(isMember(find(candidates, 'md5', 'ef59aad625eebda8650aec5820d6ce69')), true);
  const legit = find(candidates, 'md5', LEGIT);
  assert.ok(legit, 'legitimate hash still discovered');
  assert.equal(isMember(legit), false);
});

test('E — narrative hashes outside the appendix remain MODE A non-members', () => {
  const { candidates } = extract(`
<h2>Technical analysis</h2>
<p>The dropper wrote ${H3} to disk before beaconing.</p>
<h2>Indicators of compromise</h2>
<p>${H1}</p>`);
  assert.equal(isMember(find(candidates, 'md5', H1)), true);
  assert.equal(isMember(find(candidates, 'md5', H3)), false);
});

test('F — mixed heading levels keep family subsections until Conclusions', () => {
  const { candidates, zoned } = extract(`
<h1>Indicators</h1>
<h2>Family A</h2>
<h3>C2</h3>
<p>family-a-c2.example</p>
<h3>Loader</h3>
<p>${H1}</p>
<h2>Family B</h2>
<h3>Samples</h3>
<p>${H2}</p>
<h1>Conclusions</h1>
<p>Researchers at labs.example contributed telemetry including ${H4}.</p>`);
  assert.equal(isMember(find(candidates, 'domain', 'family-a-c2.example')), true);
  assert.equal(isMember(find(candidates, 'md5', H1)), true);
  assert.equal(isMember(find(candidates, 'md5', H2)), true);
  assert.equal(isMember(find(candidates, 'md5', H4)), false);
  assert.equal(reasonOf(zoned, /^Conclusions$/), 'heading_reset');
});

test('G — bold malware-family labels under File hashes still keep short hash groups', () => {
  const { candidates, zoned } = extract(`
<h2>Indicators of compromise</h2>
<h3>File hashes</h3>
<p><strong>FamilyAlpha</strong><br>${H1}<br>${H2}</p>
<p><strong>FamilyBeta</strong><br>${H3}</p>
<h3>C2 IP addresses</h3>
<p>203.0.113.10<br>203.0.113.11</p>`);
  assert.equal(reasonOf(zoned, /^FamilyAlpha$/), 'subgroup_label');
  for (const h of [H1, H2, H3]) assert.equal(isMember(find(candidates, 'md5', h)), true, h);
  assert.equal(isMember(find(candidates, 'ip', '203.0.113.10')), true);
});

test('H — publisher contact email domain is context-only, not a review candidate', () => {
  const { candidates } = extract(`
<h2>Indicators of compromise</h2>
<p>Additional IoCs are available to customers. For more details, contact us at intelreports@kaspersky.com.</p>
<h3>C2</h3>
<p>evil.example</p>
<p>phish@evil-mailer.example</p>`);
  const contact = find(candidates, 'domain', 'kaspersky.com');
  assert.ok(contact, 'contact domain may still be discovered');
  assert.equal(contact.assessment, 'context_only');
  assert.equal(contact.match_state, 'context_only');
  assert.equal(isContextOnlyCandidate(persisted(contact)), true);
  assert.equal(isMember(contact), false);
  assert.equal(contact.ai_needed, false);
  assert.equal(isMember(find(candidates, 'domain', 'evil.example')), true);
});

test('OctLurk-shaped appendix: C2 siblings then Loaders / plugins keep MD5 Indicators', () => {
  const { candidates, zoned } = extract(`
<h2>Indicators of Compromise</h2>
<p>Additional IoCs are available; contact intelreports@vendor-research.com.</p>
<h3>Backdoor domains and IPs</h3>
<h4>OctFamily C2</h4>
<p>dns[.]multitoconference[.]example</p>
<p>45[.]138[.]157[.]165</p>
<h4>Proxy C2</h4>
<p>dns[.]ssentialserv[.]example</p>
<p>154[.]196[.]162[.]76</p>
<h3>Loaders</h3>
<h4>OctFamily loader</h4>
<p>${H1} oleasapi.dll</p>
<p>${H2} msbasesysdc.dll</p>
<h4>Other loader</h4>
<p>${H3} vulkan-1.dll</p>
<h3>OctFamily backdoor</h3>
<p>${H4}</p>
<h2>Conclusions</h2>
<p>Done.</p>`);
  assert.ok(
    zoned.meta.scope_trace.some((t) => t.decision === 'appendix_retained'),
    'expected appendix_retained when leaving C2 for Loaders'
  );
  assert.equal(isMember(find(candidates, 'domain', 'dns.multitoconference.example')), true);
  assert.equal(isMember(find(candidates, 'ip', '45.138.157.165')), true);
  assert.equal(isMember(find(candidates, 'domain', 'dns.ssentialserv.example')), true);
  assert.equal(isMember(find(candidates, 'ip', '154.196.162.76')), true);
  for (const h of [H1, H2, H3, H4]) {
    const row = find(candidates, 'md5', h);
    assert.ok(row, `md5 ${h}`);
    assert.equal(isMember(row), true, `md5 ${h} Indicator`);
    assert.equal(row.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC);
  }
  const contact = find(candidates, 'domain', 'vendor-research.com');
  if (contact) {
    assert.equal(isMember(contact), false);
    assert.equal(contact.assessment, 'context_only');
  }
});
