/**
 * Review-queue audit (35858–35869) regressions (tl-candidates-v64,
 * tl-section-tree-v18).
 *
 * Generic shapes of the confirmed extraction defects, with synthetic values —
 * no publisher, report or value condition:
 *
 * FN-1 An appendix titled by what the operator owns ("Appendix E: Attacker
 *      Management Repository") over a run of repository URLs is the
 *      publisher's IOC appendix: each URL is an Indicator, like the sibling
 *      "Appendix A: Network IoCs" rows. An appendix that calls the services
 *      legitimate ("URLs of Legitimate Services Used by the Attacker") or that
 *      lists victims stays narrative, and a non-appendix heading with the same
 *      words opens nothing.
 * OBL-1 A footer's inline widget script key ("apiKey: '<32 hex>'") is not an
 *      unaccounted significant source region (threat_library_html_v11).
 * FP-1 "hotfixes (10.3.4.45 for v10, and 9.15.2.70 for v7 …)": release
 *      numbers, not IPv4 addresses. A network cue at the token still wins.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { classifySectionRole, SECTION_ROLES } from './indicatorScope.js';
import { ipv4VersionContext } from './ipv4VersionContext.js';

const SOURCE = 'https://vendor-research.example/blog/review-queue-audit-four/';

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
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

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v67');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v19');
});

// --- FN-1 --------------------------------------------------------------------

const REPOS = [
  'https[:]//github[.]com/opalpha123/aaabbbccc',
  'https[:]//github[.]com/opbeta456/dddeeefff',
  'https[:]//gitlab[.]com/opalpha123/ggghhhiii',
  'https[:]//codeberg[.]org/opgamma789/jjjkkklll'
];
const REPO_URLS = [
  'url:https://codeberg.org/opgamma789/jjjkkklll',
  'url:https://github.com/opalpha123/aaabbbccc',
  'url:https://github.com/opbeta456/dddeeefff',
  'url:https://gitlab.com/opalpha123/ggghhhiii'
];

const appendices = (title) => `
<h2>In Conclusion</h2>
<p>The operator abused several legitimate services as access destinations for the downloader.</p>
<h4>Appendix A: Network IoCs</h4>
<ul><li>198.51.100[.]21</li><li>198.51.100[.]22</li></ul>
<h4>${title}</h4>
${REPOS.map((u) => `<pre><code>${u}</code></pre>`).join('\n')}
<h4>Appendix F: Email Addresses Used for Commits</h4>
<pre><code>opalpha123@mail.example</code></pre>`;

test('FN-1: classifySectionRole reads an operator-owned resource appendix as an IOC appendix', () => {
  for (const t of [
    'Appendix E: Attacker Management Repository',
    'Appendix C: Attacker-controlled GitHub accounts',
    'Annex B: Threat actor domains',
    'Appendix 2 - Operator websites'
  ]) {
    assert.equal(classifySectionRole(t), SECTION_ROLES.IOC_APPENDIX, t);
  }
});

test('FN-1 negative: legitimate / victim stances, missing owner or noun, and non-appendix headings stay narrative', () => {
  for (const t of [
    'Appendix B: URLs of Legitimate Services Used by the Attacker',
    'Appendix G: Victimized Devices Identified from the Attacker Repository',
    'Appendix D: Attacker targeted domains',
    'Appendix F: Email Addresses Used for Commits',
    'Appendix H: Attacker tradecraft',
    'Attacker Management Repository',
    'How the attacker managed the repository over time'
  ]) {
    assert.equal(classifySectionRole(t), null, t);
  }
});

test('FN-1: repository URLs under an operator-owned resource appendix are Indicators', () => {
  const m = members(run(appendices('Appendix E: Attacker Management Repository')));
  for (const u of REPO_URLS) assert.ok(m.includes(u), `${u} missing from ${m.join(', ')}`);
  assert.ok(m.includes('ip:198.51.100.21'));
});

test('FN-1 negative: the same run under a legitimate-services appendix is not an Indicator set', () => {
  const m = members(run(appendices('Appendix B: URLs of Legitimate Services Used by the Attacker')));
  for (const u of REPO_URLS) assert.ok(!m.includes(u), `${u} became an Indicator`);
  assert.ok(m.includes('ip:198.51.100.21'));
});

// --- FP-1 --------------------------------------------------------------------

test('FP-1: hotfix release numbers ("<ver> for v10") are not IPv4 candidates', () => {
  const x = run(`
<h2>Background</h2>
<p>The vendor has since released hotfixes (10.3.4.45 for v10, and 9.15.2.70 for v7 through v9) that close both flaws.</p>`);
  const ips = x.candidates.filter((c) => c.candidate_type === 'ip').map((c) => c.normalized_value);
  assert.deepEqual(ips, [], ips.join(', '));
});

test('FP-1 unit: hotfix keyword and "for vN" phrase are version cues; a network cue still wins', () => {
  const at = (s, tok) => [s.indexOf(tok), s.indexOf(tok) + tok.length];
  const a = 'Ahsay released hotfixes (10.3.4.45 for v10, and 9.15.2.70 for v7).';
  assert.equal(ipv4VersionContext(a, ...at(a, '10.3.4.45'))?.kind, 'version');
  assert.equal(ipv4VersionContext(a, ...at(a, '9.15.2.70'))?.kind, 'version');
  const b = 'The hotfix 2.3.4.5 is now available.';
  assert.equal(ipv4VersionContext(b, ...at(b, '2.3.4.5'))?.kind, 'version');
  const c = 'The implant connected to 203.0.113.7 for v2 of its protocol.';
  assert.equal(ipv4VersionContext(c, ...at(c, '203.0.113.7')), null);
  const d = 'The loader beaconed to 198.51.100.40 every hour.';
  assert.equal(ipv4VersionContext(d, ...at(d, '198.51.100.40')), null);
});

test('FP-1 negative: an operator IP in an IOC table stays an Indicator', () => {
  const m = members(run(`
<h2>Indicators of Compromise</h2>
<table><tr><th>Item</th><th>Description</th></tr>
<tr><td>198.51.100[.]115:443</td><td>Mining pool address used by the miner</td></tr></table>`));
  assert.ok(m.includes('ip:198.51.100.115'), m.join(', '));
});

// --- OBL-1 ------------------------------------------------------------------
// A site footer whose inline newsletter-form script carries a public widget key
// ("apiKey: '<32 hex>'") left an unaccounted significant source region, which
// blocks finalize. Script / style text nested in a dropped region is code, not
// page text: counted, never significant, never sampled. A digest written as
// visible footer text still is.

const FOOTER_KEY = hex32('9f');
function hex32(seed) {
  return seed.repeat(16);
}
function droppedFooter(footerInner) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body>
<article><h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
<h2>Indicators of Compromise</h2><ul><li>198.51.100[.]31</li></ul>
<footer>${footerInner}</footer></article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return (r.document.meta.source_accounting?.dropped_regions || []).find((x) => x.region_kind === 'footer');
}

test('OBL-1: a footer inline widget script key is counted but not a significant region', () => {
  const footer = droppedFooter(`<p>Subscribe to our newsletter</p>
<script>hbspt.forms.create({ region: "eu1", onFormReady: function () { const config = { apiKey: "${FOOTER_KEY}" }; } });</script>`);
  assert.ok(footer, 'footer region recorded');
  assert.equal(footer.observable_count, 1);
  assert.equal(footer.significant, false);
  assert.deepEqual(footer.sample_observables, []);
});

test('OBL-1 negative: a digest in visible footer text keeps the region significant', () => {
  const footer = droppedFooter(`<p>Sample of the week: ${FOOTER_KEY}</p><script>var x = 1;</script>`);
  assert.ok(footer, 'footer region recorded');
  assert.equal(footer.significant, true);
  assert.deepEqual(footer.sample_observables, [FOOTER_KEY]);
});

// --- FP-2 (tl-candidates-v65) -------------------------------------------------
// "hotfixes (10.3.4.45 for v10 …), and we verified that 10.3.4.45 blocks the
// entry point": the second, cue-less mention refers back to the release the
// same paragraph just named. A network cue at the re-mention, or a value never
// read as a release in that block, keeps the IPv4 reading.

test('FP-2: a bare re-mention of a release number in the same block is not an IPv4 candidate', () => {
  const x = run(`
<h2>Background</h2>
<p>The vendor has since released hotfixes (10.3.4.45 for v10, and 9.15.2.70 for v7 through v9), and we verified that 10.3.4.45 blocks the entry point we saw.</p>`);
  const ips = x.candidates.filter((c) => c.candidate_type === 'ip').map((c) => c.normalized_value);
  assert.deepEqual(ips, [], ips.join(', '));
});

test('FP-2 unit: coreference applies only to known versions without a network cue', () => {
  const at = (s, tok, from = 0) => [s.indexOf(tok, from), s.indexOf(tok, from) + tok.length];
  const known = new Set(['10.3.4.45']);
  const a = 'and we verified that 10.3.4.45 blocks the entry point.';
  assert.equal(ipv4VersionContext(a, ...at(a, '10.3.4.45'), { knownVersions: known })?.cue, 'version_coreference');
  assert.equal(ipv4VersionContext(a, ...at(a, '10.3.4.45')), null);
  const b = 'and later 10.3.4.45 is the C2 address.';
  assert.equal(ipv4VersionContext(b, ...at(b, '10.3.4.45'), { knownVersions: known }), null);
  const c = 'the implant connected to 10.3.4.45 afterwards.';
  assert.equal(ipv4VersionContext(c, ...at(c, '10.3.4.45'), { knownVersions: known }), null);
  const d = 'and we verified that 203.0.113.9 blocks the entry point.';
  assert.equal(ipv4VersionContext(d, ...at(d, '203.0.113.9'), { knownVersions: known }), null);
});

test('FP-2 negative: a release number in one paragraph does not retype the same value in another', () => {
  const x = run(`
<h2>Background</h2>
<p>The vendor released hotfix 198.51.100.45 for v10 last week.</p>
<p>We later observed traffic from 198.51.100.45 during the intrusion.</p>`);
  const ips = x.candidates.filter((c) => c.candidate_type === 'ip').map((c) => c.normalized_value);
  assert.ok(ips.includes('198.51.100.45'), ips.join(', '));
});
