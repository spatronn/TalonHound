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
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v64');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v18');
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
