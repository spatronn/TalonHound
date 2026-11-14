/**
 * Section-scope follow-up regressions (tl-section-tree-v19, tl-candidates-v66).
 *
 * Generic shapes of the defects confirmed in the targeted section-role
 * evaluation, with synthetic values — no publisher, report or value condition:
 *
 * FN-1 An appendix titled by an observable type ("Annex 2 - <tool> filename
 *      IPv4 address") whose body is value rows, and which a publisher sentence
 *      elsewhere calls C2 / indicators, is an IOC inventory. Without that
 *      sentence, with a legitimate / translation / example title, or with a
 *      prose body, it stays narrative.
 * FN-2 A name-prefixed IOC title ("Cluster X IoCs & Technical details") whose
 *      body only points at an external list continues into same-level siblings
 *      whose sections are inventories — also past a label nested in the
 *      previous sibling — and stops at the first non-inventory sibling.
 *      Narrative titles ("How We Found the IOCs and Pivoted") are not IOC
 *      headings, and a bold label ("ARECHCLIENT2 IOC:") under a C2 heading
 *      keeps the C2 reading.
 * FP-1 A two-column IOC-table row whose label names the service a value
 *      belongs to ("Registrars | … (registrar.example)") is a provider row;
 *      a "Payload hosting" row, or one that says the operator registered it,
 *      stays an assertion.
 * Controls: public peer / STUN endpoint lists and glued patch links never
 *      become Indicators.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { annotateDocumentZones } from './documentZones.js';
import {
  classifySectionRole,
  isPrefixedIocHeading,
  observableAnnexHeading,
  rowLabelNamesServiceRole,
  textAssertsAnnexIndicators,
  SECTION_ROLES
} from './indicatorScope.js';

const SOURCE = 'https://vendor-research.example/blog/section-scope-followup/';

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

// --- FN-1 ---------------------------------------------------------------------

const ANNEX_IPS = ['198.51.100.11', '198.51.100.12', '198.51.100.13', '198.51.100.14'];
const annexBody = ANNEX_IPS.map((ip) => `<p>${ip.replace(/\.(\d+)$/, '[.]$1')}</p>`).join('\n');

function annexDoc({ title = 'Annex 2 - RMM tool filename IPv4 address', assertion = true, body = annexBody } = {}) {
  return `
<h2>Second wave: the RMM shift</h2>
<p>The RMM files follow a specific name format in which the IPv4 string acts as the server address.${
    assertion
      ? ' Based on this naming convention, additional C2 were uncovered, with a complete list of associated IPv4 addresses provided in Annex 2. These indicators should be used for hunting or retro-hunting.'
      : ' The operators reused the naming convention described in Annex 2 across several builds.'
  }</p>
<h2>Annex</h2>
<h3>Annex 1 - Translation of the lure</h3>
<p>The lure asks the recipient to download the audit notice and run it.</p>
<h3>${title}</h3>
${body}
<h2>Indicators of Compromise</h2>
<ul><li>evil-lure[.]example</li></ul>`;
}

test('FN-1 unit: observable-type appendix titles and publisher cross-references', () => {
  assert.deepEqual(observableAnnexHeading('Annex 2 - RMM tool filename IPv4 address'), { label: 'Annex 2' });
  assert.deepEqual(observableAnnexHeading('Appendix C: Domains'), { label: 'Appendix C' });
  for (const t of [
    'Annex 1 - Translation of the PDF',
    'Appendix B: Legitimate domains contacted by the sample',
    'Appendix D: Example URLs used in the test harness',
    'Appendix E: Victim IP addresses',
    'Malware Analysis',
    'Domains'
  ]) {
    assert.equal(observableAnnexHeading(t), null, t);
  }
  const s = 'Based on this naming convention, additional C2 were uncovered, with a complete list of associated IPv4 addresses provided in Annex 2. These indicators should be used for hunting.';
  assert.equal(textAssertsAnnexIndicators(s, 'Annex 2'), true);
  assert.equal(textAssertsAnnexIndicators(s, 'Annex 3'), false);
  assert.equal(textAssertsAnnexIndicators('Annex 2 lists the legitimate update servers the sample contacts.', 'Annex 2'), false);
});

test('FN-1: a value-row annex the publisher calls C2 indicators is an IOC inventory', () => {
  const m = members(run(annexDoc()));
  for (const ip of ANNEX_IPS) assert.ok(m.includes(`ip:${ip}`), `${ip} missing from ${m.join(', ')}`);
  assert.ok(m.includes('domain:evil-lure.example'));
});

test('FN-1 negative: no publisher assertion, a non-indicator title, or a prose body keeps the annex narrative', () => {
  const variants = [
    annexDoc({ assertion: false }),
    annexDoc({ title: 'Annex 2 - Legitimate RMM vendor IPv4 address' }),
    annexDoc({ title: 'Annex 2 - Example IPv4 address list' }),
    annexDoc({
      body: '<p>During the investigation, the IPv4 string embedded in the file name pointed at 198.51.100[.]11, which the operators rotated weekly across several builds of the tool.</p><p>Later builds moved to 198.51.100[.]12 after the provider suspended the first address and the operators rebuilt their panel.</p>'
    })
  ];
  for (const v of variants) {
    const m = members(run(v));
    for (const ip of ANNEX_IPS) assert.ok(!m.includes(`ip:${ip}`), `${ip} became an Indicator`);
  }
});

// --- FN-2 ---------------------------------------------------------------------

test('FN-2 unit: name-prefixed IOC titles; narrative titles and labels stay narrative', () => {
  for (const t of ['Cluster ClickFix IoCs & Technical details', 'Lazarus IOCs', 'Reference IoCs', 'Public IOCs', 'SilverFox Indicators of Compromise']) {
    assert.equal(isPrefixedIocHeading(t), true, t);
    assert.equal(classifySectionRole(t), SECTION_ROLES.IOC_APPENDIX, t);
  }
  for (const t of ['How We Found the IOCs and Pivoted', 'Why These IOCs Matter', 'near IOC inventory', 'The IOCs', 'Extracting IOCs from memory dumps']) {
    assert.equal(isPrefixedIocHeading(t), false, t);
  }
  assert.equal(classifySectionRole('ARECHCLIENT2 IOC:', { allowPrefixedIoc: false }), null);
});

const SIBLINGS = `
<h2>Conclusion</h2>
<p>The cluster remains active and continues to rotate its lure domains.</p>
<h2>Cluster Phantom IoCs &amp; Technical details</h2>
<p>The list of IoCs is available on Vendor.io GitHub repository.</p>
<h2>Fake meeting pages and associated infection chain</h2>
<p>Phishing domains impersonating the meeting service:</p>
<table><tr><td>meet[.]join-alpha[.]example</td></tr><tr><td>meet[.]join-beta[.]example</td></tr><tr><td>meet[.]join-gamma[.]example</td></tr></table>
<p>Distribution infrastructure:</p>
<table><tr><td>dist-one[.]example</td></tr><tr><td>dist-two[.]example</td></tr></table>
<h2>Additional clusters associated to the same teams</h2>
<p>Sekoia-style research uncovered further distribution infrastructure tied to the same teams.</p>
<ul><li>Zoom cluster</li></ul>
<table><tr><td>us01web-meet[.]example us03web-meet[.]example us07web-meet[.]example</td></tr></table>
<ul><li>Game cluster</li></ul>
<table><tr><td>battle-one[.]example battle-two[.]example</td></tr></table>
<ul><li>Office software cluster</li></ul>
<table><tr><td>doc-reader-one[.]example doc-reader-two[.]example</td></tr></table>
<h2>Related articles</h2>
<p>Read our earlier report about other-research[.]example and the wider ecosystem of lures.</p>`;

test('FN-2: a pointer-only IOC heading continues into same-level inventory siblings', () => {
  const m = members(run(SIBLINGS));
  for (const v of ['meet.join-alpha.example', 'meet.join-gamma.example', 'dist-two.example', 'us01web-meet.example', 'battle-two.example']) {
    assert.ok(m.includes(`domain:${v}`), `${v} missing from ${m.join(', ')}`);
  }
  assert.ok(!m.includes('domain:other-research.example'), 'a non-inventory sibling inherited the IOC scope');
  // The rows are publisher assertions of the IOC section (not body mentions a
  // model decision could demote): both siblings sit in its scope.
  const open = zones(SIBLINGS);
  assert.equal(open(/^Cluster Phantom IoCs/), 'explicit_ioc_section');
  assert.equal(open(/meet\[\.\]join-alpha/), 'explicit_ioc_section');
  assert.equal(open(/battle-two/), 'explicit_ioc_section');
  assert.notEqual(open(/other-research/), 'explicit_ioc_section', 'a related-articles sibling inherited the IOC scope');
});

function zones(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  const blocks = annotateDocumentZones(r.document, { sourceUrl: SOURCE }).blocks;
  return (re) => blocks.find((b) => re.test(String(b.text || '')))?.zone ?? null;
}

test('FN-2 negative: a narrative-prefixed heading opens nothing and a non-inventory sibling ends the scope', () => {
  const narrative = zones(SIBLINGS.replace('Cluster Phantom IoCs &amp; Technical details', 'How We Found the IOCs and Pivoted'));
  assert.equal(narrative(/^How We Found the IOCs/), 'report_body');
  assert.equal(narrative(/meet\[\.\]join-alpha/), 'report_body');

  const closed = zones(SIBLINGS.replace(
    '<h2>Fake meeting pages and associated infection chain</h2>',
    '<h2>Outlook</h2><p>We expect the operators to keep rotating lures across many hosting providers in the coming months.</p><p>Defenders should monitor new registrations closely and share what they find with their peers.</p><h2>Fake meeting pages and associated infection chain</h2>'
  ));
  assert.equal(closed(/^Cluster Phantom IoCs/), 'explicit_ioc_section');
  assert.equal(closed(/meet\[\.\]join-alpha/), 'report_body', 'scope crossed a non-inventory sibling');
});

// --- FP-1 ---------------------------------------------------------------------

test('FP-1 unit: a service-role row label marks a provider row', () => {
  assert.equal(rowLabelNamesServiceRole('Registrars | Beijing Example Co., Ltd; Example Cloud (OBSERVABLE); GoDaddy'), true);
  assert.equal(rowLabelNamesServiceRole('Suspected origin hosting | AS64500 (Example Inc); reverse-DNS pattern OBSERVABLE'), true);
  assert.equal(rowLabelNamesServiceRole('Certificate authority | OBSERVABLE'), true);
  assert.equal(rowLabelNamesServiceRole('Payload hosting | OBSERVABLE'), false);
  assert.equal(rowLabelNamesServiceRole('C2 hosting | OBSERVABLE'), false);
  assert.equal(rowLabelNamesServiceRole('Registrar | OBSERVABLE registered by the threat actor'), false);
  assert.equal(rowLabelNamesServiceRole('Suspected origins | OBSERVABLE'), false);
  assert.equal(rowLabelNamesServiceRole('OBSERVABLE | registrar'), false);
});

test('FP-1: a registrar row in an IOC table is not an Indicator; the origin row next to it is', () => {
  const m = members(run(`
<h2>Indicators of Compromise</h2>
<h3>Clustering indicators</h3>
<table>
<tr><th>Indicator</th><th>Value</th></tr>
<tr><td>Suspected origins</td><td>203[.]0[.]113[.]49, 203[.]0[.]113[.]38</td></tr>
<tr><td>Registrars</td><td>Example Registrar Co., Ltd; Example Cloud (www[.]registrar-example[.]cn); GoDaddy</td></tr>
<tr><td>Payload hosting</td><td>files[.]evil-host[.]example</td></tr>
</table>`));
  assert.ok(m.includes('ip:203.0.113.49'), m.join(', '));
  assert.ok(m.includes('domain:files.evil-host.example'), m.join(', '));
  assert.ok(!m.includes('domain:www.registrar-example.cn'), 'registrar became an Indicator');
});

// --- Controls -------------------------------------------------------------------

test('control: public peer and public STUN endpoint lists stay out of the Indicators', () => {
  const m = members(run(`
<h2>Network communication</h2>
<p>The backdoor joins the public overlay network through an embedded list of publicly available peers, most of which are run by volunteers.</p>
<h3>List of public peers in the sample</h3>
<pre><code>tls://198.51.100[.]71:993</code></pre>
<pre><code>tls://198.51.100[.]72:65534</code></pre>
<pre><code>tls://peer[.]volunteer-node[.]example:443</code></pre>
<p>It then sends standard binding requests to 3 public STUN endpoints:</p>
<table><tr><td>198[.]51[.]100[.]81</td><td>198[.]51[.]100[.]82</td><td>198[.]51[.]100[.]83</td></tr></table>
<h2>Indicators of Compromise</h2>
<ul><li>203[.]0[.]113[.]9</li></ul>`));
  for (const v of ['ip:198.51.100.71', 'ip:198.51.100.81', 'domain:peer.volunteer-node.example']) assert.ok(!m.includes(v), `${v} became an Indicator`);
  assert.ok(m.includes('ip:203.0.113.9'));
});

test('control: glued CVE ids in patch links never become Indicators', () => {
  const x = run(`
<h2>Patch links</h2>
<ul>
<li><span>CVE-2026-100001</span><a href="https://support.vendor.example/external/article/CTX1/fix.html">support.vendor.example/external/articl…fix.html</a></li>
<li><span>CVE-2026-100002</span><a href="https://hub.vendor.example/s/article/Security-123">hub.vendor.example/s/article/Security-…123</a></li>
</ul>`);
  const m = members(x);
  assert.deepEqual(m.filter((v) => /vendor\.example|cve-/i.test(v)), []);
});
