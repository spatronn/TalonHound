/**
 * Post-finalization remediation of the 24-report review queue 35935–35959
 * (tl-candidates-v73, tl-table-v22, threat_library_html_v14).
 *
 * A. 35943 / 35946 / 35948 / 35955: email addresses the publisher lists as IOCs
 *    ("Email address | Attacker-controlled email address", "Emails associated
 *    with this activity:" bullets) were rejected as an unsupported type.
 * B. 35956 / 33348 / 35441: an address in prose is context (promotable on an
 *    operational clause), a spoofed brand sender and a vendor contact are
 *    context, and package specifiers / redacted / reserved shapes are not
 *    addresses at all.
 * C. 35590: once a table's email rows parse it becomes an IOC table; its
 *    template-URL row ("…?uid=<target_specific_uuid>") must stay an Indicator.
 * D. 35951: a C2 domain in a decrypted malware configuration was refused by the
 *    promotion gate (no attacker-use sentence). Configuration slots are now
 *    operational evidence for promotion, narrowly.
 * E. 35944: source accounting reported a dropped region for values the
 *    document kept ("reviewerpress[.]com.Figure", "mycartpanda[.]com.").
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { classifyPromoteEligibility, hasMalwareConfigurationEvidence, CREATABLE_IOC_TYPES, iocStorageIdentity } from './promotion.js';
import { malwareConfigLeadInsByBlock, malwareConfigSlotKey } from './candidateHelpers.js';
import { parseIndicatorCell } from './tableSemantics.js';
import { extractGenericArticleDocument, THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';

test('post-finalization remediation contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v76');
  assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v15');
  assert.ok(CREATABLE_IOC_TYPES.includes('email'));
});

function extract(blocks) {
  return extractReportCandidates(
    { source_type: 'url', source_url: 'https://publisher.example/report' },
    createCanonicalDocument({ title: 'Remediation fixture', blocks })
  );
}
const find = (r, type, value) => r.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const member = (r, type, value) => {
  const c = find(r, type, value);
  return Boolean(c && isReportIndicatorMember(c));
};
const asRow = (c, review = 'context_only') => ({
  ...c,
  review_status: review,
  has_original_document_occurrence: true,
  evidence: buildCandidateEvidenceRecord(c)
});

test('A: IOC-table and IOC-list addresses are `email` Indicators with canonical identity', () => {
  const r = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    { id: 'p1', type: 'paragraph', text: 'Emails associated with this activity:' },
    { id: 'l1', type: 'list', text: 'paloaltonetworks@gmail[.]com' },
    { id: 'l2', type: 'list', text: 'recruiter[.]paloaltonetworks@gmail [.]com' },
    createTableBlock({
      id: 't1',
      headers: ['Indicator', 'Type', 'Description', 'First Seen'],
      rows: [
        ['alex@contacttrixauvex[.]ink', 'Email address', 'Attacker-controlled email address', 'May 2026'],
        ['c.laurent.ejfa@proton[.]me', 'Email address', 'Actor-controlled sender address', 'September 2025'],
        ['istc-cloud[.]com', 'Domain', 'ZimReaper C&C', 'February 2026']
      ]
    })
  ]);
  for (const v of ['paloaltonetworks@gmail.com', 'recruiter.paloaltonetworks@gmail.com', 'alex@contacttrixauvex.ink', 'c.laurent.ejfa@proton.me']) {
    assert.ok(member(r, 'email', v), v);
    assert.deepEqual(iocStorageIdentity(find(r, 'email', v)), { type: 'email', value: v });
  }
  assert.ok(member(r, 'domain', 'istc-cloud.com'));
  // The mailbox provider of a listed address is never an Indicator by itself.
  assert.equal(member(r, 'domain', 'gmail.com'), false);
  assert.equal(member(r, 'domain', 'proton.me'), false);
});

test('B: prose, spoofed, vendor and non-address shapes stay out of the Indicator set', () => {
  const r = extract([
    { id: 'p0', type: 'paragraph', text: 'The account email was changed to ifstap@proton[.]me, an attacker-controlled ProtonMail address.' },
    { id: 'p1', type: 'paragraph', text: 'The mail was sent as Boots <hello[@]boots[.]com>, impersonating the UK retailer.' },
    { id: 'p2', type: 'paragraph', text: 'Run npm install plain-crypto-js@4.2.1 or pin axios@1.14.1; clone git@github.com:org/repo.' },
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    createTableBlock({
      id: 't1',
      headers: ['Indicator', 'Type', 'Description'],
      rows: [
        ['e*******7[@]proton[.]me', 'Email', 'Extortion contact'],
        ['bad-c2[.]top', 'Domain', 'C2']
      ]
    }),
    { id: 'p3', type: 'paragraph', text: 'To exchange data, contact us at tdr[at]vendor-intel.com.' }
  ]);
  const ifstap = find(r, 'email', 'ifstap@proton.me');
  assert.ok(ifstap);
  assert.equal(isReportIndicatorMember(ifstap), false);
  // The publisher's "attacker-controlled" clause lets an analyst promote it.
  const promote = classifyPromoteEligibility(asRow(ifstap), { corroboration: 'Publisher: attacker-controlled ProtonMail address' });
  assert.equal(promote.ok, true, promote.detail);
  assert.equal(promote.basis, 'operational_evidence');

  const boots = find(r, 'email', 'hello@boots.com');
  assert.ok(boots);
  assert.equal(isReportIndicatorMember(boots), false);
  assert.equal(classifyPromoteEligibility(asRow(boots), { corroboration: 'spoofed sender of the lure' }).ok, false);

  assert.equal(member(r, 'email', 'tdr@vendor-intel.com'), false);
  assert.ok(member(r, 'domain', 'bad-c2.top'));
  for (const c of r.candidates.filter((x) => x.candidate_type === 'email')) {
    assert.doesNotMatch(c.normalized_value, /\*|@\d|^git@github\.com$/, c.normalized_value);
  }
});

test('C: a template-URL row of a table that also holds email rows stays an Indicator', () => {
  const parsed = parseIndicatorCell('hxxps://mail.iwsmailserver[.]com/owa/auth/logon.aspx?uid=<target_specific_uuid>', { type: 'url', endpoint: false }, { typeLabel: 'URL' });
  assert.deepEqual(parsed.values.map((v) => v.normalized_value), ['https://mail.iwsmailserver.com/owa/auth/logon.aspx?uid=']);
  // Colon / digit slots and a second placeholder stay templates.
  assert.equal(parseIndicatorCell('hxxps://x[.]com/a?id=<linkid:8>', { type: 'url', endpoint: false }).values.length, 0);
  assert.equal(parseIndicatorCell('hxxps://x[.]com/a?id=<a>&b=<c>', { type: 'url', endpoint: false }).values.length, 0);

  const r = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    createTableBlock({
      id: 't1',
      headers: ['Indicator', 'Type', 'Description', 'First Seen'],
      rows: [
        ['ali.mo@med.gov[.]sy', 'Email address', 'Sender email (likely compromised)', 'March 2026'],
        ['hxxps://mail.iwsmailserver[.]com/owa/auth/logon.aspx?uid=<target_specific_uuid>', 'URL', 'OWA credential phishing URL format', 'March 2026'],
        ['iwsmailserver[.]com', 'Domain', 'TA402 phishing host', 'March 2026']
      ]
    })
  ]);
  assert.ok(member(r, 'url', 'https://mail.iwsmailserver.com/owa/auth/logon.aspx?uid='));
  assert.ok(member(r, 'domain', 'iwsmailserver.com'));
  assert.ok(member(r, 'email', 'ali.mo@med.gov.sy'));
});

const CONFIG_LEAD = 'As an example, in early 2026, we saw a new variation of the standard Winos4.0 malware being used by this group. The malware’s configuration, once decrypted, is as follows:';
const CONFIG_BLOB = '|A16A6736FB5DC030EF3|A1:aeya388[.]club|o1:7880|t1:1|S2:aeya388[.]club|o2:7881|t2:1|dd:10|cl:30|';

test('D: a decrypted-configuration C2 slot is promotion evidence (never membership)', () => {
  const blocks = [
    { id: 'h0', type: 'heading', level: 2, text: 'Indicators of compromise' },
    createTableBlock({ id: 't0', headers: ['Indicator', 'Type'], rows: [['listed-c2[.]top', 'Domain']] }),
    { id: 'h1', type: 'heading', level: 3, text: 'Winos4.0 Analysis' },
    { id: 'p1', type: 'paragraph', text: CONFIG_LEAD },
    { id: 'p2', type: 'paragraph', text: CONFIG_BLOB }
  ];
  assert.equal(malwareConfigLeadInsByBlock(blocks).get('p2'), 'The malware’s configuration, once decrypted, is as follows:');
  const r = extract(blocks);
  const c = find(r, 'domain', 'aeya388.club');
  assert.ok(c);
  assert.equal(isReportIndicatorMember(c), false);
  const row = asRow(c);
  assert.equal(hasMalwareConfigurationEvidence(row), true);
  assert.equal(row.evidence.occurrences[0].malware_config_key, 'A1');
  const needsNote = classifyPromoteEligibility(row);
  assert.equal(needsNote.code, 'promote_corroboration_required');
  assert.equal(needsNote.basis, 'malware_configuration');
  const ok = classifyPromoteEligibility(row, { corroboration: 'C2 list of the decrypted Winos4.0 config (Proofpoint)' });
  assert.equal(ok.ok, true, ok.detail);
  assert.equal(ok.basis, 'malware_configuration');
});

test('D: example formats, probe keys, reserved hosts, provider policy and plain prose are not configuration evidence', () => {
  // An example of the format is not the sample's configuration.
  assert.equal(malwareConfigLeadInsByBlock([
    { id: 'a', type: 'paragraph', text: 'An example of the decrypted configuration format is shown below:' },
    { id: 'b', type: 'paragraph', text: '|A1:aeya388[.]club|o1:7880|t1:1|' }
  ]).size, 0);
  assert.equal(malwareConfigLeadInsByBlock([
    { id: 'a', type: 'paragraph', text: 'The decrypted configuration follows this structure:' },
    { id: 'b', type: 'code', text: '"internetCheckDomain": "<...>", "c2": "<...>", "port": 443' }
  ]).size, 0);
  // Not a dump (fewer than three slots) / a probe key / no key before the value.
  const at = (text, v) => ({ start: text.indexOf(v), end: text.indexOf(v) + v.length });
  const dump = 'internetCheckDomain: www.bing.com | host: c2.bad.top | port: 443';
  assert.equal(malwareConfigSlotKey(dump, 'www.bing.com', at(dump, 'www.bing.com')), null);
  assert.equal(malwareConfigSlotKey(dump, 'c2.bad.top', at(dump, 'c2.bad.top')), 'host');
  assert.equal(malwareConfigSlotKey('host: c2.bad.top', 'c2.bad.top', at('host: c2.bad.top', 'c2.bad.top')), null);
  const undefanged = 'A1:aeya388.club|o1:7880|t1:1';
  assert.equal(malwareConfigSlotKey(undefanged, 'aeya388.club', at(undefanged, 'aeya388.club')), null);

  const base = {
    candidate_type: 'domain',
    normalized_value: 'cfg.example',
    review_status: 'context_only',
    assessment: 'context_only',
    has_original_document_occurrence: true,
    evidence: { occurrences: [{ malware_config_key: 'A1', malware_config_lead_in: 'The configuration, once decrypted, is as follows:', surrounding_text: '|A1:cfg[.]example|' }] }
  };
  assert.equal(hasMalwareConfigurationEvidence(base), false);
  const provider = { ...base, normalized_value: 'api.github.com', evidence: { ...base.evidence, policy_decision: 'context_only_provider_service' } };
  assert.equal(classifyPromoteEligibility(provider, { corroboration: 'listed in decrypted config' }).ok, false);
  // The same value in plain prose, without the configuration fields, stays refused.
  const prose = { ...base, normalized_value: 'aeya388.club', evidence: { occurrences: [{ surrounding_text: 'We also saw aeya388[.]club in passive DNS.' }] } };
  assert.equal(classifyPromoteEligibility(prose, { corroboration: 'seen in passive DNS' }).code, 'promote_insufficient_evidence');
});

const PAGE_35944 = `<!doctype html><html><body><main class="main"><article>
<h1>Fooling AI Agents</h1>
<p>This attack, hosted at <span>hxxps[:]//reviewerpress[.]com/advertorial-maxvision-can/?lang=en</span>, serves a deceptive scam advertisement. The page has enough prose to be the article body for root selection and scoring purposes here.</p>
<p>Clicking the button redirects the user to <span>reviewerpressus.mycartpanda[.]com</span>.</p>
<figure><img src="a.png"/><figcaption>Figure 2. Example of hidden prompt in page from r<span>eviewerpress[.]com</span>.</figcaption></figure>Figure 3 provides combined screenshots showing the scam page itself.
<h2>Indicators</h2><ul><li>reviewerpressus.mycartpanda[.]com</li><li>shiftypumpkin[.]com</li></ul>
</article></main></body></html>`;

test('E: values the document kept are never reported as an unaccounted region', () => {
  const doc = extractGenericArticleDocument(PAGE_35944, { url: 'https://unit42.example/ai-agent-prompt-injection/' });
  const regions = doc.meta.source_accounting.dropped_regions.filter((r) => r.region_kind === 'outside_content_root');
  assert.deepEqual(regions, []);
});

test('E: an observable really outside the chosen root is still reported (adversarial)', () => {
  const page = PAGE_35944.replace('</main>', '</main><aside class="sidebar"><p>Also blocklist evil-sidebar[.]top today.</p></aside>');
  const doc = extractGenericArticleDocument(page, { url: 'https://unit42.example/ai-agent-prompt-injection/' });
  const outside = doc.meta.source_accounting.dropped_regions.filter((r) => r.region_kind === 'outside_content_root');
  assert.equal(outside.length, 1);
  assert.deepEqual(outside[0].sample_observables, ['evil-sidebar[.]top']);
  assert.equal(outside[0].significant, true);
});
