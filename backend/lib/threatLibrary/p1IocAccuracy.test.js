/**
 * P1 IOC accuracy (tl-candidates-v69, tl-section-tree-v21, tl-type-resolver-v29).
 *
 * A. A sentence that names the values after its colon as indicators is that
 *    declaration, even when a curated IOC table also exists. A domain that is
 *    only mentioned, or that sits in a hunting-query code block, is not.
 * B. A list row whose only extra text is a trailing "<--" comment is still
 *    that row.
 * C. A paragraph that is only an obfuscated author address is contact
 *    metadata. A defanged address in an IOC list stays an Indicator unless
 *    the publisher says the sender is spoofed.
 * D. A URL that continues into an unexpanded placeholder is a template. The
 *    shortened or percent-encoded prefix is not an Indicator. A concrete URL
 *    in the same section stays one.
 * E. Refresh replays an applied model label after a publisher assertion owns
 *    the decision, and drops it when the quoted evidence is no longer in the
 *    document. Membership is unchanged in both cases.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates, mergeAiCandidateUpdates } from './extractionStages.js';
import { aiReplayUpdatesFromRows } from './extractionRefresh.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION, templateUrlSpanEnd, validateUrlCandidate } from './observableTypeResolver.js';
import { declaredIndicatorListText, stripTrailingInlineComment } from './indicatorScope.js';

test('P1 contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v75');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v22');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v30');
});

function extract(blocks) {
  return extractReportCandidates(
    { source_type: 'url', source_url: 'https://publisher.example/report' },
    createCanonicalDocument({ title: 'P1 fixture', blocks })
  );
}

function find(result, type, value) {
  return result.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
}

function assertMember(result, type, value) {
  const c = find(result, type, value);
  assert.ok(c, `missing candidate ${type}:${value}`);
  assert.equal(isReportIndicatorMember(c), true, `${type}:${value} ${c.policy_decision} ${c.membership_decision?.rule_id}`);
  return c;
}

function assertNotMember(result, type, value) {
  const c = find(result, type, value);
  if (!c) return null;
  assert.equal(isReportIndicatorMember(c), false, `${type}:${value} became ${c.policy_decision} ${c.membership_decision?.rule_id}`);
  return c;
}

test('A: an explicit prose declaration is an Indicator beside a curated table', () => {
  const table = createTableBlock({
    id: 't1',
    headers: ['Indicator', 'Role'],
    rows: [
      ['db-connectors[.]vercel[.]app', 'Stage one loader'],
      ['138.226.247[.]154', 'C2']
    ]
  });
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'C2 and infrastructure' },
    table,
    { id: 'h2', type: 'heading', level: 2, text: 'Hunting queries' },
    {
      id: 'decl',
      type: 'paragraph',
      text: 'Network, for the observed command hosts at decoy-before.vendor.net. These domains and addresses are indicators, not destinations to visit: db-connectors[.]vercel[.]app, chainmanamgentagency[.]info, green-horse-42739[.]zap[.]cloud, blue-eagle-26751[.]zap[.]cloud, 138.226.247[.]154.'
    },
    { id: 'pass', type: 'paragraph', text: 'The vendor blog is published at research-notes.vendor.net.' },
    { id: 'code', type: 'code', text: 'DeviceProcessEvents | where RemoteUrl has "telemetry.vendor-cloud.net"' },
    { id: 'neg', type: 'paragraph', text: 'These domains are not indicators: not-an-indicator.vendor.net.' }
  ]);

  assertMember(result, 'domain', 'green-horse-42739.zap.cloud');
  assertMember(result, 'domain', 'blue-eagle-26751.zap.cloud');
  assertMember(result, 'domain', 'chainmanamgentagency.info');
  assertMember(result, 'domain', 'db-connectors.vercel.app');
  assertMember(result, 'ip', '138.226.247.154');
  const declared = find(result, 'domain', 'green-horse-42739.zap.cloud');
  assert.equal(declared.policy_decision, 'explicit_report_assertion');
  assert.equal(declared.membership_decision.rule_id, 'R10_publisher_assertion');
  assert.equal(declared.occurrences.some((o) => o.relation_marker === 'declared_indicator'), true);

  assertNotMember(result, 'domain', 'decoy-before.vendor.net');
  assertNotMember(result, 'domain', 'research-notes.vendor.net');
  assertNotMember(result, 'domain', 'telemetry.vendor-cloud.net');
  assertNotMember(result, 'domain', 'not-an-indicator.vendor.net');
});

test('declaration list text stops at the colon list and ignores a negation', () => {
  const list = declaredIndicatorListText(
    'These domains and addresses are indicators, not destinations to visit: a[.]example, b[.]example. The vendor blog is published at research-notes.vendor.net.'
  );
  assert.match(list, /a\[\.\]example/);
  assert.doesNotMatch(list, /research-notes/);
  assert.equal(declaredIndicatorListText('These domains are not indicators: not-an-indicator.vendor.net.'), null);
  assert.equal(stripTrailingInlineComment('hxxp[:]//171.22.131[.]24:8133/api/t <-- HTTP POST request, generated 4 times'), 'hxxp[:]//171.22.131[.]24:8133/api/t');
});

test('B: a trailing inline comment does not keep an infection-traffic URL unresolved', () => {
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
    { id: 'lead', type: 'paragraph', text: 'Infection traffic for the infostealer:' },
    { id: 'u1', type: 'list', text: 'hxxp[:]//45.150.32[.]130/37339606cba4522a?force=1' },
    { id: 'u2', type: 'list', text: 'hxxp[:]//171.22.131[.]24:8133/api/t <-- HTTP POST request, generated 4 times before the malware was blocked' }
  ]);
  assertMember(result, 'url', 'http://45.150.32.130/37339606cba4522a?force=1');
  const url = assertMember(result, 'url', 'http://171.22.131.24:8133/api/t');
  assert.equal(url.policy_decision, 'explicit_report_assertion');
  assert.equal(url.membership_decision.rule_id, 'R10_publisher_assertion');
});

test('C: an obfuscated author address is not an Indicator; a listed address is', () => {
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
    { id: 'd1', type: 'list', text: 'quill-kraee-um2gf[.]pro' },
    { id: 'mail', type: 'list', text: 'brahma2023[@]onionmail[.]org' },
    { id: 'aff', type: 'list', text: 'affiliate [at] evil-phish.net' },
    { id: 'rule', type: 'paragraph', text: '--' },
    { id: 'who', type: 'paragraph', text: 'Bradley Duncan' },
    { id: 'sig', type: 'paragraph', text: 'brad [at] malware-traffic-analysis.net' },
    { id: 'kw', type: 'paragraph', text: 'Keywords:' },
    { id: 'cmt', type: 'paragraph', text: '2 comment(s)' },
    { id: 'spoof', type: 'paragraph', text: 'Spoofed sender impersonating the brand: hello[@]boots[.]com' }
  ]);
  assertMember(result, 'domain', 'quill-kraee-um2gf.pro');
  // A listed defanged address keeps its row reading. Membership of an email
  // domain is unchanged by this fix: it must not be collapsed to contact metadata.
  const onion = find(result, 'domain', 'onionmail.org');
  assert.ok(onion, 'listed address domain stays a candidate');
  assert.notEqual(onion.policy_decision, 'context_only_email_domain');
  const listed = find(result, 'domain', 'evil-phish.net');
  assert.ok(listed, 'listed address domain stays a candidate');
  assert.notEqual(listed.policy_decision, 'context_only_email_domain');
  const author = assertNotMember(result, 'domain', 'malware-traffic-analysis.net');
  assert.ok(author, 'author domain stays visible as a candidate');
  assert.equal(author.policy_decision, 'context_only_email_domain');
  assertNotMember(result, 'domain', 'boots.com');
});

test('D: placeholder URLs are not Indicators and are not truncated into ones', () => {
  const full = 'http://157.20.241.16:8080/ob/cronhit?h=jup_start_<rig>&persist=<method>';
  const linkid = 'https://securedoc.example.workers.dev/?id=<linkid:8>';
  const encoded = 'https://securedoc.example.workers.dev/h?id=%3Clinkid:8%3E';
  assert.equal(validateUrlCandidate(full).reason, 'template_placeholder');
  assert.equal(validateUrlCandidate(linkid).reason, 'template_placeholder');
  assert.equal(validateUrlCandidate(encoded).reason, 'template_placeholder');
  assert.equal(validateUrlCandidate('http://157.20.241.16:8080/jup.sh').ok, true);
  assert.equal(templateUrlSpanEnd(`prefix ${full} tail`, `prefix ${full}`.indexOf('<')), `prefix ${full}`.length);
  assert.equal(templateUrlSpanEnd('http://157.20.241.16:8080/jup.sh <br> next', 'http://157.20.241.16:8080/jup.sh'.length), 'http://157.20.241.16:8080/jup.sh'.length);

  const table = createTableBlock({
    id: 't1',
    headers: ['URL', 'Note'],
    rows: [
      ['hxxp://157.20.241[.]16:8080/jup.sh', 'payload'],
      [`hxxp://157.20.241[.]16:8080/ob/cronhit?h=jup_start_<rig>&persist=<method>`, 'template'],
      ['hxxps://securedoc.example.workers.dev/?id=<linkid:8>', 'template'],
      ['hxxps://securedoc.example.workers.dev/h?id=%3Clinkid:8%3E', 'template']
    ]
  });
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
    table,
    { id: 'row', type: 'list', text: 'hxxps://securedoc.example.workers.dev/s?id=<linkid:8>' }
  ]);
  assertMember(result, 'url', 'http://157.20.241.16:8080/jup.sh');
  const urls = result.candidates.filter((c) => c.candidate_type === 'url').map((c) => c.normalized_value);
  for (const value of urls) {
    assert.equal(/jup_start_|linkid|%3C/i.test(value), false, value);
  }
  assert.equal(urls.includes('http://157.20.241.16:8080/ob/cronhit?h=jup_start_'), false);

  // Matching semantics of a letter/hyphen query slot: the publisher documents
  // the path and leaves the runtime parameter unfilled. The concrete prefix is
  // the Indicator. A colon/digit placeholder, a mid-token placeholder, or a
  // second placeholder after '&' is a template and is not shortened into one.
  const slot = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'C2 Beaconing' },
    { id: 'p', type: 'paragraph', text: 'hxxps://kkwinapp[.]oss-cn-hongkong[.]aliyuncs[.]com/dow/upload?log=<data>' }
  ]);
  assertMember(slot, 'url', 'https://kkwinapp.oss-cn-hongkong.aliyuncs.com/dow/upload?log=');
  const formatUrl = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
    { id: 'row', type: 'list', text: 'hxxps://unityprogressall[.]org/imagecontent/getimgcontent.php?id=<target-email-address>' }
  ]);
  assertMember(formatUrl, 'url', 'https://unityprogressall.org/imagecontent/getimgcontent.php?id=');

  for (const raw of [
    'hxxps://host.example/path?id=<linkid:8>',
    'hxxps://host.example/path?id=%3Clinkid:8%3E',
    'hxxp://157.20.241[.]16:8080/ob/cronhit?h=jup_start_<rig>&persist=<method>',
    'hxxps://host.example/u/<user>/a.exe',
    'hxxps://host.example/p/[VictimGUID]/b.exe',
    'hxxps://host.example/dow/upload?log=<data>&extra=<more>'
  ]) {
    const r = extract([
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
      { id: 'row', type: 'list', text: raw }
    ]);
    const members = r.candidates.filter((c) => isReportIndicatorMember(c) && c.candidate_type === 'url');
    assert.equal(members.length, 0, raw);
  }

  // Limitation: any ?name=<IDENT> with only letters/hyphens/underscores keeps
  // the published prefix. Prefer colon/digit placeholders when the publisher
  // means an unfilled opaque id that must never match traffic.
  const letterSlot = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
    { id: 'row', type: 'list', text: 'hxxps://host.example/path?id=<Victim_GUID>' }
  ]);
  assertMember(letterSlot, 'url', 'https://host.example/path?id=');
});

test('E: refresh keeps an applied model label when the quote still grounds, and drops it when the quote is gone', () => {
  const table = createTableBlock({
    id: 't1',
    headers: ['Indicator', 'Context'],
    rows: [['157.20.241.16', 'C2']]
  });
  const extracted = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators' },
    table
  ]);
  const ip = assertMember(extracted, 'ip', '157.20.241.16');
  const row = {
    candidate_type: 'ip',
    normalized_value: '157.20.241.16',
    assessment: 'malicious',
    role: 'command_and_control',
    confidence: 0.91,
    evidence_text: ip.evidence_text,
    section: ip.section,
    block_id: ip.block_id,
    evidence: {
      decision_source: 'deterministic',
      policy_decision: 'explicit_report_assertion',
      ai_classification: { assessment: 'malicious', role: 'command_and_control', applied: true, supported: true, confidence: 0.91 }
    }
  };
  const updates = aiReplayUpdatesFromRows([row]);
  assert.equal(updates.length, 1);
  assert.equal(updates[0].replay, true);
  const kept = mergeAiCandidateUpdates(extracted.candidates, { candidate_updates: updates }, { document: extracted.document });
  const keptIp = kept.find((c) => c.normalized_value === '157.20.241.16');
  assert.equal(isReportIndicatorMember(keptIp), true);
  assert.equal(keptIp.membership_decision.rule_id, 'R10_publisher_assertion');
  assert.equal(keptIp.membership_decision.inputs.model_assessment, 'malicious');
  assert.equal(keptIp.ai_classification.applied, true);
  assert.equal(keptIp.ai_classification.stale, undefined);

  const staleUpdates = aiReplayUpdatesFromRows([{ ...row, evidence_text: 'this sentence is not in the document and names 157.20.241.16' }]);
  const dropped = mergeAiCandidateUpdates(extracted.candidates, { candidate_updates: staleUpdates }, { document: extracted.document });
  const droppedIp = dropped.find((c) => c.normalized_value === '157.20.241.16');
  assert.equal(isReportIndicatorMember(droppedIp), true);
  assert.equal(droppedIp.membership_decision.rule_id, 'R10_publisher_assertion');
  assert.equal(droppedIp.membership_decision.inputs.model_assessment, null);
  assert.equal(droppedIp.ai_classification.applied, false);
  assert.equal(droppedIp.ai_classification.stale, true);
  assert.equal(droppedIp.ai_classification.assessment, 'malicious');
});
