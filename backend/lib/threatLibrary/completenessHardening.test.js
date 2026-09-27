/**
 * IOC extraction completeness hardening (tl-candidates-v11 / threat_library_html_v3
 * / tl-zones-v3 / tl-type-resolver-v3).
 *
 * Synthetic fixtures for structural patterns seen in published threat
 * research — never copies of a real report, never real indicator values:
 *  - <br>-separated IOC appendix lines, multi-value table cells
 *  - nested per-type sub-headings with arbitrary labels, scheme-less URL rows
 *  - prose sample hashes vs legitimate components, request / fetch URLs
 *  - hosting-direction grammar, file extensions in TLD position
 *  - structural completeness diagnostics
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { parseHtml, textLinesOf, textOf } from './extract/htmlBlocks.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { interpretIocTable } from './tableSemantics.js';
import { classifySourceRelationDetail, isIndicatorValueLine, isIndicatorRowShape, describesBenignComponent } from './indicatorScope.js';
import { resolveDottedToken, hasDelegatedDnsSuffix, suffixStrength } from './observableTypeResolver.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import { structuralCompleteness } from './explicitTableCompleteness.js';
import { partitionCandidatesForAi } from './ai/analyze.js';

const URL = 'https://research.example/blog/synthetic-campaign/';
/** Deterministic synthetic digests (not real samples). */
const H = (seed, len = 64) => crypto.createHash(len === 32 ? 'md5' : 'sha256').update(`synthetic-sample-${seed}`).digest('hex');
const S1 = H(1);
const S2 = H(2);
const S3 = H(3);
const M1 = H(11, 32);
const M2 = H(12, 32);
const M3 = H(13, 32);
const M4 = H(14, 32);

const FILLER = Array.from({ length: 6 }, (_, i) =>
  `<p>Section ${i + 1} of the synthetic analysis describes the intrusion timeline, the operator tradecraft and the tooling observed across several victim environments in detail.</p>`
).join('\n');

function article(body) {
  return `<!doctype html><html lang="en"><head><title>Synthetic campaign analysis</title></head><body><article>
<h1>Synthetic campaign analysis</h1>
${FILLER}
${body}
</article></body></html>`;
}

function extract(body) {
  const r = extractCanonicalDocumentFromHtml(article(body), { url: URL, finalUrl: URL, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  const res = extractCandidatesWithDiagnostics(r.document, { sourceUrl: URL });
  return { ...res, document: r.document };
}

const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const isExplicit = (c) => Boolean(c) && c.assessment === 'malicious' && c.policy_decision === 'explicit_report_assertion' && c.ai_needed === false;

// ---------------------------------------------------------------------------
// 1–2. <br> line structure
// ---------------------------------------------------------------------------

test('<br> is a line boundary: textLinesOf splits, textOf keeps the single-line reading', () => {
  const dom = parseHtml(`<p><b>File Hashes (SHA256)<br></b>${S1} (a.exe)<br>${S2} (b.exe)</p>`);
  const p = dom.children[0];
  assert.deepEqual(textLinesOf(p), ['File Hashes (SHA256)', `${S1} (a.exe)`, `${S2} (b.exe)`]);
  assert.equal(textOf(p), `File Hashes (SHA256) ${S1} (a.exe) ${S2} (b.exe)`);
  // Author newlines are whitespace, never a line boundary.
  assert.deepEqual(textLinesOf(parseHtml('<p>one\nsentence\r\nwrapped</p>').children[0]), ['one sentence wrapped']);
});

test('<br>-separated hashes and URLs inside an IOC section are deterministic explicit assertions', () => {
  const { candidates, document } = extract(`
<h2>Appendix: IOCs</h2>
<p><b>File Hashes (SHA256)<br></b>${S1} (loader.exe)<br>${S2} (agent.exe)<br>${S3} (calc.exe)</p>
<p><b>URLs</b><br>hxxp://update-relay[.]online:80/api/gate.php<br>hxxp://sync-panel[.]store/api/poll.php</p>`);
  const lineBlocks = document.blocks.filter((b) => b.line_group);
  assert.ok(lineBlocks.length >= 5, 'each <br> line is its own block sharing a line_group');
  for (const h of [S1, S2, S3]) assert.ok(isExplicit(find(candidates, 'sha256', h)), `${h} explicit`);
  assert.ok(isExplicit(find(candidates, 'url', 'http://update-relay.online/api/gate.php')));
  assert.ok(isExplicit(find(candidates, 'url', 'http://sync-panel.store/api/poll.php')));
  assert.equal(partitionCandidatesForAi(candidates).toClassify.length, 0, 'nothing in the appendix needs the model');
});

test('<br> in ordinary narrative outside the IOC section never becomes an explicit assertion', () => {
  const { candidates } = extract(`
<h2>Execution flow</h2>
<p>The operator staged the implant on the file server.<br>It later reached out to relay-cache[.]online over HTTPS.<br>A second copy was written to disk.</p>
<h2>IOCs</h2>
<ul><li>${S1}</li><li>${S2}</li></ul>`);
  const d = find(candidates, 'domain', 'relay-cache.online');
  assert.ok(d, 'the narrative domain is still discovered');
  assert.equal(isExplicit(d), false, 'a <br> line of prose is not an indicator row');
  assert.notEqual(d.policy_decision, 'explicit_report_assertion');
});

test('a file-name annotation keeps a hash line a row; a second network observable does not', () => {
  assert.equal(isIndicatorRowShape(`${S1} (map.aspx)`, S1), true);
  assert.equal(isIndicatorRowShape(`${S1} - loader.exe`, S1), true);
  assert.equal(isIndicatorRowShape(`${S1} also seen at relay-cache.online`, S1), false);
  assert.equal(isIndicatorRowShape(`${S1} (${M1})`, S1), false);
});

test('email addresses on their own <br> lines never assert their mail domain as an IOC row', () => {
  const { candidates } = extract(`
<h2>IOCs</h2>
<p><b>C2 domains</b><br>panel-sync[.]online<br>relay-cache[.]online</p>
<p><b>Account emails</b><br>ops.team@gmail[.]com<br>admin.desk@hotmail[.]com</p>`);
  assert.ok(isExplicit(find(candidates, 'domain', 'panel-sync.online')));
  for (const d of ['gmail.com', 'hotmail.com']) {
    const c = find(candidates, 'domain', d);
    assert.ok(c, `${d} still discovered`);
    assert.equal(isExplicit(c), false, `${d} is the domain of an email address, not an asserted row`);
    assert.equal(c.occurrences.every((o) => o.form === 'email_domain' && o.asserted !== true), true);
  }
});

// ---------------------------------------------------------------------------
// 3–5. Multi-value table cells
// ---------------------------------------------------------------------------

test('multi-hash table cells verify the indicator column; every hash is an explicit row value', () => {
  const { candidates, diagnostics } = extract(`
<h2>Indicators of compromise</h2>
<table><tr><td>MD5</td><td>Description</td></tr>
<tr><td>${M1}<br>${M2}</td><td>Document</td></tr>
<tr><td>${M3}<br>${M4}</td><td>Template</td></tr></table>`);
  const t = diagnostics.explicit_tables;
  assert.equal(t.explicit_tables, 1);
  assert.equal(t.rows_valid, 2);
  for (const h of [M1, M2, M3, M4]) {
    const c = find(candidates, 'md5', h);
    assert.ok(isExplicit(c), `${h} explicit`);
    assert.equal(c.table_rows.length > 0, true);
  }
  assert.equal(diagnostics.structural_completeness.warning, false);
});

test('multi-URL table cells assert each URL', () => {
  const { candidates } = extract(`
<h2>Extracted C2s</h2>
<table><tr><th>Sample</th><th>C2</th></tr>
<tr><td>${S1}</td><td>hxxp://mail.relay-one[.]online/app/a.jsp<br>hxxp://www.relay-two[.]store/inc/b.php</td></tr>
<tr><td>${S2}</td><td>hxxp://www.relay-three[.]tech/list.php</td></tr></table>`);
  for (const u of ['http://mail.relay-one.online/app/a.jsp', 'http://www.relay-two.store/inc/b.php', 'http://www.relay-three.tech/list.php']) {
    assert.ok(isExplicit(find(candidates, 'url', u)), `${u} explicit`);
  }
});

test('a description cell with prose and one domain is never an indicator column', () => {
  const interp = interpretIocTable({
    id: 't1',
    table: {
      headers: ['Tool', 'Notes'],
      rows: [
        ['Loader', 'Contacts relay-cache.online every hour'],
        ['Stealer', 'Uploads archives to the operator'],
        ['Wiper', 'Destroys the MBR']
      ]
    }
  });
  assert.equal(interp.kind, 'not_ioc_table');
  assert.equal(interp.columns.find((c) => c.header === 'Notes').intent === 'indicator', false);
  // All-tokens rule: a mixed cell ("value (note)") is not a multi-value cell either.
  const mixed = interpretIocTable({ id: 't2', table: { headers: ['Name', 'Info'], rows: [['a', `${M1} dropped by the loader`], ['b', 'no value here']] } });
  assert.notEqual(mixed.columns.find((c) => c.header === 'Info').intent, 'indicator');
});

// ---------------------------------------------------------------------------
// 6–8. IOC section hierarchy, scheme-less URL rows
// ---------------------------------------------------------------------------

test('nested sub-headings with arbitrary labels stay inside the IOC section when indicator rows follow', () => {
  const { candidates } = extract(`
<h2>Indicators of Compromise (IOCs)</h2>
<h3>PDF Files</h3>
<ul><li>${S1}</li><li>${S2}</li></ul>
<h3>Qzx Stage Blobs</h3>
<ul><li>${S3}</li></ul>
<h3>URLs</h3>
<ul><li>quickdrop-cdn[.]online/fetch/stage1.u32</li><li>stagebox[.]store/Adobe.pdf</li></ul>
<h3>C2</h3>
<ul><li>panel-sync[.]online</li></ul>`);
  for (const h of [S1, S2, S3]) assert.ok(isExplicit(find(candidates, 'sha256', h)), `${h} explicit`);
  assert.ok(isExplicit(find(candidates, 'url', 'quickdrop-cdn.online/fetch/stage1.u32')), 'scheme-less URL row under a typed sub-heading');
  assert.ok(isExplicit(find(candidates, 'url', 'stagebox.store/Adobe.pdf')));
  assert.ok(isExplicit(find(candidates, 'domain', 'panel-sync.online')));
});

test('"About the Author" nested under the IOC section closes it: author prose is not IOC scope', () => {
  const { candidates, document } = extract(`
<h2>IOCs</h2>
<ul><li>${S1}</li><li>${S2}</li></ul>
<h3>About the Author</h3>
<p>The author previously wrote about campaign-archive[.]online and speaks at conferences about malware research.</p>`);
  assert.ok(isExplicit(find(candidates, 'sha256', S1)));
  const d = find(candidates, 'domain', 'campaign-archive.online');
  assert.ok(d);
  assert.equal(isExplicit(d), false);
  assert.equal(d.assessment, 'context_only');
  const authorPara = document.blocks.find((b) => /previously wrote/.test(b.text));
  assert.ok(authorPara);
});

test('a prose sub-heading suspends the section; a later sibling sub-list resumes it', () => {
  const { candidates } = extract(`
<h2>IOCs</h2>
<h3>Hashes</h3>
<ul><li>${S1}</li></ul>
<h3>Notes on attribution</h3>
<p>These samples overlap with an earlier cluster, although attribution remains tentative.</p>
<h3>Payload locations</h3>
<ul><li>stagebox[.]store/p/blob.bin</li></ul>`);
  assert.ok(isExplicit(find(candidates, 'url', 'stagebox.store/p/blob.bin')));
});

test('scheme-less host/path URL values are indicator value lines; relative / filesystem paths are not', () => {
  assert.equal(isIndicatorValueLine('quickdrop-cdn[.]online/fetch/stage1.u32'), true);
  assert.equal(isIndicatorValueLine('• stagebox.store/Adobe.pdf'), true);
  assert.equal(isIndicatorValueLine('/wp-admin/admin-ajax.php'), false);
  assert.equal(isIndicatorValueLine('C:/inetpub/wwwroot/map.aspx'), false);
  assert.equal(isIndicatorValueLine('the file lives at stagebox.store/Adobe.pdf today'), false);
});

// ---------------------------------------------------------------------------
// 9–12. Prose hashes / URLs: model vs deterministic
// ---------------------------------------------------------------------------

test('a prose sample hash with no decisive relation reaches the model even when an IOC section exists', () => {
  const { candidates } = extract(`
<h2>Attachment analysis</h2>
<p>Our analysis focuses on the lure attachment whose MD5 hash is ${M1}</p>
<h2>IOCs</h2>
<ul><li>relay-cache[.]online</li><li>panel-sync[.]online</li></ul>`);
  const c = find(candidates, 'md5', M1);
  assert.equal(c.policy_decision, 'ai_needed_prose_sample_hash');
  assert.equal(c.ai_needed, true);
  assert.notEqual(c.assessment, 'context_only');
  // The model's answer is applied (not ignored by the curated-scope rule).
  const merged = mergeAiCandidateUpdates(candidates, {
    candidate_updates: [{ candidate_type: 'md5', normalized_value: M1, assessment: 'malicious', role: 'malware_sample', confidence: 0.8 }]
  });
  const m = find(merged, 'md5', M1);
  assert.equal(m.assessment, 'malicious');
  assert.equal(m.decision_source, 'ai');
  assert.equal(m.ai_needed, false);
});

test('a legitimate component hash is deterministic context; the malicious neighbour is not tainted', () => {
  const { candidates } = extract(`
<h2>Loader</h2>
<p>The chain starts when a legitimate component of Vendor Suite (HOSTAPP.exe, MD5 ${M1}) loads plug.dll (MD5 ${M2}), which then takes over execution.</p>
<h2>IOCs</h2>
<table><tr><td>${M2}</td><td>Malicious DLL (plug.dll)</td></tr><tr><td>${M3}</td><td>Companion file</td></tr></table>`);
  const legit = find(candidates, 'md5', M1);
  assert.equal(legit.assessment, 'context_only');
  assert.equal(legit.policy_decision, 'context_only_benign_component');
  assert.equal(legit.ai_needed, false);
  // Even an AI "malicious" answer cannot promote it.
  const merged = mergeAiCandidateUpdates(candidates, {
    candidate_updates: [{ candidate_type: 'md5', normalized_value: M1, assessment: 'malicious', role: 'malware_sample', confidence: 0.99 }]
  });
  assert.equal(find(merged, 'md5', M1).assessment, 'context_only');
  assert.ok(isExplicit(find(candidates, 'md5', M2)));
  // Maliciousness cues negate benign wording.
  assert.equal(describesBenignComponent('a trojanized copy of the legitimate updater (MD5 OBSERVABLE) was delivered'), false);
  assert.equal(describesBenignComponent('a legitimate-looking installer (OBSERVABLE)'), false);
  assert.equal(describesBenignComponent('the legitimate, signed binary OBSERVABLE is abused for side-loading'), false);
});

test('request / fetch / download / connect / retrieve phrasings are operational relations', () => {
  const rel = (text, value) => classifySourceRelationDetail(text, { zone: 'report_body', value });
  const u = 'https://files.cdn-host.online/s/k2/cfg.txt?dl=0';
  assert.equal(rel(`Step 1: the stager sends a GET request to the URL "${u}".`, u).marker, 'operational');
  assert.equal(rel(`The beacon issues a POST request to ${u} every minute.`, u).marker, 'operational');
  const v = 'https://cloud.stagebox.store/';
  assert.equal(rel('The implant then fetches a config it stores locally as cfg.dat from hxxps://cloud.stagebox[.]store, which we could not retrieve.', v).marker, 'operational');
  assert.equal(rel('The dropper downloads the next stage from https://get.stagebox.store/n.bin before exiting.', 'https://get.stagebox.store/n.bin').marker, 'operational');
  assert.equal(rel('The loader retrieves its configuration from https://cfg.stagebox.store/c.json.', 'https://cfg.stagebox.store/c.json').marker, 'operational');
  assert.equal(rel('The RAT connects to relay-cache.online on port 443.', 'relay-cache.online').marker, 'operational');
  // Documentation links stay undecided (and never reach the model in curated reports).
  assert.equal(rel('Apply the patch and follow https://docs.vendor-site.online/hardening.', 'https://docs.vendor-site.online/hardening').marker, 'none');
});

test('prose request / fetch URLs reach the model in a curated report; documentation URLs do not', () => {
  const { candidates } = extract(`
<h2>Network communication</h2>
<p>Step 1: the stager sends a GET request to the URL "https://files.cdn-host.online/s/k2/cfg.txt?dl=0".</p>
<p>Administrators should follow https://docs.vendor-site.online/hardening for mitigation guidance.</p>
<h2>IOCs</h2>
<ul><li>relay-cache[.]online</li><li>panel-sync[.]online</li></ul>`);
  const toClassify = new Set(partitionCandidatesForAi(candidates).toClassify.map((c) => `${c.candidate_type}:${c.normalized_value}`));
  assert.equal(toClassify.has('url:https://files.cdn-host.online/s/k2/cfg.txt?dl=0'), true);
  assert.equal(toClassify.has('url:https://docs.vendor-site.online/hardening'), false);
});

test('a defanged URL deep in a long paragraph is classified from its own clause', () => {
  const lead = 'The implant is delivered through a chain of loaders that we describe in detail below, including its side-loading behaviour, its anti-analysis checks and its persistence mechanism. ';
  const { candidates } = extract(`
<h2>Second stage</h2>
<p>${lead.repeat(3)}The implant then fetches a config it stores locally as cfg.dat from hxxps://cloud.stagebox[.]store, which we could not retrieve.</p>
<h2>IOCs</h2>
<ul><li>relay-cache[.]online</li><li>panel-sync[.]online</li></ul>`);
  const u = find(candidates, 'url', 'https://cloud.stagebox.store/');
  assert.ok(u);
  assert.equal(u.occurrences[0].relation_marker, 'operational');
  assert.equal(u.ai_needed, true, 'an operational prose URL reaches the model');
  assert.notEqual(u.assessment, 'context_only');
});

test('hosting / actor-usage / attribution phrasings and a same-kind anaphor route prose infrastructure to the model', () => {
  const rel = (text, value) => classifySourceRelationDetail(text, { zone: 'report_body', value }).marker;
  assert.equal(rel('The IP address 45.61.10.20 has lately been used to host the domain careers-portal[.]online.', '45.61.10.20'), 'operational');
  assert.equal(rel('The domain www.dev-map[.]online was hosted on this IP address in Jan 2021, which was attributed to the actor.', 'www.dev-map.online'), 'operational');
  assert.equal(rel('The domain relay-cache[.]online was attributed to APT99 by several vendors.', 'relay-cache.online'), 'operational');
  assert.equal(rel('One address stood out: 45.61.10.21. This IP address was previously used by a state-sponsored APT threat actor.', '45.61.10.21'), 'operational');
  // Negative controls: passive-DNS listing, anaphor about something benign, another kind of anaphor.
  assert.equal(rel('Passive DNS shows two other resolutions: 45.61.10.22 in November and 45.61.10.23 in September.', '45.61.10.22'), 'none');
  assert.equal(rel('We saw 45.61.10.24 in the logs. This IP address belongs to a university network.', '45.61.10.24'), 'none');
  assert.equal(rel('We saw 45.61.10.25 in the logs. This domain was used by the threat actor.', '45.61.10.25'), 'none');
});

// ---------------------------------------------------------------------------
// 13. Hosting direction
// ---------------------------------------------------------------------------

test('hosting grammar: the hosted object is never the provider; the rented host is', () => {
  const rel = (text, value) => classifySourceRelationDetail(text, { zone: 'report_body', value });
  const hosted = 'The IP address 45.61.10.20 was recently used to host the domain - careers-portal[.]online which was attributed to the actor.';
  assert.notEqual(rel(hosted, 'careers-portal.online').relation, 'provider_service');
  assert.equal(rel(hosted, 'careers-portal.online').marker, 'operational');
  const rented = 'The actor rented cheapvps-hosting.online to host phishing-kit.store pages.';
  assert.equal(rel(rented, 'cheapvps-hosting.online').relation, 'provider_service');
  assert.notEqual(rel(rented, 'phishing-kit.store').relation, 'provider_service');
  assert.equal(rel('payload-cdn.online was used to host payloads for the second stage.', 'payload-cdn.online').marker, 'operational');
  // Unchanged: an acquisition statement about a provider is still provider context.
  assert.equal(rel('The group purchased servers from cheapvps-hosting.online.', 'cheapvps-hosting.online').relation, 'provider_service');
});

// ---------------------------------------------------------------------------
// 14–16. File extensions in TLD position vs delegated TLDs
// ---------------------------------------------------------------------------

test('a .chm file name is never a domain candidate', () => {
  const { candidates } = extract(`
<h2>IOCs</h2>
<table><tr><td>Original Name</td><td>Translated Name</td></tr>
<tr><td>확인 안내문.chm<br>Token Mint Guide.chm</td><td>Guide.chm<br>Token Mint Guide.chm</td></tr></table>
<ul><li>${M1}</li><li>${M2}</li></ul>`);
  assert.equal(candidates.some((c) => c.candidate_type === 'domain' && /\.chm$/.test(c.normalized_value)), false);
  // No domain identity exists, so a model update cannot promote one.
  const merged = mergeAiCandidateUpdates(candidates, {
    candidate_updates: [{ candidate_type: 'domain', normalized_value: 'minting.chm', assessment: 'malicious', role: 'malware_sample', confidence: 0.9 }]
  });
  assert.equal(merged.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'minting.chm'), false);
});

test('.hta / .iqy / .chm are not delegated suffixes; .one is a delegated gTLD decided by context', () => {
  for (const t of ['Minting.chm', 'loader.hta', 'query.iqy']) {
    assert.equal(hasDelegatedDnsSuffix(t), false, t);
    assert.equal(resolveDottedToken(t, {}).kind, 'technical_artifact', t);
    assert.equal(resolveDottedToken(t, { surroundingText: `the victim opened ${t} from the archive` }).kind, 'technical_artifact', t);
  }
  assert.equal(suffixStrength(['minting', 'chm']), 'weak');
  // `.one` is delegated: a OneNote file name needs a file label / artifact context.
  assert.equal(hasDelegatedDnsSuffix('Invoice.one'), true);
  assert.equal(resolveDottedToken('Invoice.one', { typeLabel: 'File Name' }).kind, 'technical_artifact');
  assert.equal(resolveDottedToken('Invoice.one', { surroundingText: 'the attachment file name Invoice.one was opened' }).kind, 'technical_artifact');
  // An undelegated suffix the source asserts as network infrastructure is still a domain (signal, not gate).
  assert.equal(resolveDottedToken('c2.staging.corpnet', { strongZone: true, form: 'list_row' }).kind, 'domain');
  assert.equal(resolveDottedToken('c2.panel.bit', {}).kind, 'domain', 'alternative-root suffix');
  assert.equal(resolveDottedToken('hidden5xyz.onion', {}).kind, 'domain');
});

test('call syntax at a dotted token is code even beside network words', () => {
  const clause = 'The page script sends the victim to an attacker-controlled URL via window.location.replace()';
  const r = resolveDottedToken('window.location.replace', { surroundingText: clause });
  assert.equal(r.kind, 'technical_artifact');
  assert.equal(r.reason, 'code_call');
  assert.equal(r.artifact_kind, 'code');
  // A DNS-shaped host followed by a parenthetical note is still a host.
  assert.equal(resolveDottedToken('panel-sync.com', { surroundingText: 'the RAT connects to panel-sync.com(port 443)' }).kind, 'domain');
  const { candidates } = extract(`
<h2>Redirector</h2>
<p>The page script sends the victim to an attacker-controlled URL via window.location.replace()</p>
<h2>IOCs</h2>
<ul><li>relay-cache[.]online</li><li>panel-sync[.]online</li></ul>`);
  assert.equal(candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'window.location.replace'), false);
});

test('modern delegated TLDs remain domains', () => {
  for (const t of ['example-shop.online', 'copycat-frag.store', 'relay-one.tech', 'cloud-centre.xyz', 'mailhelp.email', 'mail-verify.link', 'brand-deal.kaufen', 'xn--80ak6aa92e.xn--p1ai']) {
    assert.equal(hasDelegatedDnsSuffix(t), true, t);
    assert.equal(resolveDottedToken(t, {}).kind, 'domain', t);
  }
});

// ---------------------------------------------------------------------------
// 17–18. Structural completeness diagnostics
// ---------------------------------------------------------------------------

test('diagnostic: IOC-section table / prose block that degraded to the AI path is reported', () => {
  const { diagnostics } = extract(`
<h2>Indicators of compromise</h2>
<table><tr><td>Sample</td><td>Info</td></tr>
<tr><td>${M1} loader</td><td>stage one</td></tr>
<tr><td>${M2} dropper</td><td>stage two</td></tr></table>
<p>During the intrusion we also observed ${M3} and ${M4} on two further hosts.</p>`);
  const d = diagnostics.structural_completeness;
  assert.equal(d.warning, true);
  assert.ok(d.tables_not_interpreted.some((t) => t.zone === 'explicit_ioc_section' && t.ioc_shaped_values >= 2));
  assert.ok(d.degraded_blocks.some((b) => b.ai_needed_values >= 2 && b.zone === 'explicit_ioc_section'));
  assert.ok(d.degraded_candidates >= 2);
});

test('diagnostic: ordinary narrative outside curated sections never warns', () => {
  const { diagnostics } = extract(`
<h2>Analysis</h2>
<p>The first stage (${M1}) and the second stage (${M2}) were both observed in March.</p>
<table><tr><td>Tool</td><td>Notes</td></tr><tr><td>Loader</td><td>writes ${M3} to disk</td></tr></table>`);
  assert.equal(diagnostics.structural_completeness.warning, false);
  // Pure function: empty input is quiet.
  assert.equal(structuralCompleteness([], []).warning, false);
});
