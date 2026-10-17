/**
 * Nine-report audit regressions (tl-candidates-v30 / tl-type-resolver-v10 /
 * tl-section-tree-v3 / tl-scope-engine-section-tree-v2 / tl-quality-v7 /
 * tl-evidence-integrity-v1). Generic shapes of the confirmed production
 * defects, with synthetic values — no publisher, report or value condition:
 *
 * A. Model output never silently replaces publisher evidence; unsupported
 *    model escalations are not applied; publisher stance beats model labels.
 * B. A formal IOC section that only points elsewhere delegates authority to
 *    the publisher's body assertions instead of suppressing all of them.
 * C. Hash-shaped non-file digests (build-id, certificate, vhash, keys, trivial
 *    digests) are context, never file-hash Indicators; special-use and
 *    undelegated host names are not network Indicators.
 * D. Dual-use / "not inherently malicious" publisher stances, detection-rule
 *    captions and platform-service mentions assert nothing malicious.
 * E. `host:port` is a network endpoint, not a config assignment.
 * F. Quality v7 makes each class visible without changing membership.
 *
 * The section-tree engine is the production engine; this file pins it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates, mergeAiCandidateUpdates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { QUALITY_CODES, assessPostMergeQuality } from './extractionQuality.js';
import { classifyHexDigest, DIGEST_KINDS, wellKnownDigest } from './digestSemantics.js';
import { groundAiCandidateUpdate, indexDocumentBlocks, normalizeEvidenceText } from './evidenceIntegrity.js';
import { isDetectionAlertCaption, textDescribesValueAsBenign, classifySourceRelationDetail } from './indicatorScope.js';
import { extractCandidatesWithDiagnostics, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { OBSERVABLE_TYPE_RESOLVER_VERSION } from './observableTypeResolver.js';
import { SECTION_TREE_VERSION, SECTION_TREE_SCOPE_ENGINE_VERSION } from './sectionTree/version.js';
import { annotateSectionTree } from './sectionTree/annotate.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/nine-report-audit/';
const S1 = '1'.repeat(63) + 'a';
const S2 = '2'.repeat(63) + 'b';
const S3 = '3'.repeat(63) + 'c';
const SHA1 = '4'.repeat(39) + 'd';
const SHA1B = '5'.repeat(39) + 'e';
const M1 = '6'.repeat(31) + 'f';
const M2 = '7'.repeat(31) + 'a';

function run(inner, { source = SOURCE } = {}) {
  const html = `<!doctype html><html lang="en"><head><title>Audit</title></head><body><article>
<h1>Campaign analysis</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
${inner}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: source, finalUrl: source, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: source }, r.document);
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const members = (x) => x.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();
const find = (x, value) => x.candidates.find((c) => c.normalized_value === value);
const codes = (x) => [...new Set(x.diagnostics.quality.warnings.map((w) => w.code))].sort();

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v30');
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v10');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v3');
  assert.equal(SECTION_TREE_SCOPE_ENGINE_VERSION, 'tl-scope-engine-section-tree-v2');
});

// ---------------------------------------------------------------- C. digests

test('C: the governing label decides what a hex value is', () => {
  const k = (t, v) => classifyHexDigest(t, v).kind;
  assert.equal(k(`File type: ELF 64-bit LSB executable, statically linked, BuildID[sha1]=${SHA1}, for GNU/Linux 3.2.0`, SHA1), DIGEST_KINDS.BUILD_ID);
  assert.equal(k(`APK signing certificate (SHA-1 thumbprint): ${SHA1}`, SHA1), DIGEST_KINDS.CERTIFICATE);
  assert.equal(k(`TLS certificate (SHA256 hash): ${S1}`, S1), DIGEST_KINDS.CERTIFICATE);
  assert.equal(k(`VHash: ${M1}`, M1), DIGEST_KINDS.SIMILARITY);
  assert.equal(k(`Imphash: ${M1}`, M1), DIGEST_KINDS.SIMILARITY);
  assert.equal(k(`Configuration(c2=b'x', contract_return_aes_key='${S1}')`, S1), DIGEST_KINDS.CRYPTO_KEY);
  assert.equal(k(`RC4 key: ${M1}`, M1), DIGEST_KINDS.CRYPTO_KEY);
  // File hashes keep their reading.
  for (const [t, v] of [[`SHA256 hash: ${S1}`, S1], [`MD5 hash: ${M1}`, M1], [S1, S1], [`Sample sha-256: ${S1}`, S1],
    [`SHA-256 hash | ${S1} | Core injector`, S1], [`loader.exe ${M1}`, M1], [`certificate-signed sample SHA256: ${S1}`, S1],
    [`For this analysis, we examine the following script: ${S1}.`, S1]]) {
    assert.equal(k(t, v), DIGEST_KINDS.FILE, t);
  }
});

test('C: digests of trivial inputs are well-known, never samples', () => {
  const h = (alg, s) => crypto.createHash(alg).update(s).digest('hex');
  assert.ok(wellKnownDigest(h('sha256', '123456')));
  assert.ok(wellKnownDigest(h('md5', '')));
  assert.ok(wellKnownDigest(h('sha1', 'password')));
  assert.equal(wellKnownDigest(S1), null);
  assert.equal(classifyHexDigest(`SHA-256 hash | ${h('sha256', '123456')} | shared secret`, h('sha256', '123456')).kind, DIGEST_KINDS.WELL_KNOWN);
});

test('C: key-value appendix records keep file hashes and demote build-ids / certificates / vhash', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<p>SHA256 hash: ${S1}</p><p>MD5 hash: ${M1}</p>
<p>File type: ELF 32-bit LSB executable, ARM, statically linked, BuildID[sha1]=${SHA1}, not stripped</p>
<p>SHA256 hash: ${S2}</p>
<p>VHash: ${M2}</p>
<p>APK signing certificate (SHA-1 thumbprint): ${SHA1B}</p>
<p>TLS certificate (SHA256 hash): ${S3}</p>
<p>IP address: 203.0.113[.]44</p>
<h2>Additional Resources</h2><p>Further reading.</p>`);
  assert.deepEqual(members(x), [`ip:203.0.113.44`, `md5:${M1}`, `sha256:${S1}`, `sha256:${S2}`].sort());
  for (const v of [SHA1, SHA1B, M2, S3]) {
    const c = find(x, v);
    assert.equal(c.candidate_type, 'technical_artifact', v);
    assert.equal(c.is_ioc, false, v);
    assert.ok(c.digest_kind, v);
  }
  assert.ok(codes(x).includes(QUALITY_CODES.NON_FILE_DIGEST_RECLASSIFIED));
  // A reclassified explicit row is not a dropped one.
  assert.deepEqual(x.diagnostics.explicit_tables.dropped_asserted_identities.filter((d) => d.value === SHA1), []);
});

test('C: special-use local names and undelegated undeclared hosts are never network Indicators', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<p><b>Domains:</b></p>
<ul><li>c2.campaign-example.local - DNS fall-back C2 domain</li><li>relay-panel-example[.]com - C2 panel</li></ul>
<p><b>Host Indicators:</b></p>
<ul><li>sd-agent.service - Systemd persistence service name</li></ul>
<h2>Additional Resources</h2><p>Further reading.</p>`);
  const m = members(x);
  assert.ok(m.includes('domain:relay-panel-example.com'));
  assert.ok(!m.includes('domain:c2.campaign-example.local'));
  assert.ok(!m.includes('domain:sd-agent.service'));
  assert.equal(find(x, 'c2.campaign-example.local').policy_decision, 'context_only_non_actionable_local');
  assert.match(find(x, 'sd-agent.service').policy_decision, /^ioc_excluded_(?:undelegated_suffix|non_network)$/);
  assert.equal(find(x, 'sd-agent.service').is_ioc, false);
});

test('C: a URL is no more actionable than its local / reserved host', () => {
  const x = run(`<p>The script runs cloudflared tunnel --url http://localhost:8080 and also polls http://10.0.0.5/status internally.</p>`);
  assert.equal(members(x).some((m) => m.startsWith('url:http://localhost') || m.startsWith('url:http://10.0.0.5')), false);
});

// ---------------------------------------------------------------- D. stance

test('D: a publisher dual-use stance keeps tunnel brokers out of MODE B Indicators', () => {
  const x = run(`<p>Known dual-use tools in this window include tunnel-broker-example[.]run (free SSH tunnels on *.broker-sub-example[.]life) and an ngrok binary.</p>
<p>Unusual Network Connection to Suspicious Web Service: cloudflared to api.broker-sub-example[.]life (signed binary).</p>
<p>The loader beacons to beacon-relay-example[.]net every minute.</p>`);
  const m = members(x);
  assert.ok(!m.includes('domain:tunnel-broker-example.run'), m.join(','));
  assert.ok(!m.includes('domain:broker-sub-example.life'), m.join(','));
  assert.ok(!m.includes('domain:api.broker-sub-example.life'), m.join(','));
  assert.ok(m.includes('domain:beacon-relay-example.net'), 'a real operational relation stays a MODE B Indicator');
});

test('D: "not inherently malicious" in an IOC row is a benign stance; a malicious row stays', () => {
  const x = run(`<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Value</th><th>Description</th></tr></thead><tbody>
<tr><td>Domain</td><td>api.messenger-platform-example[.]org</td><td>API endpoint for exfiltration/C2 (used in DLL). (This domain is not inherently malicious, but could be viewed as part of a potential pattern of suspicious activity.)</td></tr>
<tr><td>Domain</td><td>update-launcher-example[.]xyz</td><td>C2 domain (retrieved from contract)</td></tr>
</tbody></table>
<h2>Additional Resources</h2><p>Further reading.</p>`);
  const m = members(x);
  assert.ok(!m.includes('domain:api.messenger-platform-example.org'), m.join(','));
  assert.ok(m.includes('domain:update-launcher-example.xyz'));
  assert.equal(find(x, 'api.messenger-platform-example.org').policy_decision, 'context_only_benign_component');
});

test('D: stance helpers — hedges, contrast, captions, service nouns', () => {
  assert.equal(textDescribesValueAsBenign('X | api.example-msg.org | (This domain is not inherently malicious.)', ['api.example-msg.org']), true);
  assert.equal(textDescribesValueAsBenign('The attackers abused the legitimate service api.example-msg.org to host payloads.', ['api.example-msg.org']), false);
  assert.equal(textDescribesValueAsBenign('Samples hardcode eth.rpc-example.com as an additional endpoint alongside the five legitimate providers.', ['eth.rpc-example.com']), false);
  assert.equal(isDetectionAlertCaption('Unusual Network Connection to Suspicious Web Service: cloudflared to OBSERVABLE (signed).'), true);
  assert.equal(isDetectionAlertCaption('The malware connects to OBSERVABLE: a C2 server.'), false);
  // "Service" is a noun, not the verb "served".
  const r = classifySourceRelationDetail('Suspicious Web Service records: cloudflared to api.example-tunnel.com', { value: 'api.example-tunnel.com', zone: 'report_body' });
  assert.notEqual(r.marker, 'operational');
  // "abuse of the public X service" names a provider platform.
  const p = classifySourceRelationDetail('The payload hosting combines attacker-controlled domains with abuse of the public archive-example.org service.', { value: 'archive-example.org', zone: 'report_body' });
  assert.equal(p.relation, 'provider_service');
});

// ---------------------------------------------------------------- E. host:port

test('E: host:port is a network endpoint; config assignments stay artifacts', () => {
  const one = (t) => extractCandidatesWithDiagnostics({ meta: {}, blocks: [{ id: 'b1', type: 'paragraph', text: t }] }, {})
    .candidates.filter((c) => c.candidate_type === 'domain').map((c) => c.normalized_value);
  assert.deepEqual(one('The C2 is badhost.campaign-example[.]xyz:443 here.'), ['badhost.campaign-example.xyz']);
  assert.deepEqual(one("Configuration(c2=b'polygon.campaign-example[.]xyz:443', key=b'0x1')"), ['polygon.campaign-example.xyz']);
  assert.deepEqual(one('evil-host-example[.]com:8443 - C2 server'), ['evil-host-example.com']);
  assert.deepEqual(one('server.port: 8080'), []);
  assert.deepEqual(one('"app.config": 12'), []);
  assert.deepEqual(one('settings.timeout=30'), []);
  const ep = extractCandidatesWithDiagnostics({ meta: {}, blocks: [{ id: 'b1', type: 'paragraph', text: 'C2: relay-example[.]com:8443' }] }, {})
    .candidates.find((c) => c.normalized_value === 'relay-example.com');
  assert.deepEqual(ep.parsed.ports, [8443]);
});

test('E: URL templates and code interpolation are not resources', () => {
  const x = run(`<p>The extension requests https://qr-example.com/qrcode/api/v1/read?domain=\${encodeURIComponent(domain)} for each page.</p>
<p>Payload template: hxxps://payload-example[.]store/5c92d3b8/{campaignId}</p>`);
  const urls = x.candidates.filter((c) => c.candidate_type === 'url').map((c) => c.normalized_value);
  assert.ok(urls.includes('https://qr-example.com/qrcode/api/v1/read?domain='), urls.join(','));
  assert.equal(urls.some((u) => /campaign/i.test(u) && /payload-example/.test(u) && find(x, u).is_ioc !== false && isReportIndicatorMember(persisted(find(x, u)))), false);
});

// ---------------------------------------------------------------- B. delegated scope

const DELEGATED_BODY = `
<p>The loader downloads the installer from hxxps://stage-example[.]site/generate?id=7, while the RunPE module comes from a JPEG carrier.</p>
<p>In this campaign, the payloads communicate with the following C2 endpoints: 198.51.100[.]21:4782 and 198.51.100[.]22:443.</p>
<p>For this analysis, we examine the following script: ${S1}.</p>
<p>Wave A. ${S2} First observed on June 22, it downloads and executes a PowerShell script.</p>
<p>The infrastructure combines attacker-controlled domains with abuse of the public archive-example.org service. Results were compared with news-example[.]com coverage.</p>
<table><thead><tr><th>Campaign</th><th>Period</th><th>Key infrastructure</th></tr></thead><tbody>
<tr><td>Wave A</td><td>June</td><td>stage-example[.]site, 198.51.100[.]23</td></tr>
<tr><td>Wave B</td><td>August</td><td>relay-example[.]online</td></tr>
</tbody></table>
<table><thead><tr><th>Transaction</th><th>Variable-name</th><th>Value</th></tr></thead><tbody>
<tr><td>0x05ddd2131556d71352f5a10213fb1705b81dbd8d2f86fbe528a8a4be1de7d2e9</td><td>config["main"]</td><td>config-only-example[.]store</td></tr>
</tbody></table>`;

test('B: an IOC section that only points elsewhere delegates authority to body assertions', () => {
  const x = run(`${DELEGATED_BODY}
<h2>Indicators of compromise</h2>
<p>These indicators are also available for download here.</p>
<h2>References</h2><ul><li>https://reference-example.org/paper</li></ul>`);
  const m = members(x);
  for (const want of ['url:https://stage-example.site/generate?id=7', 'ip:198.51.100.21', 'ip:198.51.100.22', `sha256:${S1}`, `sha256:${S2}`,
    'domain:stage-example.site', 'ip:198.51.100.23', 'domain:relay-example.online']) {
    assert.ok(m.includes(want), `${want} missing from ${m.join(',')}`);
  }
  for (const not of ['domain:archive-example.org', 'domain:news-example.com', 'domain:config-only-example.store', 'url:https://reference-example.org/paper']) {
    assert.ok(!m.includes(not), `${not} must not be an Indicator`);
  }
  assert.equal(x.diagnostics.scope_engine.delegated_scope, true);
  assert.ok(codes(x).includes(QUALITY_CODES.DELEGATED_AUTHORITY_APPLIED));
  assert.ok(codes(x).includes(QUALITY_CODES.AUTHORITATIVE_SECTION_EMPTY));
});

test('B: a non-empty IOC section keeps normal MODE A (no delegation, body stays narrative)', () => {
  const x = run(`${DELEGATED_BODY}
<h2>Indicators of compromise</h2>
<ul><li>203.0.113[.]99</li></ul>
<h2>References</h2><p>Further reading.</p>`);
  assert.deepEqual(members(x), ['ip:203.0.113.99']);
  assert.equal(x.diagnostics.scope_engine.delegated_scope, false);
});

test('B: a pointer sentence carrying a link is not an inventory; a real IOC row is', () => {
  const pointer = annotateSectionTree({ blocks: [
    { id: 'p0', type: 'paragraph', text: 'The loader beacons to 198.51.100.40:443.' },
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    { id: 'p1', type: 'paragraph', text: 'All observables are available for download in our GitHub repository: https://github.com/vendor-example/iocs' }
  ] });
  assert.equal(pointer.meta.delegated_scope, true);
  assert.equal(pointer.blocks.find((b) => b.id === 'p0').tree_zone, 'delegated_ioc_scope');
  const real = annotateSectionTree({ blocks: [
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    { id: 'p1', type: 'paragraph', text: '198.51.100[.]41' }
  ] });
  assert.equal(real.meta.delegated_scope, false);
});

// ---------------------------------------------------------------- A. evidence integrity

const DOC = {
  blocks: [
    { id: 'b1', type: 'paragraph', text: "The loader was configured with subdomains of 'beacon-relay-example[.]org' as a C&C." },
    { id: 'b2', type: 'paragraph', text: 'Unrelated paragraph about the victimology of the campaign.' }
  ]
};
const CAND = { candidate_type: 'domain', normalized_value: 'beacon-relay-example.org', original_value: 'beacon-relay-example[.]org' };

test('A: grounding — verbatim quote, paraphrase, fabricated citation, uncited reading', () => {
  const blocks = indexDocumentBlocks(DOC);
  assert.equal(normalizeEvidenceText("‘x[.]com’ — hxxp"), 'x.com - http');
  const verbatim = groundAiCandidateUpdate(CAND, { evidence_text: 'configured with subdomains of beacon-relay-example[.]org as a C&C' }, blocks);
  assert.equal(verbatim.quote, 'grounded');
  assert.equal(verbatim.supported, true);
  const paraphrase = groundAiCandidateUpdate(CAND, { evidence_text: 'The report lists beacon-relay-example.org as the main C2 server of the actor.' }, blocks);
  assert.equal(paraphrase.quote, 'ungrounded');
  assert.equal(paraphrase.supported, false);
  const wrongBlock = groundAiCandidateUpdate(CAND, { evidence_block_ids: ['b2'] }, blocks);
  assert.equal(wrongBlock.cited_block, 'value_absent');
  assert.equal(wrongBlock.supported, false);
  const missingBlock = groundAiCandidateUpdate(CAND, { evidence_block_ids: ['b99'] }, blocks);
  assert.equal(missingBlock.supported, false);
  assert.equal(groundAiCandidateUpdate(CAND, {}, blocks).supported, true, 'an uncited reading of the candidate context is supported');
});

test('A: model output never overwrites publisher evidence; unsupported escalation is not applied', () => {
  const x = run(`<p>Background note: beacon-relay-example[.]org appeared in passive DNS.</p><p>Unrelated paragraph about victims.</p>`);
  const before = find(x, 'beacon-relay-example.org');
  const anchor = before.evidence_text;
  const [merged] = mergeAiCandidateUpdates([before], {
    candidate_updates: [{
      candidate_type: 'domain', normalized_value: 'beacon-relay-example.org', assessment: 'malicious', role: 'command_and_control',
      confidence: 0.95, evidence_text: 'Cloudflare-style tunnel names are used for C2 control-plane communication.'
    }]
  }, { document: x.document });
  assert.equal(merged.evidence_text, anchor, 'publisher excerpt kept');
  assert.deepEqual(merged.publisher_evidence, { text: anchor, block_id: before.block_id });
  assert.equal(merged.ai_evidence_rejected.reason, 'ungrounded');
  assert.equal(merged.ai_classification.applied, false);
  assert.notEqual(merged.assessment, 'malicious');
  const record = buildCandidateEvidenceRecord(merged);
  assert.ok(record.publisher_evidence && record.ai_classification && record.ai_evidence_rejected);
  const quality = assessPostMergeQuality([merged]).map((w) => w.code).sort();
  assert.deepEqual(quality, [QUALITY_CODES.AI_ESCALATION_UNSUPPORTED, QUALITY_CODES.AI_EVIDENCE_UNGROUNDED].sort());
});

test('A: a grounded model quote may replace the excerpt; a demotion always applies', () => {
  const x = run(`<p>The loader was configured with subdomains of 'beacon-relay-example[.]org' as a C&amp;C.</p>`);
  const c = find(x, 'beacon-relay-example.org');
  const [grounded] = mergeAiCandidateUpdates([structuredClone(c)], {
    candidate_updates: [{ candidate_type: 'domain', normalized_value: c.normalized_value, assessment: 'malicious', role: 'command_and_control', confidence: 0.9,
      evidence_text: 'configured with subdomains of beacon-relay-example[.]org as a C&C' }]
  }, { document: x.document });
  assert.equal(grounded.ai_classification.applied, true);
  assert.equal(grounded.assessment, 'malicious');
  const [demoted] = mergeAiCandidateUpdates([structuredClone(c)], {
    candidate_updates: [{ candidate_type: 'domain', normalized_value: c.normalized_value, assessment: 'context_only', role: 'reference',
      evidence_text: 'not in the document at all' }]
  }, { document: x.document });
  assert.equal(demoted.assessment, 'context_only');
});

test('A: a publisher dual-use stance wins over a model malicious label', () => {
  const x = run(`<p>Known dual-use tools in this window include tunnel-broker-example[.]run, a free SSH tunnel provider.</p>`);
  const c = find(x, 'tunnel-broker-example.run');
  const [merged] = mergeAiCandidateUpdates([c], {
    candidate_updates: [{ candidate_type: 'domain', normalized_value: c.normalized_value, assessment: 'malicious', role: 'command_and_control', confidence: 0.9 }]
  }, { document: x.document });
  assert.equal(merged.assessment, 'context_only');
  assert.equal(isReportIndicatorMember(persisted(merged)), false);
});
