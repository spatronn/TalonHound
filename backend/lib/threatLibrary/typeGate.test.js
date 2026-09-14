/**
 * Observable-type gate across the whole extraction pipeline: dotted technical
 * identifiers and relative paths / routes never become domain / URL review
 * candidates, whatever format (HTML / PDF geometry / plain text / Markdown /
 * code blocks) or language the report uses — while explicit IOC sections and
 * narrative network assertions keep working. Fixture values below mirror the
 * shape of a real vendor report; nothing in production code knows them.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { plainTextToCanonicalDocument } from './urlIngest.js';
import { pagesToBlocks } from './pdfLayout.js';
import {
  extractCandidatesWithDiagnostics,
  extractCandidatesFromDocument,
  summarizeCandidateSet
} from './candidateExtraction.js';
import { interpretIocTable, TABLE_SEMANTICS_VERSION } from './tableSemantics.js';
import { annotateDocumentZones } from './documentZones.js';
import { applyEvidencePolicy, buildCandidateEvidenceRecord, isEligibleForHighConfidenceMalicious } from './evidencePolicy.js';
import { mergeAiCandidateUpdates, compactExtractionDiagnostics } from './pipeline.js';
import { partitionCandidatesForAi } from './ai/analyze.js';
import { isActionableReviewIndicator, classifyCreateEligibility } from './promotion.js';
import { buildSystemPrompt } from './ai/prompts.js';

const keyOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const byKey = (cands) => new Map(cands.map((c) => [keyOf(c), c]));
/** Mirrors the analyst review set (backend + frontend share this predicate). */
const reviewSet = (cands) => cands.filter((c) => isActionableReviewIndicator({ ...c, evidence: buildCandidateEvidenceRecord(c) }));

// ---------------------------------------------------------------------------
// Fixture: vendor blog shape (narrative + typed artifact table + IOC section)
// ---------------------------------------------------------------------------

const F = Object.freeze({
  mutex: 'LocalFoo.Client.SingleInstance',
  path: '/clickfix/5WwYUnxSRq/file',
  domain: 'verify-cloud.digital',
  ips: ['86.109.75.168', '86.109.75.161', '178.16.54.148'],
  sha256: [
    'e2db5db12564d2a9da7ef3a57aa23d95782f5eaddc8bd35eb7c35ae6b844a0f0',
    'dede8bfb55c2e6479d89b1e73e0712791cf16a7179325804fc4bc13f708d08ae'
  ]
});

function vendorHtml() {
  return `<html lang="en"><head><title>FooRAT: an undocumented MaaS</title></head><body>
<nav><a href="https://vendor.example-blog.com/">Home</a></nav>
<article>
<h1>FooRAT: an undocumented MaaS</h1>
<h2>Inside the implant</h2>
<p>First it checks for a named mutex, ${F.mutex}, and exits if it already exists. The name has stayed static across every sample.</p>
<p>The Vue3 frontend is packaged into the executable through Go’s embed.FS. The patcher locates each block with bytes.Index and overwrites it with memmove.</p>
<h2>Campaigns</h2>
<p>The domain ${F.domain}, resolving to ${F.ips[1]}, is flagged as a phishing domain, and the payload arrives through a PowerShell one-liner served from ${F.path} on port 8081.</p>
<p>The sales thread sits on HackForums, with a parallel listing on Exploit.in.</p>
<h2>Indicators of Compromise</h2>
<h3>Hash Values (SHA-256)</h3>
<pre>${F.sha256.join('\n')}</pre>
<h3>IP Addresses</h3>
<table><tr><th>Address</th><th>Role</th></tr>
<tr><td>${F.ips[0]}</td><td>Primary C2 and panel</td></tr>
<tr><td>${F.ips[1]}</td><td>ClickFix distribution panel, resolves ${F.domain}</td></tr>
<tr><td>${F.ips[2]}</td><td>ClickFix panel serving FooRAT</td></tr>
</table>
<h3>Domain</h3>
<pre>${F.domain}</pre>
<h3>Host and Network Artifacts</h3>
<table><tr><th>Type</th><th>Value</th></tr>
<tr><td>Mutex</td><td>${F.mutex}</td></tr>
<tr><td>File</td><td>%TEMP%callback.json</td></tr>
<tr><td>PE resource</td><td>RT_RCDATA 1001, JSON configuration block with uacEnabled</td></tr>
<tr><td>C2 port</td><td>TCP 3308</td></tr>
<tr><td>Default PE metadata</td><td>Product Foo, Company Foo, version 0.2</td></tr>
<tr><td>ClickFix path</td><td>${F.path} on port 8081</td></tr>
</table>
<h2>MITRE ATT&amp;CK TTPs</h2>
<table><tr><th>Tactic</th><th>Technique</th><th>Procedure</th></tr>
<tr><td>TA0001: Initial Access</td><td>T1566.002: Phishing</td><td>Lures hosted on domains such as ${F.domain}.</td></tr>
<tr><td>TA0036: Masquerading</td><td>T1036.001</td><td>Recalculates the PE checksum through ApplyStubPE.ForceCheckSum and ApplyStubPE.WithAuthenticode.</td></tr>
</table>
</article>
<footer>© vendor https://vendor.example-blog.com/privacy</footer>
</body></html>`;
}

function extractHtml(html, url = 'https://vendor.example-blog.com/blog/foorat/') {
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return extractCandidatesWithDiagnostics(r.document, { sourceUrl: url });
}

test('internal contracts bumped for the type gate', () => {
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v2');
});

test('vendor HTML: mutex row and path row are not domain / URL IOCs; every real IOC is kept and source-asserted', () => {
  const { candidates, diagnostics } = extractHtml(vendorHtml());
  const k = byKey(candidates);
  const review = reviewSet(candidates);
  const reviewKeys = new Set(review.map(keyOf));

  // False-positive classes gone from the review set
  assert.equal(reviewKeys.has(`domain:${F.mutex.toLowerCase()}`), false, 'mutex typed as domain');
  assert.equal([...reviewKeys].some((x) => x.startsWith('url:/clickfix')), false, 'relative path typed as URL');
  assert.equal(candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === F.mutex.toLowerCase()), false);
  assert.equal(candidates.some((c) => c.candidate_type === 'url' && c.normalized_value.includes('/clickfix')), false);

  // …but retained as explainable technical context
  const mutex = k.get(`technical_artifact:${F.mutex}`);
  assert.ok(mutex, 'mutex retained as technical_artifact');
  assert.equal(mutex.is_ioc, false);
  assert.equal(mutex.assessment, 'context_only');
  assert.equal(mutex.artifact_kind, 'mutex');
  assert.equal(mutex.typing_reason, 'mutex_label');
  assert.equal(mutex.type_resolution.syntax_guess, 'domain');
  assert.equal(mutex.type_resolution.resolved_type, 'technical_artifact');
  assert.equal(mutex.type_resolution.promotion, 'excluded');
  assert.ok(mutex.occurrence_count >= 2, 'table row + narrative mention aggregate on one identity');

  const path = k.get(`relative_path:${F.path}`);
  assert.ok(path, 'path retained as relative_path');
  assert.equal(path.is_ioc, false);
  assert.equal(path.parsed.port, 8081, 'prose-stated port kept as context');
  assert.equal(path.normalized_value, F.path, 'candidate value stops before prose');
  assert.equal(path.type_resolution.syntax_guess, 'url');
  assert.equal(path.type_resolution.normalized_path, F.path);
  assert.equal(path.type_resolution.port, 8081);
  // never synthesised into host:port/path
  assert.equal(candidates.some((c) => c.candidate_type === 'url' && /8081\/clickfix/.test(c.normalized_value)), false);

  // Legitimate IOCs: all present, deterministic, malicious
  for (const key of [...F.ips.map((ip) => `ip:${ip}`), ...F.sha256.map((h) => `sha256:${h}`), `domain:${F.domain}`]) {
    const c = k.get(key);
    assert.ok(c, key);
    assert.equal(c.assessment, 'malicious', key);
    assert.equal(c.ai_needed, false, key);
    assert.ok(reviewKeys.has(key), `${key} in review set`);
  }
  assert.equal(k.get(`domain:${F.domain}`).typing_reason, 'declared_network_type', '"Domain" sub-heading under IOC heading types the value');
  assert.equal(review.length, F.ips.length + F.sha256.length + 1, 'review set = exactly the source-asserted IOCs');

  // Incidental code identifiers in prose are neither IOCs nor persisted noise
  for (const noise of ['embed.fs', 'bytes.index', 'applystubpe.forcechecksum', 'applystubpe.withauthenticode']) {
    assert.equal(candidates.some((c) => c.normalized_value.toLowerCase() === noise), false, noise);
  }
  // Forum name in prose stays a (context-only) domain — no allowlist involved
  assert.equal(k.get('domain:exploit.in')?.assessment, 'context_only');

  // Diagnostics explain the workload
  const tr = diagnostics.type_resolution;
  assert.ok(tr.syntactic_occurrences > tr.network_ioc_candidates);
  assert.ok(tr.artifact_candidates >= 2);
  assert.equal(tr.relative_paths >= 1, true);
  assert.ok(tr.excluded_reasons.mutex_label >= 1);
  const compact = compactExtractionDiagnostics(diagnostics);
  assert.equal(compact.type_resolution.artifact_candidates, tr.artifact_candidates);
  assert.equal(summarizeCandidateSet(candidates).ai_needed, 0, 'nothing left for the model to classify');
});

test('artifact table interpretation: Type | Value table of host artifacts is an artifact_table, never explicit', () => {
  const block = {
    id: 't1',
    type: 'table',
    section_heading: 'Host and Network Artifacts',
    table: {
      headers: ['Type', 'Value'],
      rows: [
        ['Mutex', F.mutex],
        ['File', '%TEMP%callback.json'],
        ['ClickFix path', `${F.path} on port 8081`]
      ]
    }
  };
  const interp = interpretIocTable(block);
  assert.equal(interp.kind, 'artifact_table');
  assert.equal(interp.explicit, false);
  const values = interp.rows.flatMap((r) => r.values);
  assert.deepEqual(
    values.map((v) => [v.candidate_type, v.normalized_value, v.is_ioc]),
    [
      ['technical_artifact', F.mutex, false],
      ['file_path', '%TEMP%callback.json', false],
      ['relative_path', F.path, false]
    ]
  );
  // a mixed table keeps its explicit IOC rows and still excludes the artifact rows
  const mixed = interpretIocTable({
    ...block,
    table: { headers: ['Type', 'Value'], rows: [['Domain', 'c2.evil-example.com'], ['Mutex', F.mutex], ['URL', 'https://evil-example.com/gate.php']] }
  });
  assert.equal(mixed.kind, 'ioc_table');
  assert.equal(mixed.explicit, true);
  const mixedValues = mixed.rows.flatMap((r) => r.values);
  assert.deepEqual(
    mixedValues.map((v) => [v.candidate_type, v.is_ioc]),
    [['domain', true], ['technical_artifact', false], ['url', true]]
  );
});

test('AI cannot resurrect an excluded artifact or retype it; confidence never bypasses the gate', () => {
  const { candidates } = extractHtml(vendorHtml());
  const merged = mergeAiCandidateUpdates(candidates, {
    candidate_updates: [
      { candidate_type: 'technical_artifact', normalized_value: F.mutex, assessment: 'malicious', role: 'command_and_control', confidence: 0.99 },
      { candidate_type: 'domain', normalized_value: F.mutex.toLowerCase(), assessment: 'malicious', role: 'command_and_control', confidence: 0.99 },
      { candidate_type: 'relative_path', normalized_value: F.path, assessment: 'malicious', role: 'payload_hosting', confidence: 0.99 },
      { candidate_type: 'url', normalized_value: `${F.path} on port 8081`, assessment: 'malicious', role: 'payload_hosting', confidence: 0.99 }
    ]
  });
  const k = byKey(merged);
  assert.equal(k.get(`technical_artifact:${F.mutex}`).assessment, 'context_only');
  assert.equal(k.get(`technical_artifact:${F.mutex}`).is_ioc, false);
  assert.equal(k.get(`relative_path:${F.path}`).assessment, 'context_only');
  assert.equal(k.has(`domain:${F.mutex.toLowerCase()}`), false, 'AI cannot create a retyped candidate');
  assert.equal(k.has(`url:${F.path} on port 8081`), false);
  assert.equal(reviewSet(merged).length, F.ips.length + F.sha256.length + 1);
});

test('canonical gate: a mis-typed legacy candidate is excluded even when marked malicious in an explicit zone', () => {
  const legacyUrl = applyEvidencePolicy({
    candidate_type: 'url',
    normalized_value: '/clickfix/abc/file on port 8081',
    assessment: 'malicious',
    confidence: 0.95,
    is_ioc: true,
    occurrences: [{ zone: 'explicit_ioc_section', form: 'table_row' }]
  });
  assert.equal(legacyUrl.is_ioc, false);
  assert.equal(legacyUrl.policy_decision, 'ioc_excluded_invalid_canonical');
  assert.equal(legacyUrl.assessment, 'context_only');
  assert.equal(isEligibleForHighConfidenceMalicious({ ...legacyUrl, assessment: 'malicious', confidence: 0.95 }), false);
  assert.equal(classifyCreateEligibility({ ...legacyUrl, review_status: 'approved' }).eligible, false);

  const legacyDomain = applyEvidencePolicy({
    candidate_type: 'domain',
    normalized_value: 'product foo, company foo',
    assessment: 'malicious',
    is_ioc: true,
    occurrences: [{ zone: 'explicit_ioc_section', form: 'table_row' }]
  });
  assert.equal(legacyDomain.is_ioc, false);

  // a valid explicit assertion still promotes deterministically
  const ok = applyEvidencePolicy({
    candidate_type: 'url',
    normalized_value: 'http://154.58.204.15:8081/clickfix/abc/file',
    is_ioc: true,
    occurrences: [{ zone: 'explicit_ioc_section', form: 'table_row' }]
  });
  assert.equal(ok.assessment, 'malicious');
  assert.equal(ok.source_assertion, 'explicit_ioc');
});

test('review partition: excluded artifacts are context, not review indicators, not AI work', () => {
  const { candidates } = extractHtml(vendorHtml());
  const part = partitionCandidatesForAi(candidates);
  assert.equal(part.toClassify.length, 0);
  assert.equal(part.explicit.some((c) => c.candidate_type === 'technical_artifact' || c.candidate_type === 'relative_path'), false);
  for (const c of candidates) {
    if (c.candidate_type === 'technical_artifact' || c.candidate_type === 'relative_path' || c.candidate_type === 'file_path') {
      assert.equal(isActionableReviewIndicator({ ...c, evidence: buildCandidateEvidenceRecord(c) }), false, keyOf(c));
      assert.equal(classifyCreateEligibility({ ...c, review_status: 'approved' }).eligible, false, keyOf(c));
    }
  }
  const ev = buildCandidateEvidenceRecord(candidates.find((c) => c.candidate_type === 'technical_artifact'));
  assert.equal(ev.type_resolution.resolved_type, 'technical_artifact');
  assert.equal(ev.artifact_kind, 'mutex');
});

// ---------------------------------------------------------------------------
// Explicit sections and narrative extraction must not regress
// ---------------------------------------------------------------------------

test('explicit typed rows keep Domain | … and URL | …; narrative IP:port still yields the network IOC', () => {
  const html = `<html><body><article>
<h1>Report</h1>
<p>The RAT connects to 154.58.204.15:8080 and beacons every 60 seconds.</p>
<p>The loader pulls a stage from http://154.58.204.15:8081/clickfix/abc/file after the lure.</p>
<h2>Indicators of Compromise</h2>
<table><tr><th>Type</th><th>Indicator</th></tr>
<tr><td>Domain</td><td>c2.evil-example.com</td></tr>
<tr><td>URL</td><td>https://evil-example.com/path</td></tr>
<tr><td>Mutex</td><td>Global\\FooRAT.Client.Lock</td></tr>
</table></article></body></html>`;
  const { candidates } = extractHtml(html, 'https://vendor.example-blog.com/r/');
  const k = byKey(candidates);
  assert.equal(k.get('domain:c2.evil-example.com')?.assessment, 'malicious');
  assert.equal(k.get('url:https://evil-example.com/path')?.assessment, 'malicious');
  assert.equal(k.get('url:http://154.58.204.15:8081/clickfix/abc/file')?.is_ioc, true, 'absolute URL with path is a URL IOC');
  const ip = k.get('ip:154.58.204.15');
  assert.ok(ip, 'narrative IP:port extracted');
  assert.equal(ip.is_ioc, true);
  assert.ok(ip.parsed.ports.includes(8080));
  assert.equal(candidates.some((c) => c.candidate_type === 'domain' && /foorat\.client\.lock/i.test(c.normalized_value)), false);
});

test('narrative report without appendix: body C2 assertions stay on the AI path, artifacts do not', () => {
  const doc = createCanonicalDocument({
    blocks: [
      { id: 'b1', type: 'paragraph', text: 'The RAT connects to c2.evil-example.com and creates the mutex Global.FooRAT.Client.Lock before it runs.' },
      { id: 'b2', type: 'paragraph', text: 'Its configuration key agent.server.timeout defaults to 30 seconds; Loader.Program.Main is the entry point.' }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);
  assert.equal(k.get('domain:c2.evil-example.com')?.ai_needed, true);
  assert.equal(k.get('domain:c2.evil-example.com')?.is_ioc, true);
  for (const key of ['domain:global.foorat.client.lock', 'domain:agent.server.timeout', 'domain:loader.program.main']) {
    assert.equal(k.has(key), false, key);
  }
  assert.equal(summarizeCandidateSet(cands).ai_needed, 1);
});

// ---------------------------------------------------------------------------
// Formats: plain text / Markdown table / PDF geometry / code block
// ---------------------------------------------------------------------------

test('Markdown / plain text: typed table rows and a Turkish narrative behave the same', () => {
  const text = [
    'FooRAT Analizi',
    `Zararlı, ${F.domain} alan adına bağlanır ve ${F.path} yolundan 8081 portu üzerinden yükü indirir.`,
    `Tek örnek kontrolü için ${F.mutex} muteksini oluşturur.`,
    '',
    'Göstergeler',
    '',
    '| Tür | Değer |',
    '| --- | --- |',
    `| Muteks | ${F.mutex} |`,
    `| ClickFix yolu | ${F.path} on port 8081 |`,
    `| Alan Adı | ${F.domain} |`,
    `| IP | ${F.ips[0]} |`,
    `| SHA256 | ${F.sha256[0]} |`
  ].join('\n');
  const doc = plainTextToCanonicalDocument(text, { title: 'FooRAT Analizi', language: 'tr' });
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);
  const review = new Set(reviewSet(cands).map(keyOf));
  assert.deepEqual([...review].sort(), [`domain:${F.domain}`, `ip:${F.ips[0]}`, `sha256:${F.sha256[0]}`].sort());
  assert.equal(k.get(`technical_artifact:${F.mutex}`)?.is_ioc, false);
  assert.equal(k.get(`relative_path:${F.path}`)?.is_ioc, false);
  assert.equal(k.get(`relative_path:${F.path}`)?.parsed.port, 8081);
  assert.equal(k.get(`domain:${F.domain}`)?.assessment, 'malicious');
});

test('Chinese narrative: 互斥体 name is an artifact, 连接 target is a domain IOC candidate', () => {
  const doc = createCanonicalDocument({
    language: 'zh',
    blocks: [
      { id: 'b1', type: 'paragraph', text: `样本首先创建互斥体 ${F.mutex}，随后连接 c2.evil-example.net 并下载载荷。` },
      { id: 'b2', type: 'paragraph', text: '配置项 agent.server.timeout 控制心跳间隔。' }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);
  assert.equal(k.get('domain:c2.evil-example.net')?.is_ioc, true);
  assert.equal(k.has(`domain:${F.mutex.toLowerCase()}`), false);
  assert.equal(k.get(`technical_artifact:${F.mutex}`)?.artifact_kind, 'mutex');
  assert.equal(k.has('domain:agent.server.timeout'), false);
});

/**
 * Minimal pdf.js-like page. Headings are larger (16pt), body lines sit at a
 * 13pt pitch, table rows at a 24pt pitch (row padding) — the geometry a
 * browser-printed report produces.
 */
function pdfPage(page, lines) {
  let y = 760;
  const items = [];
  for (const line of lines) {
    if (line === '') {
      y -= 20;
      continue;
    }
    const heading = typeof line === 'object' && !Array.isArray(line) && line.h;
    const row = Array.isArray(line);
    const cells = heading ? [[72, line.h]] : row ? line : [[72, line]];
    for (const [x, str] of cells) {
      const size = heading ? 16 : 11;
      items.push({ str, width: str.length * (heading ? 8 : 5.5), height: size, transform: [size, 0, 0, size, x, y], fontName: heading ? 'g_head' : 'g_body' });
    }
    y -= heading ? 26 : row ? 24 : 13;
  }
  return { page, pageHeight: 792, items };
}

const PDF_BODY = [
  'The implant is a native Windows client that talks to a Go control server over a',
  'custom binary protocol on TCP 3308 and exposes a web panel to the operator on',
  'port 8080. It checks a named mutex before it runs and exits when a second copy',
  'is already active on the host. The panel logs show secondary payload delivery.',
  'Operators rent the kit monthly and receive a builder that patches the C2 host',
  'into a placeholder block of the stub. Samples share PE metadata and the mutex.',
  'The ClickFix lure copies a PowerShell one-liner to the clipboard and asks the',
  'victim to paste it into the Run dialog, which fetches the second stage.'
];

test('PDF geometry: Type / Value table with a Mutex row and a path row; IOC list rows stay IOCs', () => {
  const pages = [
    pdfPage(1, [
      { h: 'Inside the implant' },
      ...PDF_BODY,
      '',
      { h: 'Host and Network Artifacts' },
      [[72, 'Type'], [320, 'Value']],
      [[72, 'Mutex'], [320, F.mutex]],
      [[72, 'ClickFix path'], [320, `${F.path} on port 8081`]],
      [[72, 'Domain'], [320, F.domain]],
      [[72, 'IP'], [320, F.ips[0]]],
      '',
      { h: 'Indicators of Compromise' },
      F.sha256[0],
      F.sha256[1],
      F.ips[2]
    ])
  ];
  const { blocks } = pagesToBlocks(pages);
  assert.ok(blocks.some((b) => b.type === 'table' && b.table.rows.length === 5), 'geometry reconstructed the table');
  const doc = createCanonicalDocument({ title: 'pdf', blocks });
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);
  assert.equal(k.has(`domain:${F.mutex.toLowerCase()}`), false, 'mutex not a domain');
  assert.equal(cands.some((c) => c.candidate_type === 'url' && c.normalized_value.includes('/clickfix')), false, 'path not a URL');
  assert.equal(k.get(`technical_artifact:${F.mutex}`)?.typing_reason, 'mutex_label');
  assert.equal(k.get(`relative_path:${F.path}`)?.parsed.port, 8081);
  const review = new Set(reviewSet(cands).map(keyOf));
  for (const key of [`domain:${F.domain}`, `ip:${F.ips[0]}`, `ip:${F.ips[2]}`, `sha256:${F.sha256[0]}`, `sha256:${F.sha256[1]}`]) {
    assert.ok(review.has(key), key);
  }
  assert.equal(review.size, 5);
});

test('code blocks: weak-suffix identifiers are artifacts, DNS-shaped C2 values inside code are still candidates', () => {
  const doc = createCanonicalDocument({
    blocks: [
      { id: 'h', type: 'heading', text: 'Configuration' },
      { id: 'c1', type: 'code', text: 'agent.server.timeout = 30\nagent.server.host = c2-panel.evil-example.net\nLoader.Program.Main()' }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);
  assert.equal(k.has('domain:agent.server.timeout'), false);
  assert.equal(k.has('domain:agent.server.host'), false, 'assignment key, not a hostname (even with a gTLD-shaped suffix)');
  assert.equal(k.has('domain:loader.program.main'), false);
  assert.equal(k.get('domain:c2-panel.evil-example.net')?.is_ioc, true);
});

test('typed sub-headings continue an open IOC section instead of resetting it', () => {
  const doc = createCanonicalDocument({
    blocks: [
      { id: 'h1', type: 'heading', text: 'Indicators of Compromise' },
      { id: 'h2', type: 'heading', text: 'IP Addresses' },
      { id: 'l1', type: 'list_item', text: '203.0.113.9' },
      { id: 'h3', type: 'heading', text: 'Domain' },
      { id: 'c1', type: 'code', text: 'c2.evil-example.org' },
      { id: 'h4', type: 'heading', text: 'Conclusion' },
      { id: 'p1', type: 'paragraph', text: 'The campaign also referenced portal.example-vendor.net in passing.' }
    ]
  });
  const annotated = annotateDocumentZones(doc);
  const z = Object.fromEntries(annotated.blocks.map((b) => [b.id, b]));
  assert.equal(z.h2.zone_reason, 'typed_subheading');
  assert.equal(z.l1.zone, 'explicit_ioc_section');
  assert.equal(z.c1.zone, 'explicit_ioc_section');
  assert.equal(z.c1.declared_type_label, 'domain');
  assert.equal(z.h4.zone_reason, 'heading_reset');
  assert.equal(z.p1.zone, 'report_body');
  const cands = extractCandidatesFromDocument(doc);
  const k = byKey(cands);
  assert.equal(k.get('domain:c2.evil-example.org')?.assessment, 'malicious');
  assert.equal(k.get('ip:203.0.113.9')?.assessment, 'malicious');
  assert.notEqual(k.get('domain:portal.example-vendor.net')?.assessment, 'malicious');
});

test('the same dotted token is typed once per document from all its occurrences', () => {
  const doc = createCanonicalDocument({
    blocks: [
      { id: 'b1', type: 'paragraph', text: 'The actor advertises on Exploit.in and updates the module weekly.' },
      { id: 'b2', type: 'paragraph', text: 'A parallel listing appeared on Exploit.in in June.' }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const dotted = cands.filter((c) => c.normalized_value.toLowerCase() === 'exploit.in');
  assert.equal(dotted.length, 1, 'one identity, not domain + artifact');
  assert.equal(dotted[0].candidate_type, 'domain');
  assert.equal(dotted[0].occurrence_count, 2);
});

test('system prompt teaches the artifact rule (mutex / config / relative path never network IOCs)', () => {
  const sys = buildSystemPrompt();
  assert.match(sys, /mutex/i);
  assert.match(sys, /relative path/i);
  assert.match(sys, /never a URL/i);
});
