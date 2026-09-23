/**
 * Section scope model: authoritative section discovery (descriptive indicator
 * headings), scope inheritance across short sub-labelled groups, structural
 * list discovery as a fallback only, and occurrence-level assertion vs
 * narrative mention inside C2 / IOC sections. Fixture values are sanitized
 * and mirror the shape of a vendor blog (single-column indicator tables under
 * one "Indicators: …" heading); nothing in production code knows them.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import {
  extractCandidatesFromDocument,
  extractCandidatesWithDiagnostics,
  summarizeCandidateSet,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import {
  annotateDocumentZones,
  classifyHeadingText,
  OBSERVABLE_LIST_MIN_ROWS,
  THREAT_LIBRARY_DOCUMENT_ZONES_VERSION
} from './documentZones.js';
import { SOURCE_ASSERTIONS, buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { plainTextToBlocks } from './pdfLayout.js';
import { compactExtractionDiagnostics, mergeAiCandidateUpdates } from './pipeline.js';
import { partitionCandidatesForAi } from './ai/analyze.js';
import {
  INDICATOR_HEADING_FORMS,
  OCCURRENCE_KINDS,
  SECTION_ROLES,
  SOURCE_RELATIONS,
  classifyIndicatorHeading,
  classifySectionRole,
  classifySourceRelationDetail,
  isIndicatorRowShape,
  isObservableListLine
} from './indicatorScope.js';

const keyOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const byVal = (cands, value) => cands.find((c) => c.normalized_value === value);
const maliciousKeys = (cands) => new Set(cands.filter((c) => c.assessment === 'malicious').map(keyOf));

function doc(blocks, extra = {}) {
  return createCanonicalDocument({
    title: extra.title || 'Scope fixture',
    language: extra.language || 'en',
    blocks: blocks.map((b, i) => ({
      id: b.id || `b${i + 1}`,
      type: b.type || 'paragraph',
      page: b.page ?? 1,
      text: b.text,
      ...(b.layout ? { layout: b.layout } : {}),
      ...(b.level != null ? { level: b.level } : {}),
      ...(b.table ? { table: b.table } : {})
    })),
    ...extra
  });
}

// ---------------------------------------------------------------------------
// Fixture: vendor blog with a descriptive "Indicators:" heading, single-column
// indicator tables with group labels (3 rows / decoy label / 1 row / IP label /
// 2 defanged IPs), a C2-themed narrative section naming a research firm, and a
// scheme-less host/path payload resource.
// ---------------------------------------------------------------------------

const F = Object.freeze({
  type1: ['11170011.com', 'puqxr.com', '80074.cc'],
  decoy: 'vip311.cc',
  c2: ['cache-cdn.org', 'cache-mcp.com', 'mcp-source.online'],
  decoy2: 'asg78.com',
  single: 'githubassets.net',
  ips: ['157.185.143.150', '146.103.91.133'],
  research: 'interisle.net',
  resource: 'js.cache-mcp.com/layer.js',
  resourceDefanged: 'js.cache-mcp[.]com/layer.js'
});

const defang = (v) => v.replace(/\./g, '[.]');
const rows = (values) => values.map((v) => `<tr><td>${defang(v)}</td></tr>`).join('');

function fixtureHtml() {
  return `<html lang="en"><head><title>Casino garbage</title></head><body>
<nav><a href="https://vendor.example-blog.com/">Home</a></nav>
<article>
<h1>How Money Laundering, Scams, and Espionage Hide in a Web Full of Casino Garbage</h1>
<h3>Type 1: Illegal Casinos</h3>
<p>When visiting ${defang(F.type1[0])} from Hong Kong the site redirected to a final destination IP address, ${defang(F.ips[0])}, hosting the website.</p>
<p>When visiting from Japan the site redirected to ${defang(F.ips[1])}.</p>
<h3>Type 3: FooBird Malware C2 Domains Embedded into Casino and Adult Websites</h3>
<p>APT groups have been running the FooBird framework since 2023, hiding their malware C2 domains inside low-quality casino websites.</p>
<p>Greg Aaron of Interisle Consulting (${defang(F.research)}) flagged a casino domain, ${defang(F.decoy2)}, which at the time was loading a suspicious JavaScript payload from ${F.resourceDefanged}.</p>
<p>Figure 15. Screenshot of a casino domain (${defang(F.decoy)}), which embeds the FooBird malware C2 domain ${defang(F.c2[1])}.</p>
<p>Live WebSocket connections use an additional domain, ${defang(F.c2[2])}.</p>
<h3>What Does a FooBird Infection Look Like on the Network?</h3>
<p>Their domain ${defang(F.single)} also comes up when people make typos in code.</p>
<h3>Indicators: Three Casinos and a Thousand Lookalikes</h3>
<p>Below are the domains and IP addresses referenced throughout this research, grouped by casino type.</p>
<table><thead><tr><th>Illegal Casino Domains (Type 1)</th></tr></thead><tbody>${rows(F.type1)}</tbody></table>
<table><thead><tr><th>FooBird C2 and Decoy Domains (Type 3)</th></tr></thead><tbody>
<tr><td>${defang(F.decoy)} – Decoy domain</td></tr>${rows(F.c2)}<tr><td>${defang(F.decoy2)} – Decoy domain</td></tr>${rows([F.single])}</tbody></table>
<table><thead><tr><th>Supporting IP Addresses for Illegal Casino Domains (Type 1)</th></tr></thead><tbody>${rows(F.ips)}</tbody></table>
<p class="entry-meta">September 15, 2026</p>
</article>
<footer>© vendor https://vendor.example-blog.com/privacy</footer>
</body></html>`;
}

function extractHtml(html, url = 'https://vendor.example-blog.com/blog/casino/') {
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: url }), document: r.document };
}

test('internal contracts bumped for the scope model (product VERSION untouched)', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v8');
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v2');
  assert.equal(OBSERVABLE_LIST_MIN_ROWS, 3, 'discovery threshold unchanged — inheritance no longer depends on it');
});

// ---------------------------------------------------------------------------
// Heading recognition
// ---------------------------------------------------------------------------

test('indicator headings with a descriptive suffix declare an indicator section (generic, multilingual)', () => {
  for (const h of [
    'Indicators: Three Casinos and a Thousand Lookalikes',
    'Indicators – Network Infrastructure',
    'Indicators of Compromise: Campaign A',
    'Network Indicators: Additional Infrastructure',
    'IOCs (Type 3)',
    'Göstergeler: Ek Altyapı',
    '威胁指标：活动A',
    'Indicadores – Campaña B'
  ]) {
    assert.equal(classifySectionRole(h), SECTION_ROLES.IOC_APPENDIX, h);
    assert.equal(classifyHeadingText(h), 'explicit_ioc_section', h);
  }
  assert.equal(classifySectionRole('C2 Servers: Secondary Cluster'), SECTION_ROLES.C2_INFRASTRUCTURE);
  assert.equal(classifyIndicatorHeading('Indicators: Three Casinos and a Thousand Lookalikes').form, INDICATOR_HEADING_FORMS.DESCRIPTIVE_SUFFIX);
  assert.equal(classifyIndicatorHeading('Indicators').form, INDICATOR_HEADING_FORMS.LABEL);
  assert.equal(classifyIndicatorHeading('Indicators:').form, INDICATOR_HEADING_FORMS.LABEL);
  assert.equal(classifyIndicatorHeading('Appendix B: C2 Servers').form, INDICATOR_HEADING_FORMS.LABEL);
  // The word alone inside a sentence-like title is not a declaration.
  assert.equal(classifySectionRole('Why these indicators matter'), null);
  assert.equal(classifySectionRole('Indicators suggest a Chinese origin'), null);
  assert.equal(classifySectionRole('Executive Summary'), null);
});

test('a descriptive indicator heading followed only by prose is not an authoritative section', () => {
  const d = doc([
    { id: 'h', type: 'heading', text: 'Indicators: what the campaign tells us about tradecraft' },
    { id: 'p', text: 'The operators rotate infrastructure quickly; the backdoor connects to 203.0.113.77 for tasking.' },
    { id: 'h2', type: 'heading', text: 'Conclusion' },
    { id: 'p2', text: 'Defenders should watch for this pattern.' }
  ]);
  const z = annotateDocumentZones(d);
  assert.equal(z.blocks.find((b) => b.id === 'h').zone_reason, 'indicator_heading_unconfirmed');
  assert.equal(z.blocks.find((b) => b.id === 'p').zone, 'report_body');
  const cands = extractCandidatesFromDocument(d);
  const ip = byVal(cands, '203.0.113.77');
  assert.equal(ip.source_assertion, SOURCE_ASSERTIONS.BODY_MENTION);
  assert.equal(ip.ai_needed, true, 'narrative C2 assertion without an appendix stays on the AI path');
});

// ---------------------------------------------------------------------------
// Exact regression fixture
// ---------------------------------------------------------------------------

test('fixture: exact authoritative set — 3-row group, decoy label, 1-row group, IP label, 2 defanged IPs', () => {
  const { candidates, diagnostics } = extractHtml(fixtureHtml());
  const expected = new Set([
    ...F.type1.map((v) => `domain:${v}`),
    `domain:${F.decoy}`,
    ...F.c2.map((v) => `domain:${v}`),
    `domain:${F.decoy2}`,
    `domain:${F.single}`,
    ...F.ips.map((v) => `ip:${v}`),
    `url:${F.resource}`
  ]);
  assert.deepEqual([...maliciousKeys(candidates)].sort(), [...expected].sort());

  for (const key of expected) {
    const c = candidates.find((x) => keyOf(x) === key);
    assert.equal(c.ai_needed, false, `${key} decided deterministically`);
    assert.equal(c.decision_source, 'deterministic', key);
    assert.ok(
      [SOURCE_ASSERTIONS.EXPLICIT_IOC, SOURCE_ASSERTIONS.EXPLICIT_C2].includes(c.source_assertion),
      `${key} is a source assertion (${c.source_assertion})`
    );
  }

  // Missing IPs: the 2-row IP subgroup inherits the section (no ≥3 run needed).
  for (const ip of F.ips) {
    const c = byVal(candidates, ip);
    const row = c.occurrences.find((o) => o.zone === 'explicit_ioc_section');
    assert.ok(row, `${ip} has an occurrence inside the indicator section`);
    assert.equal(row.occurrence_kind, OCCURRENCE_KINDS.LIST_ITEM);
    assert.equal(row.asserted, true);
    assert.equal(row.scope_opening_id, diagnostics.scope.trace.find((t) => t.decision === 'open' && t.zone === 'explicit_ioc_section').block_id);
    assert.equal(c.policy_decision, 'explicit_report_assertion');
    assert.equal(c.role, 'malicious_infrastructure');
  }
  // Single-row domain after the decoy label: retained without AI.
  const single = byVal(candidates, F.single);
  assert.equal(single.assessment, 'malicious');
  assert.ok(single.occurrences.some((o) => o.zone === 'explicit_ioc_section' && o.asserted === true));
  // Annotated rows ("x – Decoy domain") are still rows.
  assert.equal(byVal(candidates, F.decoy2).occurrences.find((o) => o.zone === 'explicit_ioc_section').occurrence_kind, OCCURRENCE_KINDS.STANDALONE_INDICATOR_ROW);

  // Contextual research firm inside the C2 section is not promoted.
  const research = byVal(candidates, F.research);
  assert.ok(research, 'research domain retained as context');
  assert.equal(research.assessment, 'context_only');
  assert.equal(research.ai_needed, false);
  assert.equal(research.policy_decision, 'context_only_contextual_mention_in_indicator_section');
  assert.equal(research.occurrences[0].zone, 'c2_section');
  assert.equal(research.occurrences[0].occurrence_kind, OCCURRENCE_KINDS.NARRATIVE_CONTEXT);
  assert.equal(research.occurrences[0].relation_marker, 'contextual');

  // Scheme-less resource: one URL in the publisher's spelling, no invented scheme.
  const res = candidates.find((c) => c.candidate_type === 'url' && c.normalized_value === F.resource);
  assert.ok(res);
  assert.equal(res.original_value, F.resourceDefanged, 'source spelling preserved');
  assert.equal(res.parsed.scheme, null);
  assert.equal(res.parsed.scheme_less, true);
  assert.equal(res.parsed.path, '/layer.js');
  assert.equal(res.parsed.host, 'js.cache-mcp.com');
  assert.equal(res.typing_reason, 'scheme_less_url_with_dns_host');
  assert.equal(res.occurrences[0].occurrence_kind, OCCURRENCE_KINDS.NARRATIVE_ASSERTION, '"payload from" is an operational clause');
  assert.equal(candidates.some((c) => /^https?:\/\//.test(String(c.normalized_value)) && c.normalized_value.includes('js.cache-mcp')), false, 'no absolute URL invented');
  assert.equal(candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'js.cache-mcp.com'), false, 'host is parsed metadata, not a standalone domain');
  assert.equal(candidates.some((c) => String(c.normalized_value).toLowerCase() === 'layer.js'), false, 'path basename is neither a domain nor an artifact');
  assert.equal(diagnostics.type_resolution.scheme_less_resources.count, 1);
  assert.equal(diagnostics.type_resolution.scheme_less_resources.examples[0].decision, 'preserved_as_scheme_less_url');

  // Nothing is left for the model.
  const summary = summarizeCandidateSet(candidates);
  assert.equal(summary.ai_needed, 0);
  assert.equal(partitionCandidatesForAi(candidates).toClassify.length, 0);

  // Diagnostics explain the scope decisions without the analyst UI changing.
  const compact = compactExtractionDiagnostics(diagnostics);
  assert.equal(compact.scope.zones_version, 'tl-zones-v2');
  assert.ok(compact.scope.trace.some((t) => t.decision === 'open' && t.form === 'descriptive_suffix'));
  assert.ok(compact.scope.trace.some((t) => t.decision === 'reset' && t.from_zone === 'c2_section'));
  assert.ok(compact.scope.occurrence_kinds.list_item >= 8);
  assert.equal(compact.type_resolution.scheme_less_resources.count, 1);
  const ev = buildCandidateEvidenceRecord(byVal(candidates, F.ips[0]));
  assert.ok(ev.occurrences.some((o) => o.occurrence_kind === OCCURRENCE_KINDS.LIST_ITEM && o.asserted === true));
});

test('fixture: heading levels — deeper sub-labels inherit, sibling topics close the section', () => {
  const d = doc([
    { id: 'h', type: 'heading', level: 2, text: 'Indicators: Campaign Infrastructure' },
    { id: 'r1', type: 'list_item', text: '203.0.113.10' },
    { id: 'r2', type: 'list_item', text: '203.0.113.11' },
    { id: 'r3', type: 'list_item', text: '203.0.113.12' },
    { id: 'sub1', type: 'heading', level: 3, text: 'Decoy domains' },
    { id: 'r4', type: 'list_item', text: 'decoy-one[.]net – Decoy domain' },
    { id: 'sub2', type: 'heading', level: 3, text: 'Supporting IP Addresses' },
    { id: 'r5', type: 'list_item', text: '198[.]51[.]100[.]20' },
    { id: 'r6', type: 'list_item', text: '198[.]51[.]100[.]21' },
    { id: 'h2', type: 'heading', level: 2, text: 'Mitigations' },
    { id: 'p', text: 'Block outbound traffic to vendor-tool.example and review logs.' }
  ]);
  const z = annotateDocumentZones(d);
  const zone = (id) => z.blocks.find((b) => b.id === id).zone;
  // A type-word label ("Decoy domains") may also satisfy the older typed-subheading rule; either way it continues.
  assert.ok(['subgroup_label', 'typed_subheading'].includes(z.blocks.find((b) => b.id === 'sub1').zone_reason));
  assert.ok(['subgroup_label', 'typed_subheading'].includes(z.blocks.find((b) => b.id === 'sub2').zone_reason));
  for (const id of ['r1', 'r2', 'r3', 'r4', 'r5', 'r6']) assert.equal(zone(id), 'explicit_ioc_section', id);
  assert.equal(z.blocks.find((b) => b.id === 'h2').zone_reason, 'heading_reset');
  assert.equal(zone('p'), 'report_body');
  const cands = extractCandidatesFromDocument(d);
  assert.deepEqual(
    [...maliciousKeys(cands)].sort(),
    ['ip:203.0.113.10', 'ip:203.0.113.11', 'ip:203.0.113.12', 'domain:decoy-one.net', 'ip:198.51.100.20', 'ip:198.51.100.21'].sort()
  );
  assert.equal(byVal(cands, 'vendor-tool.example')?.assessment, 'context_only');
});

test('fixture: no heading levels (PDF) — a label followed by rows inherits, a topic heading resets', () => {
  const d = doc([
    { id: 'h', type: 'heading', page: 12, text: 'Indicators' },
    { id: 'r1', type: 'list_item', layout: 'observable_row', page: 12, text: 'one[.]casino-x[.]com' },
    { id: 'r2', type: 'list_item', layout: 'observable_row', page: 12, text: 'two[.]casino-x[.]com' },
    { id: 'r3', type: 'list_item', layout: 'observable_row', page: 12, text: 'three[.]casino-x[.]com' },
    { id: 'f1', page: 12, text: '12 Casino Report 2026 | vendor.example-blog.com' },
    { id: 'run', type: 'heading', page: 13, text: 'CASINO REPORT' },
    { id: 'sub', type: 'heading', page: 13, text: 'Supporting IP Addresses for Illegal Casino Domains' },
    { id: 'r4', type: 'list_item', layout: 'observable_row', page: 13, text: '157[.]185[.]143[.]150' },
    { id: 'r5', type: 'list_item', layout: 'observable_row', page: 13, text: '146[.]103[.]91[.]133' },
    { id: 'f2', page: 13, text: '13 Casino Report 2026 | vendor.example-blog.com' },
    { id: 'run2', type: 'heading', page: 14, text: 'CASINO REPORT' },
    { id: 'concl', type: 'heading', page: 14, text: 'Conclusion' },
    { id: 'p', page: 14, text: 'Researchers at Example Labs (example-labs.org) contributed telemetry.' },
    { id: 'f3', page: 14, text: '14 Casino Report 2026 | vendor.example-blog.com' }
  ]);
  const z = annotateDocumentZones(d);
  const b = (id) => z.blocks.find((x) => x.id === id);
  assert.ok(['subgroup_label', 'typed_subheading'].includes(b('sub').zone_reason), b('sub').zone_reason);
  assert.equal(b('run').zone, 'header_footer', 'running header never closes the section');
  assert.equal(b('r4').zone, 'explicit_ioc_section');
  assert.equal(b('r5').zone, 'explicit_ioc_section');
  assert.equal(b('concl').zone_reason, 'heading_reset');
  assert.equal(b('p').zone, 'report_body');
  const cands = extractCandidatesFromDocument(d);
  assert.deepEqual(
    [...maliciousKeys(cands)].sort(),
    ['domain:one.casino-x.com', 'domain:two.casino-x.com', 'domain:three.casino-x.com', 'ip:157.185.143.150', 'ip:146.103.91.133'].sort()
  );
  assert.equal(byVal(cands, 'example-labs.org')?.assessment, 'context_only');
  assert.equal(summarizeCandidateSet(cands).ai_needed, 0);
});

test('a descriptive separator paragraph inside the section does not break scope', () => {
  const d = doc([
    { id: 'h', type: 'heading', text: 'Indicators of Compromise' },
    { id: 'r1', type: 'list_item', text: 'alpha-c2[.]net' },
    { id: 'sep', text: 'Additional infrastructure observed in wave 2' },
    { id: 'r2', type: 'list_item', text: 'beta-c2[.]net' },
    { id: 'sep2', text: 'Supporting IP Addresses' },
    { id: 'r3', type: 'list_item', text: '203[.]0[.]113[.]90' }
  ]);
  const cands = extractCandidatesFromDocument(d);
  assert.deepEqual([...maliciousKeys(cands)].sort(), ['domain:alpha-c2.net', 'domain:beta-c2.net', 'ip:203.0.113.90'].sort());
});

test('a new-topic heading of the same hierarchy closes the section even when rows follow', () => {
  const d = doc([
    { id: 'h', type: 'heading', level: 2, text: 'Indicators' },
    { id: 'r1', type: 'list_item', text: 'evil-one[.]net' },
    { id: 'h2', type: 'heading', level: 2, text: 'Frequently Asked Questions' },
    { id: 'q', type: 'list_item', text: 'Is support.vendor-example.com affected? No.' }
  ]);
  const z = annotateDocumentZones(d);
  assert.equal(z.blocks.find((b) => b.id === 'h2').zone_reason, 'heading_reset');
  assert.equal(z.blocks.find((b) => b.id === 'q').zone, 'report_body');
  const cands = extractCandidatesFromDocument(d);
  assert.equal(byVal(cands, 'evil-one.net').assessment, 'malicious');
  assert.notEqual(byVal(cands, 'support.vendor-example.com')?.assessment, 'malicious');
});

// ---------------------------------------------------------------------------
// Occurrence-level assertions inside C2 sections
// ---------------------------------------------------------------------------

test('C2 section: explicit rows and operational clauses assert; research / provider mentions stay context', () => {
  const d = doc([
    { id: 'h', type: 'heading', text: 'Command and Control Infrastructure' },
    { id: 'p1', text: 'Research by Example Consulting (example-consulting.net) first surfaced the cluster.' },
    { id: 'p2', text: 'The implant connects to panel-c2.example.net over TCP 8443 and beacons every 30 seconds.' },
    { id: 'p3', text: 'The actor purchased infrastructure from a VPS provider, cheap-vps-provider.com, to host it.' },
    { id: 'r1', type: 'list_item', text: 'listed-c2[.]net' },
    { id: 'p4', text: 'Operators also staged tooling on secondary-stage.net during the second wave.' }
  ]);
  const cands = extractCandidatesFromDocument(d);
  const research = byVal(cands, 'example-consulting.net');
  assert.equal(research.assessment, 'context_only');
  assert.equal(research.occurrences[0].occurrence_kind, OCCURRENCE_KINDS.NARRATIVE_CONTEXT);
  const c2 = byVal(cands, 'panel-c2.example.net');
  assert.equal(c2.assessment, 'malicious');
  assert.equal(c2.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  assert.equal(c2.occurrences[0].occurrence_kind, OCCURRENCE_KINDS.NARRATIVE_ASSERTION);
  const provider = byVal(cands, 'cheap-vps-provider.com');
  assert.equal(provider.assessment, 'context_only');
  assert.equal(provider.source_relation, SOURCE_RELATIONS.PROVIDER_SERVICE);
  const listed = byVal(cands, 'listed-c2.net');
  assert.equal(listed.assessment, 'malicious');
  assert.equal(listed.occurrences[0].occurrence_kind, OCCURRENCE_KINDS.LIST_ITEM);
  // An unmarked prose mention inside the section is evidence for the model, not a verdict either way.
  const staged = byVal(cands, 'secondary-stage.net');
  assert.equal(staged.assessment, 'unknown');
  assert.equal(staged.ai_needed, true);
  assert.equal(staged.policy_decision, 'ai_needed_authoritative_narrative');
  assert.equal(staged.occurrences[0].occurrence_kind, OCCURRENCE_KINDS.NARRATIVE_MENTION);
  assert.equal(summarizeCandidateSet(cands).ai_needed, 1);
  // …and the model's verdict is honoured for it, while it still cannot touch the research firm.
  const merged = mergeAiCandidateUpdates(cands, {
    candidate_updates: [
      { candidate_type: 'domain', normalized_value: 'secondary-stage.net', assessment: 'malicious', role: 'payload_hosting', confidence: 0.8 },
      { candidate_type: 'domain', normalized_value: 'example-consulting.net', assessment: 'malicious', role: 'command_and_control', confidence: 0.95 }
    ]
  });
  assert.equal(byVal(merged, 'secondary-stage.net').assessment, 'malicious');
  assert.equal(byVal(merged, 'example-consulting.net').assessment, 'context_only');
  assert.equal(summarizeCandidateSet(merged).ai_needed, 0);
});

test('same observable: contextual prose mention + explicit row → the row wins', () => {
  const d = doc([
    { id: 'h', type: 'heading', text: 'C2 Servers' },
    { id: 'p', text: 'According to researchers at Example Labs, dual-role.net was registered in March.' },
    { id: 'r', type: 'list_item', text: 'dual-role[.]net' }
  ]);
  const c = byVal(extractCandidatesFromDocument(d), 'dual-role.net');
  assert.equal(c.assessment, 'malicious');
  assert.equal(c.occurrences.filter((o) => o.asserted).length, 1);
});

test('relation detail: zone is evidence, not proof', () => {
  const ctx = { zone: 'c2_section', value: 'interisle.net', form: 'standalone', blockType: 'paragraph' };
  const research = classifySourceRelationDetail('Greg Aaron of Interisle Consulting (interisle[.]net) flagged a casino domain', ctx);
  assert.equal(research.relation, SOURCE_RELATIONS.CONTEXTUAL);
  assert.equal(research.marker, 'contextual');
  const op = classifySourceRelationDetail('the payload beacons to interisle.net every hour', ctx);
  assert.equal(op.relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  const row = classifySourceRelationDetail('interisle[.]net', { ...ctx, form: 'list_row' });
  assert.equal(row.marker, 'structural_row');
  const bodyRow = classifySourceRelationDetail('interisle[.]net', { zone: 'report_body', value: 'interisle.net', form: 'list_row' });
  assert.equal(bodyRow.relation, SOURCE_RELATIONS.CONTEXTUAL, 'a row outside any authoritative section asserts nothing by itself');
});

test('row-shape helpers', () => {
  assert.equal(isIndicatorRowShape('vip311[.]cc – Decoy domain', 'vip311.cc'), true);
  assert.equal(isIndicatorRowShape('C2 203.0.113.44', '203.0.113.44'), true);
  assert.equal(isIndicatorRowShape('Domain: evil.example', 'evil.example'), true);
  assert.equal(isIndicatorRowShape('The backdoor connects to 203.0.113.88 for command and control.', '203.0.113.88'), false);
  assert.equal(isIndicatorRowShape('Figure 6. A closer view of the screenshot of the player embedded into the low-quality casino website associated with 1862[.]cc', '1862.cc'), false);
  assert.equal(isObservableListLine('36.35.56.0/24 36.49.207.0/24 116.142.9.0/24'), true);
  assert.equal(isObservableListLine('e2db5db12564d2a9da7ef3a57aa23d95782f5eaddc8bd35eb7c35ae6b844a0f0 dede8bfb55c2e6479d89b1e73e0712791cf16a7179325804fc4bc13f708d08ae'), true);
  assert.equal(isObservableListLine('Trend Micro documented a campaign'), false);
  assert.equal(isObservableListLine('1. 203[.]0[.]113[.]5'), true);
});

// ---------------------------------------------------------------------------
// Scheme-less host/path outside an authoritative section
// ---------------------------------------------------------------------------

test('scheme-less host/path in a narrative-only report: one URL on the AI path, no host explosion, no scheme', () => {
  const cands = extractCandidatesFromDocument(
    doc([{ text: 'The loader fetches its second stage from cdn-stage.example.net/assets/loader.bin before sleeping.' }])
  );
  const url = cands.find((c) => c.candidate_type === 'url');
  assert.ok(url);
  assert.equal(url.normalized_value, 'cdn-stage.example.net/assets/loader.bin');
  assert.equal(url.parsed.scheme_less, true);
  assert.equal(url.parsed.path, '/assets/loader.bin');
  assert.equal(url.ai_needed, true, 'no appendix → the model classifies the narrative assertion');
  assert.equal(url.source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  assert.equal(cands.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'cdn-stage.example.net'), false);
  assert.equal(cands.some((c) => String(c.normalized_value).includes('loader.bin') && c.candidate_type !== 'url'), false);
  assert.equal(cands.some((c) => /^https?:\/\//.test(String(c.normalized_value))), false);
});

test('scheme-less host/path: code-shaped hosts and absolute URLs are untouched', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { text: 'Built on Node.js/Express with a React front end.' },
      { text: 'Payload hosted at hxxps://drop.example.net/files/a.exe was replaced later.' }
    ])
  );
  assert.equal(cands.some((c) => c.candidate_type === 'url' && /node\.js/i.test(c.normalized_value)), false);
  const abs = cands.find((c) => c.candidate_type === 'url');
  assert.equal(abs.normalized_value, 'https://drop.example.net/files/a.exe');
  assert.equal(cands.filter((c) => c.candidate_type === 'url').length, 1);
});

test('scheme-less host/path row inside an indicator section is a deterministic URL assertion', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: 'Indicators of Compromise' },
      { id: 'r1', type: 'list_item', text: 'js.cache-mcp[.]com/layer.js' },
      { id: 'r2', type: 'list_item', text: 'cache-mcp[.]com' }
    ])
  );
  const url = cands.find((c) => c.candidate_type === 'url');
  assert.equal(url.normalized_value, 'js.cache-mcp.com/layer.js');
  assert.equal(url.assessment, 'malicious');
  assert.equal(url.ai_needed, false);
  assert.equal(cands.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'js.cache-mcp.com'), false);
  assert.equal(byVal(cands, 'cache-mcp.com').assessment, 'malicious');
});

// ---------------------------------------------------------------------------
// Multi-format / multi-language
// ---------------------------------------------------------------------------

test('Turkish plain text: descriptive Göstergeler heading, short sub-groups, research firm stays context', () => {
  const text = [
    'Komuta Kontrol Altyapısı',
    'Örnek Araştırma firması (ornek-arastirma.com.tr) kampanyayı ilk raporlayan ekipti.',
    'Zararlı 203.0.113.9:8443 adresine bağlanır.',
    'Göstergeler: Kampanya Altyapısı',
    'kotu-c2.ornek.net',
    'Destekleyici IP Adresleri',
    '198[.]51[.]100[.]7',
    '198[.]51[.]100[.]8',
    'Kaynaklar',
    '[1] https://arastirma.ornek-firma.com.tr/rapor'
  ].join('\n');
  const { blocks } = plainTextToBlocks(text, 1, 1);
  const cands = extractCandidatesFromDocument(createCanonicalDocument({ title: 'TR', language: 'tr', blocks }));
  assert.equal(byVal(cands, 'ornek-arastirma.com.tr')?.assessment, 'context_only');
  assert.equal(byVal(cands, '203.0.113.9')?.assessment, 'malicious');
  assert.equal(byVal(cands, 'kotu-c2.ornek.net')?.assessment, 'malicious');
  assert.equal(byVal(cands, '198.51.100.7')?.assessment, 'malicious');
  assert.equal(byVal(cands, '198.51.100.8')?.assessment, 'malicious');
  assert.equal(cands.find((c) => String(c.normalized_value).includes('arastirma.ornek-firma.com.tr'))?.assessment, 'context_only');
});

test('Chinese headings: 威胁指标 with a descriptive suffix, a 2-row sub-group and a 参考链接 section', () => {
  const cands = extractCandidatesFromDocument(
    doc(
      [
        { id: 'h1', type: 'heading', text: '威胁指标：活动A' },
        { id: 'r1', type: 'list_item', text: 'c2-one[.]example[.]com' },
        { id: 'sub', type: 'heading', text: '相关IP地址' },
        { id: 'r2', type: 'list_item', text: '203[.]0[.]113[.]44' },
        { id: 'r3', type: 'list_item', text: '203[.]0[.]113[.]45' },
        { id: 'h2', type: 'heading', text: '参考链接' },
        { id: 'b2', text: 'https://research.example.org/prior' }
      ],
      { language: 'zh' }
    )
  );
  assert.equal(byVal(cands, 'c2-one.example.com')?.assessment, 'malicious');
  assert.equal(byVal(cands, '203.0.113.44')?.assessment, 'malicious');
  assert.equal(byVal(cands, '203.0.113.45')?.assessment, 'malicious');
  assert.equal(cands.find((c) => String(c.normalized_value).includes('research.example.org'))?.assessment, 'context_only');
});

test('PDF page continuation: a 1-row group split across a page break with a running footer keeps scope', () => {
  const d = doc([
    { id: 'h', type: 'heading', page: 5, text: 'Indicators – Network Infrastructure' },
    { id: 'r1', type: 'list_item', layout: 'observable_row', page: 5, text: 'first[.]casino-y[.]com' },
    { id: 'r2', type: 'list_item', layout: 'observable_row', page: 5, text: 'second[.]casino-y[.]com' },
    { id: 'f1', page: 5, layout: 'page_edge', text: '5 | Vendor Research' },
    { id: 'f2', page: 6, layout: 'page_edge', text: '6 | Vendor Research' },
    { id: 'lbl', page: 6, text: 'Decoy domains' },
    { id: 'r3', type: 'list_item', layout: 'observable_row', page: 6, text: 'decoy[.]casino-y[.]com' }
  ]);
  const cands = extractCandidatesFromDocument(d);
  assert.deepEqual(
    [...maliciousKeys(cands)].sort(),
    ['domain:first.casino-y.com', 'domain:second.casino-y.com', 'domain:decoy.casino-y.com'].sort()
  );
  assert.equal(summarizeCandidateSet(cands).ai_needed, 0);
});

test('discovery fallback unchanged: an unlabelled 2-row list in body text is not an assertion', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'p', text: 'We observed the following during the investigation.' },
      { id: 'r1', type: 'list_item', text: 'maybe-one[.]net' },
      { id: 'r2', type: 'list_item', text: 'maybe-two[.]net' }
    ])
  );
  for (const v of ['maybe-one.net', 'maybe-two.net']) {
    assert.notEqual(byVal(cands, v).assessment, 'malicious', v);
    assert.equal(byVal(cands, v).ai_needed, true, v);
  }
});
