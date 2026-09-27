/**
 * Occurrence provenance vs candidate-level decision (Issue A).
 *
 * A candidate identity aggregates occurrences. Each occurrence keeps its local
 * relation. The candidate decision is derived from the complete set:
 *   - strongestSourceRelation is a routing rank (operational > provider >
 *     contextual > reference), not "first wins" / "last wins" / "malicious
 *     assessment always wins";
 *   - mixed narrative evidence stays on the AI path with every local excerpt;
 *   - an explicit table/list assertion stays authoritative regardless of
 *     surrounding benign prose or paragraph order.
 *
 * Paragraph order of equivalent evidence must not change that decision.
 * One occurrence per block remains the extraction model (two spans in the
 * same paragraph collapse); that is not the Case 8 paragraph-order contract.
 *
 * Synthetic values only — no publisher names or production IOCs.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import {
  buildAnalysisChunks,
  buildChunkRequest,
  candidatesForChunk,
  partitionCandidatesForAi,
  withCandidateIds
} from './ai/analyze.js';
import { SOURCE_RELATIONS } from './indicatorScope.js';

const SRC = 'https://research.example/blog/synthetic-occurrence-order/';
const DOMAIN = 'relay-node.com';
const MD5 = '0123456789abcdef0123456789abcdef';

function fromBlocks(blocks) {
  const document = createCanonicalDocument({
    title: 'Synthetic occurrence order',
    language: 'en',
    blocks: blocks.map((b, i) => ({
      id: b.id || `b${i + 1}`,
      type: b.type || 'paragraph',
      page: 1,
      text: b.text,
      ...(b.table ? { table: b.table } : {}),
      ...(b.layout ? { layout: b.layout } : {})
    }))
  });
  return { document, candidates: extractCandidatesFromDocument(document) };
}

function fromHtml(body) {
  const html = `<!doctype html><html lang="en"><head><title>Synthetic</title></head><body><article>
<h1>Synthetic occurrence order</h1>
<p>The synthetic analysis describes the delivery chain and the operator tradecraft observed across several environments.</p>
${body}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SRC, finalUrl: SRC, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return { document: r.document, ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SRC }) };
}

const find = (cands, type, value) =>
  cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;

function decisionOf(c) {
  return {
    assessment: c.assessment,
    role: c.role,
    policy: c.policy_decision,
    assertion: c.source_assertion,
    relation: c.source_relation,
    ai_needed: c.ai_needed,
    strength: c.evidence_strength
  };
}

function occurrenceBag(c) {
  return (c.occurrences || [])
    .map((o) => `${o.source_relation}/${o.relation_marker}/${o.occurrence_kind}`)
    .sort();
}

function classifyLine(document, candidates, value) {
  const partition = partitionCandidatesForAi(withCandidateIds(candidates));
  const chunks = buildAnalysisChunks(document);
  const idx = chunks.findIndex((ch) =>
    candidatesForChunk(partition.toClassify, ch, false).some((c) => c.normalized_value === value)
  );
  if (idx < 0) return { inClassify: false, line: null, excerpts: [] };
  const { user } = buildChunkRequest({
    document,
    chunk: chunks[idx],
    chunkIndex: idx,
    chunkTotal: chunks.length,
    partition,
    sourceHost: 'research.example'
  });
  const line = user.split('\n').find((l) => l.startsWith('- candidate_id') && l.includes(`value=${value}`)) || null;
  const excerpts = line ? [...line.matchAll(/\(([^)]*)\)(?: \||\])/g)].map((m) => m[1]) : [];
  return { inClassify: true, line, excerpts };
}

function assertOrderInvariant(a, b, value, type) {
  const ca = find(a.candidates, type, value);
  const cb = find(b.candidates, type, value);
  assert.ok(ca && cb, `${type}:${value} must exist in both orders`);
  assert.deepEqual(decisionOf(ca), decisionOf(cb), 'candidate decision must be order-invariant');
  assert.deepEqual(occurrenceBag(ca), occurrenceBag(cb), 'occurrence relation bag must be order-invariant');
  const pa = classifyLine(a.document, a.candidates, value);
  const pb = classifyLine(b.document, b.candidates, value);
  assert.equal(pa.inClassify, pb.inClassify);
  if (pa.inClassify) {
    assert.deepEqual([...pa.excerpts].sort(), [...pb.excerpts].sort(), 'AI must see the same occurrence excerpts');
  }
}

const FALLBACK = { id: 'b1', text: 'Users who lack the required parameter are redirected to relay-node.com as a fallback landing page.' };
const C2 = { id: 'b2', text: 'The malware communicates with relay-node.com as its C2 server.' };
const HASH_ID = { id: 'b1', text: `The identifier ${MD5} appears in the download URL.` };
const HASH_MAL = { id: 'b2', text: `The malicious payload has MD5 ${MD5}.` };

test('A1: URL-contained hash is suppressed; standalone occurrence owns evidence and relation', () => {
  const { candidates, document } = fromHtml(`
<p>The payload is available at https://files-relay.com/files/${MD5} for download.</p>
<p>The malicious attachment has MD5 ${MD5}.</p>`);
  const c = find(candidates, 'md5', MD5);
  assert.ok(c);
  assert.equal(c.occurrences.length, 1);
  assert.equal(c.occurrences[0].form, 'standalone');
  assert.match(c.occurrences[0].surrounding_text, /malicious attachment has MD5/);
  assert.doesNotMatch(c.occurrences[0].surrounding_text, /https?:\/\//);
  assert.match(c.evidence_text, /malicious attachment has MD5/);
  assert.doesNotMatch(c.evidence_text, /files-relay\.com\/files/);
  const alone = find(fromHtml(`<p>The malicious attachment has MD5 ${MD5}.</p>`).candidates, 'md5', MD5);
  assert.equal(c.occurrences[0].source_relation, alone.occurrences[0].source_relation);
  assert.equal(c.occurrences[0].relation_marker, alone.occurrences[0].relation_marker);
  const { excerpts } = classifyLine(document, candidates, MD5);
  assert.equal(excerpts.length, 1);
  assert.match(excerpts[0], /malicious attachment has MD5/);
  assert.doesNotMatch(excerpts[0], /files-relay/);
});

test('A2/A3: benign then C2 domain — paragraph order does not change the candidate decision', () => {
  const ab = fromBlocks([FALLBACK, C2]);
  const ba = fromBlocks([C2, FALLBACK]);
  const c = find(ab.candidates, 'domain', DOMAIN);
  assert.equal(c.occurrences.length, 2);
  assert.equal(c.source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  assert.equal(c.ai_needed, true);
  assert.equal(c.assessment, 'unknown');
  assert.notEqual(c.policy_decision, 'context_only_narrative_with_authoritative_scope');
  const relations = c.occurrences.map((o) => o.source_relation).sort();
  assert.deepEqual(relations, [SOURCE_RELATIONS.CONTEXTUAL, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS].sort());
  const { excerpts } = classifyLine(ab.document, ab.candidates, DOMAIN);
  assert.equal(excerpts.length, 2);
  assert.ok(excerpts.some((e) => /fallback landing page/.test(e)));
  assert.ok(excerpts.some((e) => /C2 server/.test(e)));
  assertOrderInvariant(ab, ba, DOMAIN, 'domain');
});

test('A4/A5: identifier then malicious hash — paragraph order does not change the candidate decision', () => {
  const ab = fromBlocks([HASH_ID, HASH_MAL]);
  const ba = fromBlocks([HASH_MAL, HASH_ID]);
  const c = find(ab.candidates, 'md5', MD5);
  assert.equal(c.occurrences.length, 2);
  assert.equal(c.source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  assert.equal(c.ai_needed, true);
  assert.equal(c.assessment, 'unknown');
  assertOrderInvariant(ab, ba, MD5, 'md5');
});

test('A6: neutral mention then operational domain keeps malicious evidence available', () => {
  const amb = { id: 'b1', text: 'Analysts also recorded relay-node.com during the investigation.' };
  const ab = fromBlocks([amb, C2]);
  const ba = fromBlocks([C2, amb]);
  const c = find(ab.candidates, 'domain', DOMAIN);
  assert.ok(c.occurrences.some((o) => o.source_relation === SOURCE_RELATIONS.OPERATIONAL_MALICIOUS));
  assert.equal(c.ai_needed, true);
  assertOrderInvariant(ab, ba, DOMAIN, 'domain');
});

test('A7/A8: explicit IOC table remains authoritative next to benign narrative, either order', () => {
  const heading = { id: 'h', type: 'heading', text: 'Indicators of Compromise' };
  const table = {
    id: 'tbl',
    type: 'table',
    text: `Type | Value ¶ Domain | ${DOMAIN}`,
    layout: 'table',
    table: { headers: ['Type', 'Value'], rows: [['Domain', DOMAIN]] }
  };
  const narrative = { id: 'b1', text: `Research by Example Consulting (${DOMAIN}) flagged the campaign.` };
  const ab = fromBlocks([heading, table, narrative]);
  const ba = fromBlocks([narrative, heading, table]);
  for (const pack of [ab, ba]) {
    const c = find(pack.candidates, 'domain', DOMAIN);
    assert.equal(c.assessment, 'malicious');
    assert.equal(c.policy_decision, 'explicit_report_assertion');
    assert.equal(c.ai_needed, false);
    assert.equal(c.occurrences.length, 2);
    assert.ok(c.occurrences.some((o) => o.form === 'table_row' && o.asserted === true));
    assert.ok(c.occurrences.some((o) => o.occurrence_kind === 'narrative_context'));
  }
  assert.deepEqual(decisionOf(find(ab.candidates, 'domain', DOMAIN)), decisionOf(find(ba.candidates, 'domain', DOMAIN)));
  assert.deepEqual(occurrenceBag(find(ab.candidates, 'domain', DOMAIN)), occurrenceBag(find(ba.candidates, 'domain', DOMAIN)));
});

test('A9: redirector then C2 keeps both occurrence excerpts; candidate has one role slot', () => {
  const red = { id: 'b1', text: 'Victims are first sent to relay-node.com, which the operators used as a redirector.' };
  const ab = fromBlocks([red, C2]);
  const ba = fromBlocks([C2, red]);
  const c = find(ab.candidates, 'domain', DOMAIN);
  assert.equal(c.occurrences.length, 2);
  assert.equal(c.source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  assert.equal(c.ai_needed, true);
  assert.equal(c.role, 'unknown', 'narrative multi-role evidence is not collapsed into a guessed role');
  const { excerpts } = classifyLine(ab.document, ab.candidates, DOMAIN);
  assert.ok(excerpts.some((e) => /redirector/.test(e)));
  assert.ok(excerpts.some((e) => /C2 server/.test(e)));
  assertOrderInvariant(ab, ba, DOMAIN, 'domain');
});

test('A10: contradictory benign + attacker-controlled evidence stays on the AI path with both records', () => {
  const benign = { id: 'b1', text: 'relay-node.com is legitimate infrastructure used by customers as a fallback.' };
  const mal = { id: 'b2', text: 'Elsewhere the report states the malware communicates with relay-node.com as its attacker-controlled C2 server.' };
  const ab = fromBlocks([benign, mal]);
  const ba = fromBlocks([mal, benign]);
  const c = find(ab.candidates, 'domain', DOMAIN);
  assert.equal(c.occurrences.length, 2);
  assert.ok(c.occurrences.some((o) => o.relation_marker === 'benign'));
  assert.ok(c.occurrences.some((o) => o.source_relation === SOURCE_RELATIONS.OPERATIONAL_MALICIOUS));
  assert.equal(c.ai_needed, true, 'conflict is not resolved by a simplistic precedence rule');
  assert.equal(c.assessment, 'unknown');
  assert.notEqual(c.policy_decision, 'context_only_benign_component');
  const { excerpts } = classifyLine(ab.document, ab.candidates, DOMAIN);
  assert.equal(excerpts.length, 2);
  assertOrderInvariant(ab, ba, DOMAIN, 'domain');
});

test('same block: two spans collapse to one occurrence (clause-local); both orders still reach AI', () => {
  const ab = fromBlocks([{
    id: 'same',
    text: 'Users who lack the required parameter are redirected to relay-node.com as a fallback landing page. The malware communicates with relay-node.com as its C2 server.'
  }]);
  const ba = fromBlocks([{
    id: 'same',
    text: 'The malware communicates with relay-node.com as its C2 server. Users who lack the required parameter are redirected to relay-node.com as a fallback landing page.'
  }]);
  const ca = find(ab.candidates, 'domain', DOMAIN);
  const cb = find(ba.candidates, 'domain', DOMAIN);
  assert.equal(ca.occurrences.length, 1);
  assert.equal(cb.occurrences.length, 1);
  assert.equal(ca.ai_needed, true);
  assert.equal(cb.ai_needed, true);
  assert.equal(ca.occurrences[0].source_relation, SOURCE_RELATIONS.CONTEXTUAL);
  assert.equal(cb.occurrences[0].source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
});
