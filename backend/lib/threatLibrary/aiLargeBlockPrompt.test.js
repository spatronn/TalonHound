/**
 * Large-block AI prompt construction (Issue B).
 *
 * Flatten budget is 100_000 characters for the serialized chunk body.
 * A single block larger than that is omitted entirely; the TO CLASSIFY
 * evidence excerpt (60 chars each side of the observable) must still carry
 * the value and its local relation. Mid-size blocks stay in the prompt.
 * Script tags are stripped by HTML extraction; <pre><code> is a code block
 * and is flattened when it fits the budget (no extra classifier).
 *
 * Synthetic values only.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, flattenCanonicalText } from './canonicalDocument.js';
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
import { evidenceExcerpt, EVIDENCE_EXCERPT_SIDE_CHARS } from './ai/prompts.js';

const SRC = 'https://research.example/blog/synthetic-large-block/';
const DOMAIN = 'relay-node.com';
const OTHER = 'payload-drop.net';
const MD5 = '0123456789abcdef0123456789abcdef';
const PROSE = 'Long technical narrative sentence about the intrusion chain and tooling. ';

function fromBlocks(blocks) {
  const document = createCanonicalDocument({
    title: 'Synthetic large-block prompt',
    language: 'en',
    blocks: blocks.map((b, i) => ({
      id: b.id || `b${i + 1}`,
      type: b.type || 'paragraph',
      page: 1,
      text: b.text
    }))
  });
  return { document, candidates: withCandidateIds(extractCandidatesFromDocument(document)) };
}

function fromHtml(body) {
  const html = `<!doctype html><html lang="en"><head><title>Synthetic</title></head><body><article>
<h1>Synthetic large-block prompt</h1>
<p>The synthetic analysis describes the delivery chain and the operator tradecraft observed across several environments.</p>
${body}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SRC, finalUrl: SRC, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return {
    document: r.document,
    candidates: withCandidateIds(extractCandidatesWithDiagnostics(r.document, { sourceUrl: SRC }).candidates)
  };
}

function promptFor(document, candidates, value) {
  const partition = partitionCandidatesForAi(candidates);
  const chunks = buildAnalysisChunks(document);
  const idx = chunks.findIndex((ch) =>
    candidatesForChunk(partition.toClassify, ch, false).some((c) => c.normalized_value === value)
  );
  assert.ok(idx >= 0, `${value} is not a TO CLASSIFY candidate`);
  const { user, promptChars } = buildChunkRequest({
    document,
    chunk: chunks[idx],
    chunkIndex: idx,
    chunkTotal: chunks.length,
    partition,
    sourceHost: 'research.example'
  });
  const line = user.split('\n').find((l) => l.startsWith('- candidate_id') && l.includes(`value=${value}`));
  assert.ok(line, `no evidence line for ${value}`);
  const excerpts = [...line.matchAll(/\(([^)]*)\)(?: \||\])/g)].map((m) => m[1]);
  const flatten = flattenCanonicalText({ ...document, blocks: chunks[idx].blocks }, { maxChars: 100_000 });
  return {
    user,
    promptChars,
    approxTokens: Math.ceil(promptChars / 4),
    excerpts,
    line,
    blockInPrompt: flatten.includes(value),
    flattenChars: flatten.length,
    chunkChars: chunks[idx].chars,
    chunks: chunks.length,
    chunkSizes: chunks.map((c) => ({ blocks: c.blocks.length, chars: c.chars }))
  };
}

test('B1: candidate near the start of a >100k block — excerpt keeps value and relation; block omitted', () => {
  const text = `${DOMAIN} is the C2 server used by the malware. ${PROSE.repeat(1800)}`;
  const { document, candidates } = fromBlocks([{ id: 'huge', text }]);
  const p = promptFor(document, candidates, DOMAIN);
  assert.ok(text.length > 100_000, `precondition: ${text.length}`);
  assert.equal(p.flattenChars, 0, 'block larger than flatten budget is omitted');
  assert.equal(p.blockInPrompt, false);
  assert.match(p.excerpts[0], new RegExp(`${DOMAIN} is the C2 server`));
  assert.ok(p.promptChars < 12_000, `bounded prompt, got ${p.promptChars}`);
});

test('B2: candidate near the middle of a >100k block still has local evidence', () => {
  const text = `${PROSE.repeat(900)} The malware communicates with ${DOMAIN} as its C2 server. ${PROSE.repeat(900)}`;
  const { document, candidates } = fromBlocks([{ id: 'huge', text }]);
  const p = promptFor(document, candidates, DOMAIN);
  assert.equal(p.flattenChars, 0);
  assert.match(p.excerpts[0], new RegExp(`malware communicates with ${DOMAIN} as its C2 server`));
  assert.ok(p.excerpts[0].includes(DOMAIN));
});

test('B3: candidate near the end cannot disappear because the block was omitted', () => {
  const text = `${PROSE.repeat(1800)} The malware communicates with ${DOMAIN} as its C2 server.`;
  const { document, candidates } = fromBlocks([{ id: 'huge', text }]);
  const p = promptFor(document, candidates, DOMAIN);
  assert.equal(p.flattenChars, 0);
  assert.match(p.excerpts[0], new RegExp(`malware communicates with ${DOMAIN}`));
});

test('B4: relation before the candidate survives omission', () => {
  const text = `${PROSE.repeat(1800)} The malware communicates with ${DOMAIN}.`;
  const { document, candidates } = fromBlocks([{ id: 'huge', text }]);
  const p = promptFor(document, candidates, DOMAIN);
  assert.match(p.excerpts[0], /malware communicates with/);
  assert.ok(p.excerpts[0].includes(DOMAIN));
});

test('B5: relation after the candidate survives omission', () => {
  const text = `${PROSE.repeat(1800)} ${DOMAIN} is used as the C2 server by the implant.`;
  const { document, candidates } = fromBlocks([{ id: 'huge', text }]);
  const p = promptFor(document, candidates, DOMAIN);
  assert.match(p.excerpts[0], new RegExp(`${DOMAIN} is used as the C2 server`));
});

test('B6: two candidates in one huge block each get their own excerpt; the block is not multiplied', () => {
  const text = `${PROSE.repeat(900)} The malware communicates with ${DOMAIN} as its C2 server. ${'Long technical narrative sentence about staging and exfiltration. '.repeat(900)} The implant later downloads a payload from ${OTHER}.`;
  const { document, candidates } = fromBlocks([{ id: 'huge', text }]);
  const pa = promptFor(document, candidates, DOMAIN);
  const pb = promptFor(document, candidates, OTHER);
  assert.equal(pa.flattenChars, 0);
  assert.equal(pa.chunks, pb.chunks);
  assert.match(pa.excerpts[0], new RegExp(`communicates with ${DOMAIN}`));
  assert.match(pb.excerpts[0], new RegExp(`downloads a payload from ${OTHER}`));
  assert.equal(pa.excerpts[0].includes(OTHER), false, 'A is not described by B\'s clause');
  assert.equal(pb.excerpts[0].includes(DOMAIN), false, 'B is not described by A\'s clause');
  assert.equal(pa.promptChars, pb.promptChars, 'one prompt, two excerpt lines — block not duplicated');
});

test('B7: HTML <script> is stripped; a <pre><code> block under the flatten budget is included', () => {
  const js = `function x(){${'var a=1;'.repeat(8000)}hash="${MD5}";host="${DOMAIN}";}`;
  const { document, candidates } = fromHtml(`<script>window.__noise="${MD5}";</script><pre><code>${js}</code></pre><p>The malicious attachment has MD5 ${MD5}.</p>`);
  const code = document.blocks.find((b) => b.type === 'code');
  assert.ok(code, 'pre/code becomes a code block');
  assert.ok(code.text.length < 100_000, `precondition: ${code.text.length}`);
  assert.equal(code.text.includes('window.__noise'), false, 'script tags never reach the document');
  const p = promptFor(document, candidates, MD5);
  assert.equal(p.blockInPrompt, true, 'code block under 100k is flattened');
  assert.ok(p.excerpts.some((e) => e.includes(MD5)));
  assert.ok(p.excerpts.some((e) => /malicious attachment has MD5/.test(e)));
  assert.ok(p.promptChars < 80_000, `code-sized prompt stays under the flatten ceiling, got ${p.promptChars}`);
});

test('B8: long technical prose under the flatten budget is included as a normal block', () => {
  const text = `${PROSE.repeat(80)} The malware communicates with ${DOMAIN} as its C2 server.`;
  assert.ok(text.length < 14_000);
  const { document, candidates } = fromBlocks([{ id: 'prose', text }]);
  const p = promptFor(document, candidates, DOMAIN);
  assert.ok(p.flattenChars > 0);
  assert.equal(p.blockInPrompt, true);
  assert.match(p.excerpts[0], new RegExp(`communicates with ${DOMAIN}`));
});

test('B9: evidenceExcerpt alone is enough when the block is omitted', () => {
  const text = `${PROSE.repeat(1800)} The dropper recovered from the victim host has MD5 ${MD5}.`;
  const { document, candidates } = fromBlocks([{ id: 'huge', text }]);
  const c = candidates.find((x) => x.normalized_value === MD5);
  const excerpt = evidenceExcerpt(c.occurrences[0].surrounding_text, [MD5]);
  assert.ok(excerpt.includes(MD5));
  assert.match(excerpt, /dropper recovered from the victim host has MD5/);
  assert.ok(excerpt.length <= 2 * EVIDENCE_EXCERPT_SIDE_CHARS + MD5.length + 8);
  const p = promptFor(document, candidates, MD5);
  assert.equal(p.flattenChars, 0);
  assert.match(p.excerpts[0], /dropper recovered from the victim host has MD5/);
});

test('B10: many mid-size blocks stay near the per-chunk budget and do not explode prompt size', () => {
  const blocks = [];
  for (let i = 0; i < 12; i += 1) {
    blocks.push({
      id: `h${i}`,
      text: `${'Long technical narrative sentence about the intrusion chain. '.repeat(80)} Host node-${i}.relay-lab.com was observed.`
    });
  }
  blocks.push({ id: 'c2', text: `The malware communicates with ${DOMAIN} as its C2 server.` });
  const { document, candidates } = fromBlocks(blocks);
  const partition = partitionCandidatesForAi(candidates);
  const chunks = buildAnalysisChunks(document);
  const sizes = chunks.map((chunk, i) => {
    const { promptChars } = buildChunkRequest({
      document,
      chunk,
      chunkIndex: i,
      chunkTotal: chunks.length,
      partition,
      sourceHost: 'research.example'
    });
    return { chars: chunk.chars, promptChars, approxTokens: Math.ceil(promptChars / 4), blocks: chunk.blocks.length };
  });
  assert.ok(chunks.length >= 2, 'long report is chunked');
  for (const s of sizes) {
    assert.ok(s.chars <= 16_000, `chunk body near 14k grouping budget, got ${s.chars}`);
    assert.ok(s.promptChars < 25_000, `serialized prompt stays bounded, got ${s.promptChars}`);
  }
  const p = promptFor(document, candidates, DOMAIN);
  assert.match(p.excerpts[0], new RegExp(`communicates with ${DOMAIN}`));
});
