/**
 * AI context delivery: the per-occurrence evidence excerpt in a TO CLASSIFY
 * line is centered on the observable. The value itself is never cut and the
 * local relation on either side survives, because the block text is not always
 * in the same prompt (a block larger than the flatten budget, or an
 * overflowing last chunk, is not flattened).
 *
 * Also pins the stale-candidate contract: reports extracted before v12 re-run
 * extraction on Retry instead of reusing stale candidates.
 *
 * Synthetic values only.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import {
  buildAnalysisChunks,
  buildChunkRequest,
  candidatesForChunk,
  partitionCandidatesForAi,
  withCandidateIds
} from './ai/analyze.js';
import { evidenceExcerpt, formatCandidateEvidenceLine, EVIDENCE_EXCERPT_SIDE_CHARS } from './ai/prompts.js';
import { decideCandidateReuse } from './pipeline.js';

const SRC = 'https://research.example/blog/synthetic-context/';
const H1 = `aaaaaaaa${'0123456789abcdef'}01234567`;
const H2 = `bbbbbbbb${'0123456789abcdef'}01234567`;
const S256 = '0123456789abcdef'.repeat(4);
const LEAD =
  'During the second phase of the intrusion the operators staged several archives on the compromised file server and later removed most traces of the activity from the host,';

function analyze(body) {
  const html = `<!doctype html><html lang="en"><head><title>Synthetic</title></head><body><article>
<h1>Synthetic context delivery</h1>
<p>The synthetic analysis describes the delivery chain and the operator tradecraft observed across several environments.</p>
${body}
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SRC, finalUrl: SRC, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  const candidates = withCandidateIds(extractCandidatesWithDiagnostics(r.document, { sourceUrl: SRC }).candidates);
  const partition = partitionCandidatesForAi(candidates);
  const chunks = buildAnalysisChunks(r.document);
  return { document: r.document, candidates, partition, chunks };
}

/** The TO CLASSIFY line for `value` and whether its block text is in the same prompt. */
function lineFor(ctx, value) {
  const idx = ctx.chunks.findIndex((ch) =>
    candidatesForChunk(ctx.partition.toClassify, ch, false).some((c) => c.normalized_value === value)
  );
  assert.ok(idx >= 0, `${value} is not a TO CLASSIFY candidate`);
  const { user } = buildChunkRequest({
    document: ctx.document,
    chunk: ctx.chunks[idx],
    chunkIndex: idx,
    chunkTotal: ctx.chunks.length,
    partition: ctx.partition,
    sourceHost: 'research.example'
  });
  const lines = user.split('\n');
  const line = lines.find((l) => l.startsWith('- candidate_id') && l.includes(`value=${value}`));
  assert.ok(line, `no evidence line for ${value}`);
  const excerpts = [...line.matchAll(/\[b\d+\]\((.*?)\)(?: \||\])/g)].map((m) => m[1]);
  return { line, excerpts, blockInPrompt: lines.some((l) => /^\[b\d+\|/.test(l) && l.includes(value)) };
}

test('1. IOC at the start: value and the relation after it', () => {
  const ctx = analyze(`<p>${H1} is the MD5 of the malicious attachment delivered to victims.</p>`);
  const [e] = lineFor(ctx, H1).excerpts;
  assert.ok(e.includes(H1));
  assert.match(e, /malicious attachment/);
});

test('2. IOC at the end of a long sentence: the value is never clipped', () => {
  const ctx = analyze(`<p>${LEAD} and the analysed malicious attachment was recovered from the mail gateway, MD5: ${H1}</p>`);
  const [e] = lineFor(ctx, H1).excerpts;
  assert.ok(e.includes(H1));
  assert.match(e, /mail gateway, MD5:/);
});

test('3. relation after the IOC survives', () => {
  const ctx = analyze(`<p>${LEAD} leaving only ${H1}, which researchers confirmed is the malicious payload used by the campaign.</p>`);
  const [e] = lineFor(ctx, H1).excerpts;
  assert.ok(e.includes(H1));
  assert.match(e, /confirmed is the malicious payload/);
});

test('4. relation before the IOC survives', () => {
  const ctx = analyze(`<p>The malicious payload has SHA256 ${S256}.</p>`);
  const [e] = lineFor(ctx, S256).excerpts;
  assert.match(e, new RegExp(`malicious payload has SHA256 ${S256}`));
});

test('5. long clause: the excerpt is the IOC neighbourhood, not the paragraph head', () => {
  const ctx = analyze(`<p>The malicious payload dropped by the loader ${LEAD} ${LEAD} was identified by MD5 ${H1} in the sandbox.</p>`);
  const [e] = lineFor(ctx, H1).excerpts;
  assert.match(e, new RegExp(`identified by MD5 ${H1} in the sandbox`));
  assert.ok(e.length <= 2 * EVIDENCE_EXCERPT_SIDE_CHARS + H1.length, 'bounded excerpt');
});

test('6. two hashes in one block: each excerpt is centered on its own value', () => {
  const ctx = analyze(
    `<p>The benign installer signed by the vendor has MD5 ${H1}, whereas the trojanized installer later delivered by the operators to victims has MD5 ${H2}.</p>`
  );
  const [eb] = lineFor(ctx, H2).excerpts;
  assert.ok(eb.includes(H2));
  assert.match(eb, /delivered by the operators to victims has MD5/);
  assert.equal(eb.includes(H1), false, 'B is not described by A\'s clause');
  assert.doesNotMatch(eb, /benign installer/);
});

test('7. URL copy then standalone hash: the AI evidence is the standalone occurrence', () => {
  const ctx = analyze(`
<p>The sample was mirrored at https://files-relay.com/files/${H1} for a few days.</p>
<p>The malicious attachment MD5 is ${H1}.</p>`);
  const md5 = ctx.candidates.filter((c) => c.candidate_type === 'md5');
  assert.equal(md5.length, 1);
  assert.equal(md5[0].occurrences.length, 1, 'the URL copy is not a hash occurrence');
  const { excerpts } = lineFor(ctx, H1);
  assert.deepEqual(excerpts, [`The malicious attachment MD5 is ${H1}.`]);
});

test('9. block not flattened into the prompt: the excerpt alone carries the IOC and its relation', () => {
  const huge = 'Long technical narrative sentence about the intrusion chain and tooling. '.repeat(2050);
  const ctx = analyze(`<p>${huge} The dropper recovered from the victim host has MD5 ${H1}.</p>`);
  const { excerpts, blockInPrompt } = lineFor(ctx, H1);
  assert.equal(blockInPrompt, false, 'precondition: the block exceeds the flatten budget');
  assert.match(excerpts[0], new RegExp(`dropper recovered from the victim host has MD5 ${H1}`));
});

test('10. explicit IOC-table hashes do not depend on the excerpt path', () => {
  const ctx = analyze(`
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>
<tr><td>MD5</td><td>${H1}</td></tr></tbody></table>`);
  assert.equal(ctx.partition.toClassify.some((c) => c.normalized_value === H1), false);
  assert.ok(ctx.partition.explicit.some((c) => c.normalized_value === H1));
});

test('excerpt: defanged / source spellings are located; unknown spelling falls back to the head', () => {
  const text = `${'x'.repeat(200)} beacons to relay-node[.]com every minute ${'y'.repeat(200)}`;
  const e = evidenceExcerpt(text, [null, 'relay-node.com']);
  assert.match(e, /beacons to relay-node\[\.\]com every minute/);
  assert.equal(evidenceExcerpt('abc def', ['zzz']), 'abc def');
  assert.equal(evidenceExcerpt(`${'q'.repeat(300)}`, ['zzz']).length, 2 * EVIDENCE_EXCERPT_SIDE_CHARS);
  const line = formatCandidateEvidenceLine({
    candidate_id: 'cand-009',
    candidate_type: 'url',
    normalized_value: 'https://relay-node.com/gate.php',
    original_value: 'hxxps://relay-node[.]com/gate.php',
    occurrences: [{ zone: 'report_body', block_id: 'b9', surrounding_text: `${'z'.repeat(150)} the implant polls hxxps://relay-node[.]com/gate.php for tasks` }]
  });
  assert.match(line, /\(.*the implant polls hxxps:\/\/relay-node\[\.\]com\/gate\.php for tasks\)/);
});

test('contract: candidates stored by an earlier extraction contract are rebuilt, not reused', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v19');
  const base = { documentRebuilt: false, existingCount: 12, resumePreferred: true, refreshCandidates: false };
  assert.deepEqual(decideCandidateReuse({ ...base, priorExtractionVersion: 'tl-candidates-v15' }), {
    extractionChanged: true,
    shouldReuseCandidates: false
  });
  assert.deepEqual(decideCandidateReuse({ ...base, priorExtractionVersion: 'tl-candidates-v19' }), {
    extractionChanged: false,
    shouldReuseCandidates: true
  });
});
