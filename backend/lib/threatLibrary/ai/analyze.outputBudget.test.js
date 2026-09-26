/**
 * Semantic-v6 output budget + generation-ceiling handling (fake provider,
 * deterministic call counts — no wall-clock assertions, no model calls).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeThreatDocument,
  buildChunkRequest,
  partitionCandidatesForAi,
  buildAnalysisChunks,
  checkOutputBudget,
  classifyChunkOutcome,
  CHUNK_OUTCOMES
} from './analyze.js';
import { AI_OUTPUT_BOUNDS, buildProviderJsonSchema, candidateUpdatesMaxItemsForChunk, outputBudget } from './contract.js';
import { AI_FAILURE_CODES } from './timeouts.js';
import {
  buildChunkPrompt,
  buildSystemPrompt,
  COMPACT_RECOVERY_LINE,
  RELATIONSHIP_SELECTION_LINES
} from './prompts.js';
import { isGenerationLimitHit, parseOllamaNdjsonLine, callAiProvider } from './client.js';
import { processAiResponseText, validateAiAnalysis } from './schema.js';
import { createCanonicalDocument } from '../canonicalDocument.js';

const settings = {
  enabled: true,
  provider: 'ollama',
  model: 'qwen3.5:9b',
  base_url: 'http://192.168.1.3:11434',
  max_input_chars: 60000,
  total_analysis_timeout_ms: 1_800_000
};

const B = AI_OUTPUT_BOUNDS;
const LIMIT = { eval_count: B.numPredict, num_predict: B.numPredict, done_reason: 'length' };
const NATURAL = { eval_count: 900, num_predict: B.numPredict, done_reason: 'stop' };

function doc(blocks) {
  return createCanonicalDocument({
    title: 'Budget report',
    language: 'en',
    blocks: blocks || [
      { id: 'b0', type: 'paragraph', page: 1, text: 'The actor Foxtrot deployed the Lynx backdoor. Lynx communicates with 203.0.113.7.' }
    ]
  });
}

function candidate(id, overrides = {}) {
  return {
    candidate_type: 'domain',
    normalized_value: `${id}.example`,
    block_id: 'b0',
    occurrences: [{ block_id: 'b0', surrounding_text: `${id}.example` }],
    assessment: 'unknown',
    ai_needed: false,
    ...overrides
  };
}

function payload(extra = {}) {
  return JSON.stringify({
    summary: 'Foxtrot deploys Lynx.',
    entities: [
      { entity_type: 'threat_actor', name: 'Foxtrot' },
      { entity_type: 'malware', name: 'Lynx' }
    ],
    candidate_updates: [],
    relationships: [
      { subject_kind: 'entity', subject_ref: 'Foxtrot', relationship_type: 'uses', object_kind: 'entity', object_ref: 'Lynx' }
    ],
    ...extra
  });
}

function relationships(n) {
  return Array.from({ length: n }, (_, i) => ({
    subject_kind: 'entity',
    subject_ref: 'Foxtrot',
    relationship_type: 'uses',
    object_kind: 'entity',
    object_ref: `Tool ${i}`
  }));
}

function entities(n) {
  return [{ entity_type: 'threat_actor', name: 'Foxtrot' }, ...Array.from({ length: n - 1 }, (_, i) => ({ entity_type: 'tool', name: `Tool ${i}` }))];
}

/** Truncated at the ceiling in the middle of a relationship (Job 35 shape). */
const TRUNCATED = '{"summary":"s","entities":[{"entity_type":"threat_actor","name":"Foxtrot"}],"candidate_updates":[],"relationships":[{"subject_kind":"entity","subject_ref":"Foxtrot","relationship_type":"uses","object_kind":"candidate","object_ref":"cand-127","confidence":';

function scripted(calls, responses) {
  return async (_settings, messages, hooks) => {
    calls.push({ user: messages.user, system: messages.system, formatSchema: hooks?.formatSchema, callDeadlineAt: hooks?.callDeadlineAt });
    const r = responses[Math.min(calls.length - 1, responses.length - 1)];
    const text = typeof r.text === 'function' ? r.text(messages) : r.text;
    return { text, timing: { total_ms: 1, output_chars: text.length, ...(r.timing || {}) } };
  };
}

function hooksWith(calls, responses, extra = {}) {
  const failed = [];
  const saved = [];
  return {
    failed,
    saved,
    hooks: {
      callProvider: scripted(calls, responses),
      markChunkFailed: async (chunk, code, message, meta) => failed.push({ chunk, code, message, meta }),
      saveChunkResult: async (chunk, value, meta) => saved.push({ chunk, value, meta }),
      ...extra
    }
  };
}

// ---------------------------------------------------------------- budgets

test('output budgets: documented derivation, recovery strictly smaller, all under Zod ceilings', () => {
  const chunk = outputBudget('chunk');
  const recovery = outputBudget('recovery');
  const synthesis = outputBudget('synthesis');
  assert.deepEqual(chunk, { kind: 'chunk', maxEntities: 30, maxRelationships: 24 });
  assert.deepEqual(recovery, { kind: 'recovery', maxEntities: 15, maxRelationships: 12 });
  assert.deepEqual(synthesis, { kind: 'synthesis', maxEntities: 80, maxRelationships: 80 });
  // Healthy production maxima (entity↔entity relationships per chunk 16, entities per chunk 25).
  assert.ok(chunk.maxRelationships >= Math.ceil(16 * 1.5));
  assert.ok(chunk.maxEntities > 25);
  assert.ok(recovery.maxRelationships < chunk.maxRelationships && recovery.maxEntities < chunk.maxEntities);
  for (const b of [chunk, recovery, synthesis]) {
    assert.ok(b.maxEntities <= B.entityMaxItemsMerged);
    assert.ok(b.maxRelationships <= B.relationshipMaxItemsMerged);
  }
  assert.ok(B.evidenceTextMaxLengthGeneration >= 374, 'covers the longest healthy evidence_text observed');
  assert.ok(B.entityDescriptionMaxLengthGeneration >= 249, 'covers the longest healthy entity description observed');
  assert.ok(B.summaryMaxLengthChunk >= 770, 'covers the longest healthy chunk summary observed');
});

test('at p95 healthy item sizes a fully-used chunk budget still fits under num_predict', () => {
  // Healthy production p95 serialized sizes (chars): relationship 337, entity 268;
  // candidate update ≈ evidence p95 263 + ~150 structure. Job 35 measured 3.04 chars/token.
  const candidateUpdates = candidateUpdatesMaxItemsForChunk(2, 20);
  const chars =
    outputBudget('chunk').maxRelationships * 337 +
    outputBudget('chunk').maxEntities * 268 +
    candidateUpdates * 413 +
    B.summaryMaxLengthChunk;
  const tokens = Math.ceil(chars / 3.04);
  assert.ok(tokens < B.numPredict, `${tokens} tokens must stay below ${B.numPredict}`);
  assert.equal(B.numPredict, 10240, 'num_predict unchanged (finite, not raised)');
});

test('provider schema carries the per-call item budget and never emits Ollama-unparseable maxLength 2000', () => {
  const chunk = buildProviderJsonSchema({ maxEntities: 30, maxRelationships: 24, maxCandidateUpdates: 12 });
  assert.equal(chunk.properties.entities.maxItems, 30);
  assert.equal(chunk.properties.relationships.maxItems, 24);
  assert.equal(chunk.properties.candidate_updates.maxItems, 12);
  const recovery = buildProviderJsonSchema({ maxEntities: 15, maxRelationships: 12 });
  assert.equal(recovery.properties.relationships.maxItems, 12);
  assert.equal(buildProviderJsonSchema({ maxRelationships: 10_000 }).properties.relationships.maxItems, B.relationshipMaxItemsMerged);
  for (const s of [chunk, recovery, buildProviderJsonSchema()]) {
    const text = JSON.stringify(s);
    assert.equal(/"maxLength":2000\b/.test(text), false);
    for (const key of ['entities', 'candidate_updates', 'relationships']) {
      assert.equal(s.properties[key].items.properties.evidence_text.maxLength, B.evidenceTextMaxLengthGeneration);
    }
  }
});

// ---------------------------------------------------------------- prompt contract

test('chunk prompt communicates relationship budget, priority, dedup, concise evidence and update rules', () => {
  const prompt = buildChunkPrompt({
    documentTitle: 't',
    language: 'en',
    chunkIndex: 0,
    chunkTotal: 1,
    blocksText: 'body',
    blockIds: ['b0'],
    toClassify: [],
    resolved: []
  });
  assert.match(prompt, /at most 30 entities and at most 24 relationships/);
  assert.match(prompt, /an empty relationships array is valid/);
  assert.match(prompt, /Relationships are selective, not exhaustive/);
  assert.match(prompt, /threat_actor\/campaign uses malware\/tool/);
  assert.match(prompt, /Never create one relationship per indicator because it appears in the RESOLVED list, an IOC table/);
  assert.match(prompt, /at most one relationship per subject \+ relationship_type \+ object/);
  assert.match(prompt, /status=context_only are background only/);
  assert.match(prompt, new RegExp(`copied verbatim \\(at most ${B.evidenceTextMaxLengthGeneration} characters`));
  assert.match(prompt, /never join several sentences/);
  assert.match(prompt, /aliases go in aliases\[\], not separate entities/);
  assert.match(prompt, /Relate a CVE or ATT&CK technique through a vulnerability \/\s+attack_pattern entity/);
  assert.match(prompt, /Every entity used in a\s+relationship must also be listed in entities/);
  assert.match(prompt, /exactly one entry per TO CLASSIFY candidate/);
  assert.match(prompt, /Do NOT return entries for RESOLVED indicators unless/);
  assert.equal(/relationships they have with\s+the RESOLVED and TO CLASSIFY indicators/.test(prompt), false, 'v5 enumeration invitation removed');
  assert.equal(prompt.includes(COMPACT_RECOVERY_LINE), false);
  assert.ok(RELATIONSHIP_SELECTION_LINES.length > 0);
  assert.equal(/at most 80/.test(buildSystemPrompt()), false);
});

test('compact recovery prompt keeps every TO CLASSIFY line and carries the smaller budget', () => {
  const toClassify = Array.from({ length: 40 }, (_, i) =>
    candidate(`c${i}`, { candidate_id: `cand-${String(i + 1).padStart(3, '0')}`, ai_needed: true })
  );
  const prompt = buildChunkPrompt({
    documentTitle: 't',
    language: 'en',
    chunkIndex: 0,
    chunkTotal: 1,
    blocksText: 'body',
    blockIds: ['b0'],
    toClassify,
    resolved: [],
    budget: outputBudget('recovery'),
    compactRecovery: true
  });
  assert.ok(prompt.startsWith(COMPACT_RECOVERY_LINE));
  assert.match(prompt, /at most 15 entities and at most 12 relationships/);
  for (const c of toClassify) assert.ok(prompt.includes(`candidate_id=${c.candidate_id} `));
});

// ---------------------------------------------------------------- required ai_needed decisions

test('relationship budget never reduces required candidate_updates capacity (primary and recovery)', async () => {
  const toClassify = Array.from({ length: 40 }, (_, i) => candidate(`need${i}`, { ai_needed: true }));
  const contextOnly = Array.from({ length: 10 }, (_, i) => candidate(`ctx${i}`, { assessment: 'context_only', role: 'reference' }));
  const explicit = Array.from({ length: 3 }, (_, i) =>
    candidate(`bad${i}`, { assessment: 'malicious', source_assertion: 'explicit_ioc', role: 'command_and_control' })
  );
  const calls = [];
  const { hooks } = hooksWith(calls, [{ text: TRUNCATED, timing: LIMIT }, { text: payload(), timing: NATURAL }]);
  await analyzeThreatDocument(settings, { document: doc(), candidates: [...toClassify, ...contextOnly, ...explicit] }, hooks);
  assert.equal(calls.length, 2);
  for (const call of calls) {
    // 40 required + 3 refinable explicit; context-only resolved never widen the cap.
    assert.equal(call.formatSchema.properties.candidate_updates.maxItems, 43);
    assert.ok(call.formatSchema.properties.candidate_updates.maxItems >= toClassify.length);
  }
  assert.equal(calls[0].formatSchema.properties.relationships.maxItems, 24);
  assert.equal(calls[1].formatSchema.properties.relationships.maxItems, 12);
});

test('chunk request counts only refinable resolved indicators toward optional updates', () => {
  const document = doc();
  const [chunk] = buildAnalysisChunks(document);
  const partition = partitionCandidatesForAi([
    candidate('a', { ai_needed: true, candidate_id: 'cand-001' }),
    candidate('b', { assessment: 'malicious', source_assertion: 'explicit_ioc', candidate_id: 'cand-002' }),
    candidate('c', { assessment: 'context_only', candidate_id: 'cand-003' })
  ]);
  const req = buildChunkRequest({ document, chunk, chunkIndex: 0, chunkTotal: 1, partition, sourceHost: null });
  assert.equal(req.toClassify.length, 1);
  assert.equal(req.resolved.length, 2);
  assert.equal(req.refinableResolved, 1);
});

// ---------------------------------------------------------------- relationship budget

test('relationships within budget are accepted in one call; dense-but-valid output at the cap is kept', async () => {
  const calls = [];
  const { hooks, saved } = hooksWith(calls, [
    { text: payload({ entities: entities(30), relationships: relationships(24) }), timing: NATURAL }
  ]);
  const out = await analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooks);
  assert.equal(calls.length, 1);
  assert.equal(out.value.relationships.length, 24);
  assert.equal(out.value.entities.length, 30);
  assert.equal(saved.length, 1);
  assert.equal(out.meta.timing[0].outcome, CHUNK_OUTCOMES.OK);
  assert.equal(out.meta.timing[0].decision, 'accept');
});

test('semantically duplicate relationships collapse to one (runtime defense in depth)', () => {
  const dup = [
    { subject_kind: 'entity', subject_ref: 'Foxtrot', relationship_type: 'uses', object_kind: 'entity', object_ref: 'Lynx', evidence_text: 'a' },
    { subject_kind: 'entity', subject_ref: 'foxtrot ', relationship_type: 'Uses', object_kind: 'entity', object_ref: 'LYNX', evidence_text: 'b' },
    { subject_kind: 'entity', subject_ref: 'Lynx', relationship_type: 'communicates-with', object_kind: 'entity', object_ref: 'Foxtrot' },
    { subject_kind: 'entity', subject_ref: 'Lynx', relationship_type: 'communicates_with', object_kind: 'entity', object_ref: 'Foxtrot' }
  ];
  const r = validateAiAnalysis({
    summary: 's',
    entities: [{ entity_type: 'threat_actor', name: 'Foxtrot' }, { entity_type: 'malware', name: 'Lynx' }],
    candidate_updates: [],
    relationships: dup
  });
  assert.equal(r.ok, true);
  assert.equal(r.value.relationships.length, 2);
  assert.equal(r.value.relationships[0].evidence_text, 'a');
  assert.equal(r.rejected.filter((x) => x.code === 'duplicate_relationship').length, 2);
});

test('over-budget output (provider ignored the grammar) is rejected, not truncated, and gets one compact regeneration', async () => {
  const calls = [];
  const { hooks, saved } = hooksWith(calls, [
    { text: payload({ entities: entities(2), relationships: relationships(30) }), timing: NATURAL },
    { text: payload(), timing: NATURAL }
  ]);
  const over = checkOutputBudget(
    processAiResponseText(payload({ entities: entities(2), relationships: relationships(30) })),
    outputBudget('chunk')
  );
  assert.equal(over.ok, false);
  assert.equal(over.code, AI_FAILURE_CODES.AI_OUTPUT_BUDGET_EXCEEDED);
  assert.equal(classifyChunkOutcome(over, NATURAL), CHUNK_OUTCOMES.BUDGET_EXCEEDED);

  const out = await analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooks);
  assert.equal(calls.length, 2);
  assert.ok(calls[1].user.startsWith(COMPACT_RECOVERY_LINE));
  assert.equal(out.value.relationships.length, 1, 'only the regenerated answer is kept');
  assert.equal(saved.length, 1);
  assert.deepEqual(out.meta.timing.map((t) => [t.kind, t.outcome, t.decision]), [
    ['chunk', CHUNK_OUTCOMES.BUDGET_EXCEEDED, 'compact_recovery'],
    ['recovery', CHUNK_OUTCOMES.OK, 'accept']
  ]);
});

// ---------------------------------------------------------------- num_predict exhaustion

test('generation-ceiling detection: Ollama eval_count/done_reason, OpenAI length, Anthropic max_tokens', () => {
  assert.equal(isGenerationLimitHit({ eval_count: 10240, num_predict: 10240 }), true);
  assert.equal(isGenerationLimitHit({ eval_count: 10239, num_predict: 10240 }), false);
  assert.equal(isGenerationLimitHit({ done_reason: 'length' }), true);
  assert.equal(isGenerationLimitHit({ done_reason: 'max_tokens' }), true);
  assert.equal(isGenerationLimitHit({ done_reason: 'stop', eval_count: 12, num_predict: 10240 }), false);
  assert.equal(isGenerationLimitHit(null), false);
  const acc = { text: '' };
  parseOllamaNdjsonLine(JSON.stringify({ message: { content: '' }, done: true, done_reason: 'length', eval_count: 10240 }), acc);
  assert.equal(acc.provider_metrics.done_reason, 'length');
  assert.equal(acc.provider_metrics.eval_count, 10240);
});

test('Ollama call timing records num_predict and flags a ceiling hit', async () => {
  const encoder = new TextEncoder();
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(`${JSON.stringify({ message: { content: '{"summary":' } })}\n`));
      controller.enqueue(encoder.encode(`${JSON.stringify({ message: { content: '' }, done: true, done_reason: 'length', eval_count: 10240, prompt_eval_count: 6159 })}\n`));
      controller.close();
    }
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, body });
  try {
    const result = await callAiProvider(
      { enabled: true, provider: 'ollama', model: 'qwen3.5:9b', base_url: 'http://127.0.0.1:11434' },
      { system: 'sys', user: 'usr' },
      { formatSchema: buildProviderJsonSchema() }
    );
    assert.equal(result.timing.num_predict, 10240);
    assert.equal(result.timing.eval_count, 10240);
    assert.equal(result.timing.done_reason, 'length');
    assert.equal(result.timing.generation_limit_hit, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('eval_count == num_predict + truncated JSON is a generation-limit failure: no syntax repair, exactly one compact regeneration', async () => {
  const calls = [];
  const { hooks, saved } = hooksWith(calls, [
    { text: TRUNCATED, timing: { eval_count: 10240, num_predict: 10240 } },
    { text: payload(), timing: NATURAL }
  ]);
  const out = await analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooks);
  assert.equal(calls.length, 2);
  assert.equal(calls.some((c) => c.user.startsWith('Your previous response was structurally invalid.')), false, 'normal repair never runs');
  assert.ok(calls[1].user.startsWith(COMPACT_RECOVERY_LINE));
  assert.ok(calls[1].user.includes('=== BEGIN UNTRUSTED REPORT CHUNK DATA ==='), 'recovery regenerates from the report, not from the truncated output');
  assert.equal(calls[1].user.includes('cand-127'), false);
  assert.equal(out.meta.timing[0].outcome, CHUNK_OUTCOMES.GENERATION_LIMIT);
  assert.equal(out.meta.timing[0].decision, 'compact_recovery');
  assert.equal(out.meta.timing[1].kind, 'recovery');
  assert.equal(saved.length, 1);
});

test('recovery that also hits the ceiling fails closed after exactly two calls with labelled bounded samples', async () => {
  const calls = [];
  const { hooks, saved, failed } = hooksWith(calls, [
    { text: TRUNCATED + 'x'.repeat(30_000), timing: LIMIT },
    { text: TRUNCATED, timing: LIMIT }
  ]);
  const err = await analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooks).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.AI_GENERATION_LIMIT);
  assert.match(err.message, /generation token ceiling \(10240\/10240 tokens\)/);
  assert.equal(calls.length, 2);
  assert.equal(saved.length, 0, 'no AI result persisted');
  assert.equal(failed.length, 1);
  const sample = failed[0].meta.raw_output_sample;
  assert.ok(sample.startsWith('[primary]\n'));
  assert.ok(sample.includes('\n[recovery]\n'));
  assert.ok(sample.length <= 8200, 'bounded diagnostics, never the full output');
  const kinds = failed[0].meta.timing.map((t) => [t.kind, t.outcome, t.decision, t.eval_count, t.num_predict]);
  assert.deepEqual(kinds, [
    ['chunk', CHUNK_OUTCOMES.GENERATION_LIMIT, 'compact_recovery', 10240, 10240],
    ['recovery', CHUNK_OUTCOMES.GENERATION_LIMIT, 'fail_closed', 10240, 10240]
  ]);
  assert.ok(err.details.some((d) => d.path === '(generation)'));
});

test('compact recovery is skipped (fail closed, one call) when the remaining budget cannot hold a regeneration', async () => {
  const calls = [];
  const tight = { ...settings, total_analysis_timeout_ms: 60_000 };
  const realNow = Date.now;
  let offset = 0;
  Date.now = () => realNow() + offset;
  try {
    // 60s ceiling → reserve 10s, min primary 6s. Start with 20s left; the
    // primary "takes" 15s, leaving 5s: not enough to regenerate the chunk.
    const { hooks } = hooksWith(calls, [{ text: TRUNCATED, timing: LIMIT }], {
      analysisStartedAt: Date.now() - 40_000
    });
    const inner = hooks.callProvider;
    hooks.callProvider = async (...args) => {
      offset += 15_000;
      return inner(...args);
    };
    const err = await analyzeThreatDocument(tight, { document: doc(), candidates: [] }, hooks).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.AI_GENERATION_LIMIT);
    assert.equal(calls.length, 1);
    assert.ok(err.details.some((d) => /Compact recovery skipped/.test(d.message)));
  } finally {
    Date.now = realNow;
  }
});

test('no recovery loop: a provider that always hits the ceiling costs at most two calls and stops later chunks', async () => {
  const blocks = Array.from({ length: 40 }, (_, i) => ({ id: `b${i}`, type: 'paragraph', page: 1, text: `Paragraph ${i} `.repeat(120) }));
  const document = doc(blocks);
  assert.ok(buildAnalysisChunks(document, { maxInputChars: settings.max_input_chars }).length > 1);
  const calls = [];
  const { hooks } = hooksWith(calls, [{ text: TRUNCATED, timing: LIMIT }]);
  const err = await analyzeThreatDocument(settings, { document, candidates: [] }, hooks).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.AI_GENERATION_LIMIT);
  assert.equal(calls.length, 2);
});

// ---------------------------------------------------------------- repair / ambiguity

test('naturally completed malformed small output still gets exactly one syntax repair', async () => {
  const calls = [];
  const { hooks } = hooksWith(calls, [
    { text: '{"summary": "s", "entities": [}', timing: NATURAL },
    { text: payload(), timing: NATURAL }
  ]);
  const out = await analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooks);
  assert.equal(calls.length, 2);
  assert.ok(calls[1].user.startsWith('Your previous response was structurally invalid.'));
  assert.equal(calls[1].formatSchema.properties.relationships.maxItems, 24, 'repair keeps the chunk budget');
  assert.deepEqual(out.meta.timing.map((t) => [t.kind, t.outcome, t.decision]), [
    ['chunk', CHUNK_OUTCOMES.MALFORMED, 'repair'],
    ['repair', CHUNK_OUTCOMES.OK, 'accept']
  ]);
});

test('repair output that hits the ceiling is reported as a generation-limit failure (no further calls)', async () => {
  const calls = [];
  const { hooks, saved } = hooksWith(calls, [
    { text: '{"summary": "s", "entities": [}', timing: NATURAL },
    { text: TRUNCATED, timing: LIMIT }
  ]);
  const err = await analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooks).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.AI_GENERATION_LIMIT);
  assert.equal(calls.length, 2);
  assert.equal(saved.length, 0);
});

test('competing JSON payloads fail closed without any follow-up call', async () => {
  const calls = [];
  const { hooks, saved } = hooksWith(calls, [{ text: `${payload()}\n${payload()}`, timing: NATURAL }]);
  const err = await analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooks).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.AI_OUTPUT_PARSE_ERROR);
  assert.match(err.message, /multiple JSON/);
  assert.equal(calls.length, 1);
  assert.equal(saved.length, 0);
});

test('parser stays fail-closed for truncated, prose-mixed and malformed-fence payloads', () => {
  for (const text of [
    TRUNCATED,
    `Sure! ${payload()} Hope this helps.`,
    '```json\n{"summary": "s",\n```',
    `${payload()}{"summary":"other"}`
  ]) {
    const r = processAiResponseText(text);
    assert.equal(r.ok, false, text.slice(0, 40));
  }
});
