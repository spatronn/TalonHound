/**
 * AI workload regression (semantic-v4) with a controlled fake provider.
 * Deterministic call counts / prompt-size bounds — no wall-clock assertions.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  analyzeThreatDocument,
  buildAnalysisChunks,
  partitionCandidatesForAi,
  selectSemanticBlocks,
  SYNTHESIS_CHUNK_KEY
} from './analyze.js';
import {
  buildProviderJsonSchema,
  candidateUpdatesMaxItemsForChunk,
  providerSafeMaxLength,
  AI_OUTPUT_BOUNDS,
  OLLAMA_UNPARSEABLE_MAX_LENGTH,
  OLLAMA_SAFE_ALIAS_FOR_UNPARSEABLE_MAX_LENGTH,
  THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
} from './contract.js';
import { AI_FAILURE_CODES, aiFailure, resolveAiTimeoutPolicy, resolveRecoveryReserveMs, resolveMinPrimaryCallMs, resolveMinRepairMs } from './timeouts.js';
import { buildSystemPrompt, buildChunkPrompt } from './prompts.js';
import { validateAiStructure } from './schema.js';
import { mergeAiCandidateUpdates } from '../pipeline.js';
import { extractCandidatesFromDocument } from '../candidateExtraction.js';
import { createCanonicalDocument } from '../canonicalDocument.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = JSON.parse(fs.readFileSync(path.join(here, '..', 'fixtures', 'kimsuky-appendix-canonical.json'), 'utf8'));

const settings = {
  enabled: true,
  provider: 'ollama',
  model: 'qwen3.5:9b',
  base_url: 'http://192.168.1.3:11434',
  max_input_chars: 60000,
  total_analysis_timeout_ms: 1_800_000
};

function okPayload(extra = {}) {
  return JSON.stringify({
    summary: 'ok',
    report_type: 'apt',
    language: 'zh',
    tlp: 'clear',
    confidence: 0.8,
    entities: [{ entity_type: 'threat_actor', name: 'Kimsuky' }],
    candidate_updates: [],
    relationships: [],
    ...extra
  });
}

function fakeProvider(calls, opts = {}) {
  return async (_settings, messages, hooks) => {
    calls.push({
      system: messages.system,
      user: messages.user,
      keepAlive: hooks?.keepAlive,
      callDeadlineAt: hooks?.callDeadlineAt,
      analysisStartedAt: hooks?.analysisStartedAt,
      formatSchema: hooks?.formatSchema
    });
    if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
    const text = typeof opts.respond === 'function' ? opts.respond(messages, calls.length) : okPayload();
    return {
      text,
      timing: {
        total_ms: opts.delayMs || 1,
        prompt_chars: messages.user.length,
        output_chars: text.length,
        thinking_chars: 0,
        ...(opts.timing || {})
      }
    };
  };
}

test('fixture report: explicit appendix resolved deterministically → zero candidates for the model', () => {
  const cands = extractCandidatesFromDocument(FIXTURE, {});
  const part = partitionCandidatesForAi(cands);
  assert.equal(part.toClassify.length, 0);
  assert.equal(part.explicit.length, 9);
  assert.equal(part.resolvedOther.length, 4);
});

test('fixture report: header/footer/navigation/reference rows never reach the model', () => {
  const sel = selectSemanticBlocks(FIXTURE);
  assert.ok(sel.dropped >= 36, `dropped ${sel.dropped}`);
  assert.ok(sel.blocks.every((b) => b.layout !== 'page_edge'));
  const text = sel.blocks.map((b) => b.text).join('\n');
  assert.equal(/\d+\/18$/m.test(text), false, 'page-number footers stripped');
  assert.equal(text.includes('https://mp.weixin.qq.com/s/9ilhH'), false, 'printed source URL stripped');
  assert.equal(text.includes('dev.to'), false, 'reference rows stripped from body text');
  assert.ok(text.includes('107.172.249.140:443'), 'body C2 sentence kept');
});

test('fixture report: one chunk, one AI call, bounded prompt, resolved context present', async () => {
  const cands = extractCandidatesFromDocument(FIXTURE, {});
  const calls = [];
  const result = await analyzeThreatDocument(settings, { document: FIXTURE, candidates: cands }, { callProvider: fakeProvider(calls) });
  assert.equal(result.ok, true);
  assert.equal(result.meta.chunks_total, 1);
  assert.equal(result.meta.ai_calls, 1, 'no repair, no synthesis');
  assert.equal(result.meta.ai_needed_candidates, 0);
  assert.equal(result.meta.resolved_candidates, 13);
  const user = calls[0].user;
  // v3 sent the full page-blob document + 18 candidate evidence lines (~15.3k chars).
  assert.ok(user.length < 11_000, `prompt chars ${user.length}`);
  assert.ok(user.includes('=== RESOLVED INDICATORS'));
  assert.ok(user.includes('source_assertion=explicit_c2'));
  assert.ok(user.includes('value=107.172.249.140'));
  assert.ok(user.includes('(none — return an empty candidate_updates array)'));
  assert.equal(user.includes('9ilhH-WUqeNCStDfbrBsrw 1/18'), false);
  assert.ok(result.meta.timing.length === 1 && result.meta.timing[0].kind === 'chunk');
  assert.ok(result.meta.prompt_chars_total > 0);
});

test('provider JSON schema requires candidate_id (join key) on every candidate update', () => {
  const schema = buildProviderJsonSchema();
  assert.deepEqual(schema.properties.candidate_updates.items.required, ['candidate_id', 'assessment']);
  assert.ok(schema.properties.candidate_updates.items.properties.role.enum.includes('malware_sample'));
});

function collectMaxLengths(node, acc = []) {
  if (!node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) {
    node.forEach((n) => collectMaxLengths(n, acc));
    return acc;
  }
  if (node.maxLength != null) acc.push(node.maxLength);
  for (const v of Object.values(node)) collectMaxLengths(v, acc);
  return acc;
}

test('provider JSON schema bounds match the documented contract and stay ≤ Zod', () => {
  const schema = buildProviderJsonSchema();
  const B = AI_OUTPUT_BOUNDS;
  assert.equal(schema.properties.entities.maxItems, B.entityMaxItemsChunk);
  assert.equal(schema.properties.relationships.maxItems, B.relationshipMaxItemsChunk);
  assert.equal(schema.properties.candidate_updates.maxItems, B.candidateUpdatesMaxItems);
  assert.equal(schema.properties.summary.maxLength, B.summaryMaxLengthChunk);
  assert.equal(schema.properties.entities.items.properties.evidence_text.maxLength, B.evidenceTextMaxLength);
  assert.ok(B.entityMaxItemsChunk <= B.entityMaxItemsMerged);
  assert.ok(B.relationshipMaxItemsChunk <= B.relationshipMaxItemsMerged);
  assert.ok(B.summaryMaxLengthChunk <= B.summaryMaxLengthMerged);
  assert.equal(candidateUpdatesMaxItemsForChunk(2, 20), 22);
  assert.equal(candidateUpdatesMaxItemsForChunk(0, 0), 8);
  const workloadSchema = buildProviderJsonSchema({ maxCandidateUpdates: candidateUpdatesMaxItemsForChunk(2, 20) });
  assert.equal(workloadSchema.properties.candidate_updates.maxItems, 22);

  const maxValid = {
    summary: 's',
    entities: Array.from({ length: B.entityMaxItemsChunk }, (_, i) => ({
      entity_type: 'threat_actor',
      name: `Actor ${i}`
    })),
    candidate_updates: [],
    relationships: []
  };
  assert.equal(validateAiStructure(maxValid).ok, true);
});

test('provider schema remaps Ollama-unparseable maxLength 2000 and never emits it', () => {
  assert.equal(providerSafeMaxLength(2000), 1999);
  assert.equal(providerSafeMaxLength(1999), 1999);
  assert.equal(providerSafeMaxLength(4000), 4000);
  const schema = buildProviderJsonSchema();
  const lengths = collectMaxLengths(schema);
  assert.equal(lengths.includes(OLLAMA_UNPARSEABLE_MAX_LENGTH), false);
  assert.equal(
    schema.properties.entities.items.properties.description.maxLength,
    OLLAMA_SAFE_ALIAS_FOR_UNPARSEABLE_MAX_LENGTH
  );
  assert.equal(
    schema.properties.candidate_updates.items.properties.normalized_value.maxLength,
    OLLAMA_SAFE_ALIAS_FOR_UNPARSEABLE_MAX_LENGTH
  );
  assert.ok(schema.properties.entities.items.properties.description.maxLength <= AI_OUTPUT_BOUNDS.entityDescriptionMaxLength);
  assert.ok(schema.properties.candidate_updates.items.properties.normalized_value.maxLength <= AI_OUTPUT_BOUNDS.normalizedValueMaxLength);
});

test('runtime Zod still rejects over-limit fields the provider grammar cannot express at 2000', () => {
  const B = AI_OUTPUT_BOUNDS;
  const base = { summary: 's', entities: [], candidate_updates: [], relationships: [] };
  assert.equal(validateAiStructure({ ...base, entities: Array.from({ length: B.entityMaxItemsMerged + 1 }, (_, i) => ({ entity_type: 'threat_actor', name: `A${i}` })) }).ok, false);
  assert.equal(validateAiStructure({ ...base, relationships: Array.from({ length: B.relationshipMaxItemsMerged + 1 }, () => ({ subject_kind: 'entity', subject_ref: 'a', relationship_type: 'uses', object_kind: 'entity', object_ref: 'b' })) }).ok, false);
  assert.equal(validateAiStructure({ ...base, summary: 'x'.repeat(B.summaryMaxLengthMerged + 1) }).ok, false);
  assert.equal(validateAiStructure({
    ...base,
    entities: [{ entity_type: 'malware', name: 'M', evidence_text: 'e'.repeat(B.evidenceTextMaxLength + 1) }]
  }).ok, false);
  assert.equal(validateAiStructure({
    ...base,
    candidate_updates: Array.from({ length: B.candidateUpdatesMaxItems + 1 }, (_, i) => ({
      candidate_id: `c${i}`,
      candidate_type: 'domain',
      normalized_value: `v${i}.example`,
      assessment: 'unknown',
      role: 'unknown'
    }))
  }).ok, false);
  assert.equal(validateAiStructure({
    ...base,
    entities: [{ entity_type: 'malware', name: 'M', description: 'd'.repeat(B.entityDescriptionMaxLength) }]
  }).ok, true);
  assert.equal(validateAiStructure({
    ...base,
    entities: [{ entity_type: 'malware', name: 'M', description: 'd'.repeat(B.entityDescriptionMaxLength + 1) }]
  }).ok, false);
});

test('candidate_updates provider capacity follows the chunk workload and stays under the Zod ceiling', () => {
  const needed = candidateUpdatesMaxItemsForChunk(45, 9);
  assert.equal(needed, 54);
  assert.ok(needed <= AI_OUTPUT_BOUNDS.candidateUpdatesMaxItems);
  const schema = buildProviderJsonSchema({ maxCandidateUpdates: needed });
  assert.equal(schema.properties.candidate_updates.maxItems, 54);
  const legitimate = {
    summary: 's',
    entities: [],
    candidate_updates: Array.from({ length: 45 }, (_, i) => ({
      candidate_id: `c${i}`,
      candidate_type: 'domain',
      normalized_value: `host${i}.example`,
      assessment: 'unknown',
      role: 'unknown'
    })),
    relationships: []
  };
  assert.equal(validateAiStructure(legitimate).ok, true);
});

test('prompts include semantic output budgets without weakening required candidate updates', () => {
  const sys = buildSystemPrompt();
  assert.match(sys, /at most 80 entities/);
  assert.match(sys, /at most 80 relationships/);
  assert.match(sys, /one candidate_updates entry per TO CLASSIFY/);
  const chunk = buildChunkPrompt({
    documentTitle: 't',
    language: 'en',
    chunkIndex: 0,
    chunkTotal: 1,
    blocksText: 'body',
    blockIds: ['b1'],
    toClassify: [],
    resolved: []
  });
  assert.match(chunk, /do not drop required updates/i);
});

test('primary provider call deadline protects the recovery reserve', async () => {
  const doc = createCanonicalDocument({ title: 'Reserve', language: 'en', blocks: [{ id: 'b0', type: 'paragraph', page: 1, text: 'text' }] });
  const calls = [];
  const started = Date.now();
  await analyzeThreatDocument(settings, { document: doc, candidates: [] }, {
    analysisStartedAt: started,
    callProvider: fakeProvider(calls)
  });
  const reserve = resolveRecoveryReserveMs(resolveAiTimeoutPolicy(settings));
  assert.equal(reserve, 180_000);
  assert.equal(calls[0].callDeadlineAt, started + 1_800_000 - reserve);
  assert.ok(calls[0].formatSchema.properties.relationships.maxItems);
});

test('only ai_needed candidates are asked for; explicit assertions cannot be downgraded by the model', async () => {
  const doc = createCanonicalDocument({
    title: 'Mixed',
    language: 'en',
    blocks: [
      { id: 'b1', type: 'paragraph', page: 1, text: 'Traffic to 198.51.100.44 was blocked by the proxy.' },
      { id: 'b1b', type: 'paragraph', page: 1, text: 'Beacons to https://drop.badactor-example.net/gate were seen.' },
      { id: 'b1c', type: 'paragraph', page: 1, text: 'A fetch from https://cdn.some-host-example.org/update.bin was observed.' },
      { id: 'h', type: 'heading', page: 2, text: 'Indicators of Compromise' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', page: 2, text: 'https://drop.badactor-example.net/gate' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', page: 2, text: '203.0.113.77' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', page: 2, text: 'c4ca4238a0b923820dcc509a6f75849b' }
    ]
  });
  const cands = extractCandidatesFromDocument(doc);
  const part = partitionCandidatesForAi(cands);
  assert.deepEqual(part.toClassify.map((c) => c.normalized_value).sort(), [
    'https://cdn.some-host-example.org/update.bin'
  ]);
  assert.equal(part.explicit.length, 3);
  assert.equal(
    cands.find((c) => c.normalized_value === '198.51.100.44')?.assessment,
    'context_only',
    'narrative-only IP stays context when an IOC appendix exists'
  );

  const calls = [];
  const result = await analyzeThreatDocument(
    settings,
    { document: doc, candidates: cands },
    {
      callProvider: fakeProvider(calls, {
        respond: (messages) => {
          const ids = [...messages.user.matchAll(/candidate_id=(cand-\d+) type=(\w+) value=(\S+)/g)].map((m) => ({ id: m[1], type: m[2], value: m[3] }));
          const fetchUrl = ids.find((x) => x.value === 'https://cdn.some-host-example.org/update.bin');
          return okPayload({
            candidate_updates: [
              { candidate_id: fetchUrl.id, assessment: 'malicious', role: 'malware_download', confidence: 0.8 }
            ]
          });
        }
      })
    }
  );
  assert.equal(result.ok, true);
  const user = calls[0].user;
  const toClassify = user.split('=== TO CLASSIFY')[1];
  assert.equal(toClassify.includes('198.51.100.44'), false);
  assert.equal(toClassify.includes('203.0.113.77'), false);
  assert.ok(toClassify.includes('url_host=cdn.some-host-example.org(parser-derived, not a separate IOC)'));
  assert.ok(user.split('=== RESOLVED INDICATORS')[1].includes('value=https://drop.badactor-example.net/gate status=malicious'));
  assert.equal(result.value.candidate_updates.length, 1);
});

test('total deadline after partial progress → failure carries checkpoint progress; retry resumes', async () => {
  const blocks = [];
  for (let i = 0; i < 6; i += 1) {
    blocks.push({ id: `b${i}`, type: 'paragraph', page: i + 1, text: `Section ${i} ${'x'.repeat(2500)}` });
  }
  const doc = createCanonicalDocument({ title: 'Slow', language: 'en', blocks });
  const chunks = buildAnalysisChunks(doc, { maxInputChars: 12000 });
  assert.ok(chunks.length >= 2);

  const completed = new Map();
  const hooks = {
    loadCompletedChunk: async (k) => completed.get(k) || null,
    saveChunkResult: async (chunk, value, meta) => {
      completed.set(chunk.chunk_key, { ok: true, value, schema_version: meta.schema_version, block_ids: chunk.block_ids });
    }
  };
  const calls = [];
  const tight = { ...settings, max_input_chars: 12000, total_analysis_timeout_ms: 60_000 };
  const policy = resolveAiTimeoutPolicy(tight);
  const reserve = resolveRecoveryReserveMs(policy);
  const minPrimary = resolveMinPrimaryCallMs(policy);
  // Enough budget to start exactly one primary call; the 800ms first call
  // leaves less than reserve+minPrimary for chunk 2.
  const remainingAtStart = reserve + minPrimary + 300;
  const err = await analyzeThreatDocument(
    tight,
    { document: doc, candidates: [] },
    { ...hooks, analysisStartedAt: Date.now() - (60_000 - remainingAtStart), callProvider: fakeProvider(calls, { delayMs: 800 }) }
  ).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE);
  assert.equal(err.progress.analysis_chunks_total, chunks.length);
  assert.equal(err.progress.analysis_chunks_completed, 1);
  assert.equal(err.progress.analysis_chunks_remaining, chunks.length - 1);
  assert.equal(err.progress.ai_calls, 1);
  assert.equal(completed.size, 1, 'first chunk checkpointed before the deadline fired');

  // Retry with a fresh budget: completed chunk is reused, remaining chunks run.
  calls.length = 0;
  const resumed = await analyzeThreatDocument({ ...settings, max_input_chars: 12000 }, { document: doc, candidates: [] }, { ...hooks, callProvider: fakeProvider(calls) });
  assert.equal(resumed.ok, true);
  assert.equal(resumed.meta.chunks_from_cache, 1);
  assert.equal(resumed.meta.chunks_analyzed_now, chunks.length - 1);
});

test('checkpoints from an older contract or different block set are not reused', async () => {
  const doc = createCanonicalDocument({
    title: 'Compat',
    language: 'en',
    blocks: [{ id: 'b0', type: 'paragraph', page: 1, text: 'A'.repeat(200) }]
  });
  const stale = new Map([
    ['chunk-001', { ok: true, value: JSON.parse(okPayload()), schema_version: 'threat-library-semantic-v3', block_ids: ['b0'] }]
  ]);
  const calls = [];
  const r1 = await analyzeThreatDocument(settings, { document: doc, candidates: [] }, { loadCompletedChunk: async (k) => stale.get(k) || null, callProvider: fakeProvider(calls) });
  assert.equal(r1.ok, true);
  assert.equal(calls.length, 1, 'v3 checkpoint ignored');

  const wrongBlocks = new Map([
    ['chunk-001', { ok: true, value: JSON.parse(okPayload()), schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION, block_ids: ['old-b0'] }]
  ]);
  calls.length = 0;
  const r2 = await analyzeThreatDocument(settings, { document: doc, candidates: [] }, { loadCompletedChunk: async (k) => wrongBlocks.get(k) || null, callProvider: fakeProvider(calls) });
  assert.equal(r2.ok, true);
  assert.equal(calls.length, 1, 'checkpoint for other block ids ignored');

  const good = new Map([
    ['chunk-001', { ok: true, value: JSON.parse(okPayload()), schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION, block_ids: ['b0'] }]
  ]);
  calls.length = 0;
  const r3 = await analyzeThreatDocument(settings, { document: doc, candidates: [] }, { loadCompletedChunk: async (k) => good.get(k) || null, callProvider: fakeProvider(calls) });
  assert.equal(r3.ok, true);
  assert.equal(calls.length, 0, 'compatible checkpoint reused without a provider call');
});

test('synthesis is optional: skipped when budget is short, failure never loses chunk results', async () => {
  const blocks = [];
  for (let i = 0; i < 4; i += 1) blocks.push({ id: `b${i}`, type: 'paragraph', page: 1, text: `S${i} ${'y'.repeat(3000)}` });
  const doc = createCanonicalDocument({ title: 'Synth', language: 'en', blocks });
  const chunks = buildAnalysisChunks(doc, { maxInputChars: 12000 });
  assert.ok(chunks.length >= 2);

  // Budget nearly exhausted after chunks → synthesis skipped, merged result returned.
  let calls = [];
  const synthSettings = { ...settings, max_input_chars: 12000 };
  const tight = await analyzeThreatDocument(
    { ...synthSettings, total_analysis_timeout_ms: 60_000 },
    { document: doc, candidates: [] },
    { analysisStartedAt: Date.now() - 20_000, callProvider: fakeProvider(calls) }
  );
  assert.equal(tight.ok, true);
  assert.equal(tight.meta.synthesis.skipped_reason, 'insufficient_budget');
  assert.equal(calls.length, chunks.length);

  // Synthesis provider failure → merged chunk result kept.
  calls = [];
  const failing = await analyzeThreatDocument(
    synthSettings,
    { document: doc, candidates: [] },
    {
      callProvider: async (_s, messages, hooks) => {
        calls.push(messages.user);
        if (messages.user.startsWith('Synthesize')) {
          const e = new Error('boom');
          e.code = AI_FAILURE_CODES.PROVIDER_HTTP_ERROR;
          throw e;
        }
        return { text: okPayload({ summary: `part ${calls.length}` }), timing: {} };
      }
    }
  );
  assert.equal(failing.ok, true);
  assert.equal(failing.meta.synthesis.attempted, true);
  assert.equal(failing.meta.synthesis.used, false);
  assert.ok(failing.value.summary.includes('part 1'));

  // Successful synthesis is checkpointed under its own key.
  const saved = new Map();
  calls = [];
  const ok = await analyzeThreatDocument(
    synthSettings,
    { document: doc, candidates: [] },
    {
      saveChunkResult: async (chunk, value, meta) => saved.set(chunk.chunk_key, { ok: true, value, schema_version: meta.schema_version, block_ids: chunk.block_ids }),
      callProvider: fakeProvider(calls, { respond: (m) => okPayload({ summary: m.user.startsWith('Synthesize') ? 'final' : 'part' }) })
    }
  );
  assert.equal(ok.meta.synthesis.used, true);
  assert.equal(ok.value.summary, 'final');
  assert.ok(saved.has(SYNTHESIS_CHUNK_KEY));
});

test('repair call is bounded by remaining budget and only fires on invalid output', async () => {
  const doc = createCanonicalDocument({ title: 'Repair', language: 'en', blocks: [{ id: 'b0', type: 'paragraph', page: 1, text: 'text' }] });
  let calls = [];
  const repaired = await analyzeThreatDocument(
    settings,
    { document: doc, candidates: [] },
    { callProvider: fakeProvider(calls, { respond: (_m, n) => (n === 1 ? 'not json at all' : okPayload()) }) }
  );
  assert.equal(repaired.ok, true);
  assert.equal(calls.length, 2);
  assert.ok(calls[1].user.startsWith('Your previous response was structurally invalid.'));
  assert.equal(repaired.meta.timing.filter((t) => t.kind === 'repair').length, 1);

  calls = [];
  const tight = { ...settings, total_analysis_timeout_ms: 60_000 };
  const policy = resolveAiTimeoutPolicy(tight);
  const reserve = resolveRecoveryReserveMs(policy);
  const minPrimary = resolveMinPrimaryCallMs(policy);
  const minRepair = resolveMinRepairMs(policy);
  const remainingAtStart = reserve + minPrimary + 400;
  const noBudget = await analyzeThreatDocument(
    tight,
    { document: doc, candidates: [] },
    {
      analysisStartedAt: Date.now() - (60_000 - remainingAtStart),
      callProvider: fakeProvider(calls, {
        delayMs: remainingAtStart - minRepair + 250,
        respond: () => 'not json at all'
      })
    }
  ).catch((e) => e);
  assert.equal(calls.length, 1, 'no repair when the remaining budget cannot fit it');
  assert.ok(noBudget.details.some((d) => /Repair skipped/.test(d.message)));
  assert.ok(minRepair > 0);
});

test('a new chunk is not started when remaining budget cannot cover reserve + min call', async () => {
  const doc = createCanonicalDocument({ title: 'NoStart', language: 'en', blocks: [{ id: 'b0', type: 'paragraph', page: 1, text: 'text' }] });
  const calls = [];
  const err = await analyzeThreatDocument(
    { ...settings, total_analysis_timeout_ms: 60_000 },
    { document: doc, candidates: [] },
    { analysisStartedAt: Date.now() - 55_000, callProvider: fakeProvider(calls) }
  ).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE);
  assert.equal(calls.length, 0);
});

test('parse failure keeps timing/progress and does not merge or persist a chunk result', async () => {
  const doc = createCanonicalDocument({ title: 'FailObs', language: 'en', blocks: [{ id: 'b0', type: 'paragraph', page: 1, text: 'text' }] });
  const calls = [];
  const saved = [];
  const failed = [];
  const err = await analyzeThreatDocument(
    settings,
    { document: doc, candidates: [] },
    {
      callProvider: fakeProvider(calls, {
        respond: () => 'not json at all',
        timing: { eval_count: 12, prompt_eval_count: 40 }
      }),
      saveChunkResult: async (chunk, value) => saved.push({ chunk, value }),
      markChunkFailed: async (chunk, code, message, meta) => failed.push({ chunk, code, message, meta })
    }
  ).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.AI_OUTPUT_PARSE_ERROR);
  assert.ok(err.progress);
  assert.ok(Array.isArray(err.progress.timing));
  assert.equal(err.progress.timing[0].output_chars, 'not json at all'.length);
  assert.equal(err.progress.timing[0].eval_count, 12);
  assert.equal(saved.length, 0);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].code, AI_FAILURE_CODES.AI_OUTPUT_PARSE_ERROR);
  assert.ok(Array.isArray(failed[0].meta.timing));
  const merged = mergeAiCandidateUpdates([], { candidate_updates: [{ candidate_type: 'domain', normalized_value: 'evil.example', assessment: 'malicious' }] });
  assert.equal(merged.length, 0, 'empty deterministic set stays empty — AI cannot insert identities');
});

test('provider HTTP 400 grammar failure persists sanitized diagnostic and timing, no AI result', async () => {
  const doc = createCanonicalDocument({ title: 'Grammar', language: 'en', blocks: [{ id: 'b0', type: 'paragraph', page: 1, text: 'text' }] });
  const saved = [];
  const failed = [];
  const err = await analyzeThreatDocument(
    settings,
    { document: doc, candidates: [] },
    {
      callProvider: async () => {
        const e = aiFailure(
          AI_FAILURE_CODES.PROVIDER_HTTP_ERROR,
          'AI provider error (400): Failed to initialize samplers: failed to parse grammar'
        );
        e.http_status = 400;
        e.provider_error = {
          http_status: 400,
          code: '400',
          type: 'invalid_request_error',
          message: 'Failed to initialize samplers: failed to parse grammar'
        };
        e.timing = { total_ms: 41, prompt_chars: 120, output_chars: 0 };
        throw e;
      },
      saveChunkResult: async (chunk, value) => saved.push({ chunk, value }),
      markChunkFailed: async (chunk, code, message, meta) => failed.push({ chunk, code, message, meta })
    }
  ).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.PROVIDER_HTTP_ERROR);
  assert.match(err.message, /failed to parse grammar/i);
  assert.ok(err.progress);
  assert.ok(Array.isArray(err.progress.timing));
  assert.equal(err.progress.timing[0].output_chars, 0);
  assert.equal(err.progress.timing[0].http_status, 400);
  assert.equal(err.progress.timing[0].failed, AI_FAILURE_CODES.PROVIDER_HTTP_ERROR);
  assert.deepEqual(err.details[0].message, 'Failed to initialize samplers: failed to parse grammar');
  assert.equal(saved.length, 0);
  assert.equal(failed.length, 1);
  assert.equal(failed[0].code, AI_FAILURE_CODES.PROVIDER_HTTP_ERROR);
  assert.ok(Array.isArray(failed[0].meta.timing));
  assert.equal(failed[0].meta.timing[0].output_chars, 0);
  assert.match(failed[0].meta.validation_details[0].message, /failed to parse grammar/i);
});
