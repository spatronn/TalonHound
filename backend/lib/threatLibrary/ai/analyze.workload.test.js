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
import { buildProviderJsonSchema, THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './contract.js';
import { AI_FAILURE_CODES } from './timeouts.js';
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
    calls.push({ system: messages.system, user: messages.user, keepAlive: hooks?.keepAlive });
    if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
    const text = typeof opts.respond === 'function' ? opts.respond(messages, calls.length) : okPayload();
    return { text, timing: { total_ms: opts.delayMs || 1, prompt_chars: messages.user.length, output_chars: text.length, thinking_chars: 0 } };
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
  // Budget: 60s minimum ceiling, started 59.4s ago → first chunk (600ms) completes, then the loop hits the deadline.
  const err = await analyzeThreatDocument(
    { ...settings, max_input_chars: 12000, total_analysis_timeout_ms: 60_000 },
    { document: doc, candidates: [] },
    { ...hooks, analysisStartedAt: Date.now() - 59_400, callProvider: fakeProvider(calls, { delayMs: 700 }) }
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
    { analysisStartedAt: Date.now() - 55_000, callProvider: fakeProvider(calls) }
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
  const noBudget = await analyzeThreatDocument(
    { ...settings, total_analysis_timeout_ms: 60_000 },
    { document: doc, candidates: [] },
    { analysisStartedAt: Date.now() - 30_000, callProvider: fakeProvider(calls, { respond: () => 'not json at all' }) }
  ).catch((e) => e);
  assert.equal(calls.length, 1, 'no repair when the remaining budget cannot fit it');
  assert.ok(noBudget.details.some((d) => /Repair skipped/.test(d.message)));
});
