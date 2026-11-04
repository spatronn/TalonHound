/**
 * A run with a tolerance policy keeps what the model finished: a failed chunk is
 * retried once, unanswered candidates are asked about once more, and the result says
 * exactly what is missing. Without the policy every failure stays fatal.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeThreatDocument, buildAnalysisChunks, computeAiCoverage, unansweredCandidates } from './analyze.js';
import { createCanonicalDocument } from '../canonicalDocument.js';
import { AI_FAILURE_CODES } from './timeouts.js';
import { buildAiProvenance, fetchModelIdentity, promptFingerprint } from './modelIdentity.js';

const settings = {
  enabled: true,
  provider: 'ollama',
  model: 'qwen3.5:9b',
  base_url: 'http://192.0.2.1:11434',
  max_input_chars: 12000,
  connection_timeout_ms: 5000,
  first_token_timeout_ms: 60_000,
  inactivity_timeout_ms: 60_000,
  total_analysis_timeout_ms: 600_000
};

function doc(blockCount = 8) {
  const blocks = [];
  for (let i = 0; i < blockCount; i += 1) {
    blocks.push({ id: `b${i}`, type: 'paragraph', text: `Section ${i}. Beacon host-${i}.example ${'y'.repeat(2500)}` });
  }
  return createCanonicalDocument({ title: 'Report', language: 'en', blocks });
}

const payload = (updates = []) => JSON.stringify({
  summary: 'part',
  report_type: 'malware',
  language: 'en',
  tlp: 'TLP:AMBER',
  confidence: 0.7,
  entities: [],
  candidate_updates: updates,
  relationships: []
});
const ok = (text = payload()) => ({ text, timing: { done_reason: 'stop', prompt_eval_count: 1000 } });
const boom = (code = AI_FAILURE_CODES.PROVIDER_HTTP_ERROR) => Object.assign(new Error(code), { code, http_status: 400 });

const candidate = (value, blockId) => ({
  candidate_type: 'domain',
  normalized_value: value,
  original_value: value,
  ai_needed: true,
  is_ioc: true,
  assessment: 'unknown',
  occurrences: [{ block_id: blockId }],
  block_id: blockId,
  evidence_text: `Beacon ${value}`
});

const update = (value, blockId) => ({
  candidate_type: 'domain',
  normalized_value: value,
  assessment: 'malicious',
  role: 'c2',
  confidence: 0.9,
  evidence_text: `Beacon ${value}`,
  evidence_block_ids: [blockId]
});

const hooksWith = (callProvider, extra = {}) => ({ callProvider, analysisStartedAt: Date.now(), ...extra });

test('without a tolerance policy a chunk failure stays fatal', async () => {
  await assert.rejects(
    analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooksWith(async () => { throw boom(); })),
    (err) => err.code === AI_FAILURE_CODES.PROVIDER_HTTP_ERROR
  );
});

test('a failed chunk is retried once, and a success on retry leaves no failure', async () => {
  const document = doc();
  const total = buildAnalysisChunks(document, { maxInputChars: 12000 }).length;
  assert.ok(total >= 2);
  let calls = 0;
  const res = await analyzeThreatDocument(settings, { document, candidates: [] }, hooksWith(async (s, m, h) => {
    if (h.purpose !== 'chunk') return ok();
    calls += 1;
    if (calls === 1) throw boom();
    return ok();
  }, { partial: { tolerate: () => true } }));
  assert.equal(res.ok, true);
  assert.deepEqual(res.meta.chunk_failures, []);
  assert.equal(res.meta.chunks_completed, total);
  assert.equal(calls, total + 1);
});

test('a chunk that keeps failing is named and the rest of the analysis stands', async () => {
  const document = doc();
  const chunks = buildAnalysisChunks(document, { maxInputChars: 12000 });
  let call = 0;
  let failedCalls = 0;
  const res = await analyzeThreatDocument(settings, { document, candidates: [] }, hooksWith(async (s, m, h) => {
    if (h.purpose !== 'chunk') return ok();
    call += 1;
    if (call === 1 || m.user.includes('Section 0.')) {
      failedCalls += 1;
      throw boom();
    }
    return ok();
  }, { partial: { tolerate: () => true } }));
  assert.equal(res.meta.chunk_failures.length, 1);
  assert.equal(res.meta.chunk_failures[0].chunk_key, chunks[0].chunk_key);
  assert.equal(res.meta.chunks_completed, chunks.length - 1);
  assert.equal(failedCalls, 2, 'one attempt and one retry');
});

test('a failure the policy does not tolerate is thrown at once', async () => {
  let calls = 0;
  await assert.rejects(analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooksWith(async () => {
    calls += 1;
    throw boom();
  }, { partial: { tolerate: () => false } })));
  assert.equal(calls, 1);
});

test('cancellation always stops the run, whatever the policy says', async () => {
  await assert.rejects(
    analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooksWith(async () => { throw boom(AI_FAILURE_CODES.JOB_CANCELLED); }, { partial: { tolerate: () => true } })),
    (err) => err.code === AI_FAILURE_CODES.JOB_CANCELLED
  );
});

test('when every chunk fails the error reaches the caller instead of an empty success', async () => {
  await assert.rejects(
    analyzeThreatDocument(settings, { document: doc(), candidates: [] }, hooksWith(async () => { throw boom(); }, { partial: { tolerate: () => true } })),
    (err) => err.code === AI_FAILURE_CODES.PROVIDER_HTTP_ERROR
  );
});

test('an unanswered candidate gets one targeted question, and only that candidate is asked', async () => {
  const document = doc(2);
  const candidates = [candidate('host-0.example', 'b0'), candidate('host-1.example', 'b1')];
  const prompts = [];
  const res = await analyzeThreatDocument(settings, { document, candidates }, hooksWith(async (s, m, h) => {
    if (h.purpose !== 'chunk') return ok();
    prompts.push(m.user);
    // The first chunk's answer omits host-0; the second chunk answers host-1.
    if (prompts.length === 1) return ok();
    if (prompts.length === 2) return ok(payload([update('host-1.example', 'b1')]));
    return ok(payload([update('host-0.example', 'b0')]));
  }, { partial: { tolerate: () => true } }));
  assert.equal(res.meta.targeted_retries, 1);
  assert.equal(prompts.length, 3);
  assert.equal(res.meta.coverage.requested, 2);
  assert.equal(res.meta.coverage.unanswered, 0);
  const targeted = prompts[2];
  assert.ok(targeted.includes('host-0.example'));
  assert.ok(!/classify[^\n]*host-1\.example/i.test(targeted));
});

test('an answer a chunk gave survives a synthesis that leaves it out', async () => {
  const document = doc(2);
  const candidates = [candidate('host-0.example', 'b0'), candidate('host-1.example', 'b1')];
  let chunk = 0;
  const res = await analyzeThreatDocument(settings, { document, candidates }, hooksWith(async (s, m, h) => {
    if (h.purpose === 'synthesis') return ok(payload([update('host-1.example', 'b1')]));
    chunk += 1;
    return ok(payload([chunk === 1 ? update('host-0.example', 'b0') : update('host-1.example', 'b1')]));
  }));
  assert.equal(res.meta.synthesis.used, true);
  assert.deepEqual(res.value.candidate_updates.map((u) => u.normalized_value).sort(), ['host-0.example', 'host-1.example']);
  assert.equal(res.meta.coverage.unanswered, 0);
});

test('targeted retries are bounded, and a candidate never answered stays visible', async () => {
  const document = doc(8);
  const chunks = buildAnalysisChunks(document, { maxInputChars: 12000 });
  const candidates = chunks.map((c) => candidate(`never-${c.block_ids[0]}.example`, c.block_ids[0]));
  let calls = 0;
  const res = await analyzeThreatDocument(settings, { document, candidates }, hooksWith(async (s, m, h) => {
    if (h.purpose === 'chunk') calls += 1;
    return ok();
  }, { partial: { tolerate: () => true } }));
  assert.ok(res.meta.targeted_retries <= 3);
  assert.equal(calls, chunks.length + res.meta.targeted_retries);
  assert.equal(res.meta.coverage.unanswered, candidates.length);
  assert.equal(res.meta.coverage.unanswered_keys.length, candidates.length);
});

test('a later chunk of plain tables with nothing to classify costs no model call', async () => {
  const table = (id) => ({ id, type: 'table', text: `Indicator\nsha ${'a'.repeat(3000)}`, table: { headers: ['Indicator'], rows: [['x']] } });
  const blocks = [
    { id: 'p0', type: 'paragraph', text: `Intro ${'y'.repeat(3000)}` },
    { id: 'p1', type: 'paragraph', text: `More ${'y'.repeat(3000)}` },
    ...Array.from({ length: 6 }, (_, i) => table(`t${i}`))
  ];
  const document = createCanonicalDocument({ title: 'T', language: 'en', blocks });
  const chunks = buildAnalysisChunks(document, { maxInputChars: 4000 });
  const tableOnly = chunks.filter((c, i) => i > 0 && c.blocks.every((b) => b.type === 'table')).length;
  assert.ok(tableOnly > 0, 'fixture has table-only chunks');
  let calls = 0;
  const res = await analyzeThreatDocument({ ...settings, max_input_chars: 4000 }, { document, candidates: [] }, hooksWith(async (s, m, h) => {
    if (h.purpose === 'chunk') calls += 1;
    return ok();
  }, { partial: { tolerate: () => true } }));
  assert.equal(res.meta.chunks_skipped_structured, tableOnly);
  assert.equal(calls, chunks.length - tableOnly);
});

test('coverage helpers count by identity', () => {
  const requested = [candidate('a.example', 'b'), candidate('b.example', 'b')];
  assert.deepEqual(unansweredCandidates(requested, [{ candidate_updates: [update('a.example', 'b')] }]).map((c) => c.normalized_value), ['b.example']);
  const c = computeAiCoverage(requested, [update('a.example', 'b')]);
  assert.deepEqual([c.requested, c.answered, c.unanswered], [2, 1, 1]);
});

test('model identity: digest and context length from Ollama; unreachable is stated, not thrown', async () => {
  const fetchImpl = async (url) => ({
    ok: true,
    json: async () => (String(url).endsWith('/api/tags')
      ? { models: [{ name: 'qwen3.5:9b', digest: 'sha256:abc' }] }
      : { model_info: { 'qwen.context_length': 32768 }, details: { quantization_level: 'Q4' } })
  });
  const id = await fetchModelIdentity(settings, { fetchImpl });
  assert.equal(id.digest, 'sha256:abc');
  assert.equal(id.digest_status, 'reported');
  assert.equal(id.context_length, 32768);
  const down = await fetchModelIdentity(settings, { fetchImpl: async () => { throw new Error('refused'); } });
  assert.equal(down.digest, null);
  assert.equal(down.digest_status, 'unreachable');
  const other = await fetchModelIdentity({ provider: 'openai', model: 'x' }, { fetchImpl });
  assert.equal(other.digest_status, 'not_available_for_provider');
});

test('provenance records prompts, settings and what was missed', () => {
  const p = buildAiProvenance({
    settings,
    identity: { digest: 'sha256:abc', digest_status: 'reported', context_length: 32768 },
    meta: { ai_calls: 3, chunks_total: 2, chunks_completed: 1, chunk_failures: [{ chunk_key: 'c', code: 'x' }], timing: [{ prompt_eval_count: 900 }, { prompt_eval_count: 1200 }] },
    degraded: null
  });
  assert.equal(p.model_digest, 'sha256:abc');
  assert.equal(p.prompt_hash, promptFingerprint());
  assert.match(p.prompt_hash, /^[0-9a-f]{64}$/);
  assert.equal(p.inference.temperature, 0.1);
  assert.equal(p.inference.num_ctx_source, 'provider_default');
  assert.equal(p.inference.context_length, 32768);
  assert.equal(p.inference.max_prompt_eval_count, 1200);
  assert.equal(p.chunk_failures.length, 1);
});
