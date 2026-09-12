/**
 * Chunk checkpoint / resume tests (no live provider).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeThreatDocument, buildAnalysisChunks } from './analyze.js';
import { createCanonicalDocument } from '../canonicalDocument.js';
import { AI_FAILURE_CODES } from './timeouts.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './contract.js';

function sampleDoc(blockCount = 6) {
  const blocks = [];
  for (let i = 0; i < blockCount; i += 1) {
    blocks.push({
      id: `b${i}`,
      type: 'paragraph',
      text: `Section ${i}. Indicator example-${i}.example with padding ${'y'.repeat(2500)}`
    });
  }
  return createCanonicalDocument({ title: 'Slow Provider Report', language: 'en', blocks });
}

function okPayload(summary) {
  return JSON.stringify({
    summary,
    report_type: 'malware',
    language: 'en',
    tlp: 'TLP:AMBER',
    confidence: 0.7,
    entities: [],
    candidate_updates: [],
    relationships: []
  });
}

const settings = {
  enabled: true,
  provider: 'ollama',
  model: 'qwen3.5:9b',
  base_url: 'http://192.168.1.3:11434',
  max_input_chars: 12000,
  connection_timeout_ms: 5000,
  first_token_timeout_ms: 60_000,
  inactivity_timeout_ms: 60_000,
  total_analysis_timeout_ms: 600_000
};

test('checkpoint resume skips completed chunks on retry', async () => {
  const document = sampleDoc(8);
  const chunks = buildAnalysisChunks(document, { maxInputChars: 12000, maxChunks: 24 });
  assert.ok(chunks.length >= 3, `expected multiple chunks, got ${chunks.length}`);

  const completed = new Map();
  const providerCalls = [];

  // Seed chunks 1–3 as already completed
  for (let i = 0; i < 3; i += 1) {
    completed.set(chunks[i].chunk_key, {
      ok: true,
      schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
      value: {
        summary: `Cached ${i + 1}`,
        report_type: 'malware',
        language: 'en',
        tlp: 'TLP:AMBER',
        confidence: 0.5,
        entities: [],
        candidate_updates: [],
        relationships: []
      }
    });
  }

  const result = await analyzeThreatDocument(
    settings,
    { document, candidates: [] },
    {
      loadCompletedChunk: async (key) => completed.get(key) || null,
      saveChunkResult: async (chunk, value) => {
        completed.set(chunk.chunk_key, {
          ok: true,
          value,
          schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
        });
      },
      callProvider: async (_s, messages) => {
        providerCalls.push(messages.user.slice(0, 80));
        // Fail once on first live call, then succeed — proves we only call unfinished chunks
        if (providerCalls.length === 1) {
          const err = new Error('simulated chunk failure');
          err.code = AI_FAILURE_CODES.INVALID_AI_RESPONSE;
          throw err;
        }
        return { text: okPayload(`Live ${providerCalls.length}`) };
      }
    }
  ).catch((err) => err);

  assert.equal(result.code, AI_FAILURE_CODES.INVALID_AI_RESPONSE);
  assert.equal(providerCalls.length, 1, 'only first unfinished chunk should hit the provider');

  // Retry: same checkpoints → only remaining unfinished chunks
  providerCalls.length = 0;
  const resumed = await analyzeThreatDocument(
    settings,
    { document, candidates: [] },
    {
      loadCompletedChunk: async (key) => completed.get(key) || null,
      saveChunkResult: async (chunk, value) => {
        completed.set(chunk.chunk_key, {
          ok: true,
          value,
          schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
        });
      },
      callProvider: async () => {
        providerCalls.push('call');
        return { text: okPayload(`Resume ${providerCalls.length}`) };
      }
    }
  );

  assert.equal(resumed.ok, true);
  assert.ok(providerCalls.length >= 1);
  // Completed first 3 must not be re-sent (+ optional final synthesis call)
  assert.ok(providerCalls.length <= chunks.length - 3 + 1);
  assert.equal(completed.size, chunks.length);
});

test('browser-independent analysis: analyzeThreatDocument does not require an open HTTP request', async () => {
  // Structural guarantee: analysis is an async function with no req/res args.
  assert.equal(analyzeThreatDocument.length, 2);
  const document = sampleDoc(2);
  const out = await analyzeThreatDocument(
    settings,
    { document, candidates: [] },
    {
      callProvider: async () => ({ text: okPayload('done') })
    }
  );
  assert.equal(out.ok, true);
  assert.match(out.value.summary, /done|Cached|Live|Resume|Section/i);
});
