/**
 * Slow-provider / multi-timeout tests (no real multi-minute waits).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveAiTimeoutPolicy,
  isLocalAiProvider,
  AI_FAILURE_CODES
} from './timeouts.js';
import { consumeProviderStream } from './client.js';
import { buildAnalysisChunks, candidatesForChunk } from './analyze.js';
import { createCanonicalDocument } from '../canonicalDocument.js';

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function sseStreamFromEvents(events) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    async start(controller) {
      for (const ev of events) {
        if (ev.waitMs) await delay(ev.waitMs);
        if (ev.line != null) {
          controller.enqueue(encoder.encode(`${ev.line}\n`));
        }
      }
      controller.close();
    }
  });
}

test('local Ollama defaults are much more tolerant than hosted', () => {
  const local = resolveAiTimeoutPolicy({ provider: 'ollama', base_url: 'http://192.168.1.3:11434' });
  const hosted = resolveAiTimeoutPolicy({ provider: 'openai' });
  assert.equal(isLocalAiProvider({ provider: 'ollama', base_url: 'http://192.168.1.3:11434' }), true);
  assert.equal(isLocalAiProvider({ provider: 'openai' }), false);
  assert.ok(local.first_token_timeout_ms >= 300000);
  assert.ok(local.total_analysis_timeout_ms >= 1_800_000);
  assert.ok(hosted.first_token_timeout_ms < local.first_token_timeout_ms);
});

test('legacy timeout_ms seeds inactivity for local providers', () => {
  const p = resolveAiTimeoutPolicy({ provider: 'ollama', timeout_ms: 60000 });
  assert.ok(p.inactivity_timeout_ms >= 300000);
});

test('slow but active stream succeeds beyond old 60s wall clock (simulated)', async () => {
  // Virtual timeline: tokens every 25ms, total ~120ms activity window with short timeouts
  const body = sseStreamFromEvents([
    { waitMs: 20, line: 'data: {"choices":[{"delta":{"content":"{\\"summary\\":\\""}}]}' },
    { waitMs: 25, line: 'data: {"choices":[{"delta":{"content":"ok"}}]}' },
    { waitMs: 25, line: 'data: {"choices":[{"delta":{"content":"\\"}"}}]}' },
    { waitMs: 10, line: 'data: [DONE]' }
  ]);
  const text = await consumeProviderStream(body, {
    firstTokenTimeoutMs: 200,
    inactivityTimeoutMs: 80,
    totalDeadlineAt: Date.now() + 5000,
    parseLine: (line, acc) => {
      if (line === 'data: [DONE]') return;
      let payload = line.startsWith('data:') ? line.slice(5).trim() : line;
      try {
        const json = JSON.parse(payload);
        acc.text += json.choices?.[0]?.delta?.content || '';
      } catch {
        /* ignore */
      }
    }
  });
  assert.match(text, /summary/);
});

test('provider inactivity timeout when no further chunks arrive', async () => {
  const body = sseStreamFromEvents([
    { waitMs: 5, line: 'data: {"choices":[{"delta":{"content":"{"}}]}' },
    { waitMs: 200, line: 'data: {"choices":[{"delta":{"content":"x"}}]}' }
  ]);
  await assert.rejects(
    () =>
      consumeProviderStream(body, {
        firstTokenTimeoutMs: 100,
        inactivityTimeoutMs: 40,
        totalDeadlineAt: Date.now() + 5000,
        parseLine: (line, acc) => {
          if (!line.startsWith('data:')) return;
          try {
            const json = JSON.parse(line.slice(5).trim());
            acc.text += json.choices?.[0]?.delta?.content || '';
          } catch {
            /* ignore */
          }
        }
      }),
    (err) => err.code === AI_FAILURE_CODES.PROVIDER_INACTIVITY_TIMEOUT
  );
});

test('slow first token within allowance succeeds', async () => {
  const body = sseStreamFromEvents([
    { waitMs: 80, line: 'data: {"choices":[{"delta":{"content":"h"}}]}' },
    { waitMs: 10, line: 'data: {"choices":[{"delta":{"content":"i"}}]}' },
    { waitMs: 5, line: 'data: [DONE]' }
  ]);
  const text = await consumeProviderStream(body, {
    firstTokenTimeoutMs: 250,
    inactivityTimeoutMs: 200,
    totalDeadlineAt: Date.now() + 5000,
    parseLine: (line, acc) => {
      if (line === 'data: [DONE]' || line === '[DONE]') return;
      let payload = line.startsWith('data:') ? line.slice(5).trim() : line;
      if (!payload || payload[0] !== '{') return;
      try {
        acc.text += JSON.parse(payload).choices?.[0]?.delta?.content || '';
      } catch {
        /* ignore */
      }
    }
  });
  assert.equal(text, 'hi');
});

test('total deadline exceeded fails even if chunks arrive', async () => {
  const body = sseStreamFromEvents([
    { waitMs: 5, line: 'data: {"choices":[{"delta":{"content":"a"}}]}' },
    { waitMs: 50, line: 'data: {"choices":[{"delta":{"content":"b"}}]}' },
    { waitMs: 50, line: 'data: {"choices":[{"delta":{"content":"c"}}]}' }
  ]);
  await assert.rejects(
    () =>
      consumeProviderStream(body, {
        firstTokenTimeoutMs: 500,
        inactivityTimeoutMs: 500,
        totalDeadlineAt: Date.now() + 40,
        parseLine: (line, acc) => {
          if (!line.startsWith('data:')) return;
          try {
            acc.text += JSON.parse(line.slice(5).trim()).choices?.[0]?.delta?.content || '';
          } catch {
            /* ignore */
          }
        }
      }),
    (err) => err.code === AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE
  );
});

test('buildAnalysisChunks covers full document without discarding blocks', () => {
  const blocks = [];
  for (let i = 0; i < 50; i += 1) {
    blocks.push({ id: `b${i}`, type: 'paragraph', text: `Block ${i} ${'x'.repeat(800)}` });
  }
  const doc = createCanonicalDocument({ title: 't', blocks });
  const chunks = buildAnalysisChunks(doc, { maxInputChars: 20000, maxChunks: 8 });
  assert.ok(chunks.length >= 2);
  const covered = new Set(chunks.flatMap((c) => c.block_ids));
  assert.equal(covered.size, 50);
});

test('candidatesForChunk prefers evidence-local candidates', () => {
  const chunk = { block_ids: ['b2'] };
  const cands = [
    { candidate_type: 'domain', normalized_value: 'a.example', block_id: 'b1' },
    { candidate_type: 'domain', normalized_value: 'b.example', block_id: 'b2' },
    { candidate_type: 'ip', normalized_value: '1.2.3.4', block_id: null }
  ];
  assert.deepEqual(
    candidatesForChunk(cands, chunk, false).map((c) => c.normalized_value),
    ['b.example']
  );
  assert.equal(candidatesForChunk(cands, chunk, true).length, 2);
});
