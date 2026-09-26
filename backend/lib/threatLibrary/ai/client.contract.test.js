/**
 * Ollama request contract + stream metric capture.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { callAiProvider, parseOllamaNdjsonLine, consumeProviderStream, OLLAMA_NUM_PREDICT } from './client.js';
import { buildProviderJsonSchema, AI_OUTPUT_BOUNDS } from './contract.js';

test('Ollama num_predict matches the documented last-resort ceiling', () => {
  assert.equal(OLLAMA_NUM_PREDICT, AI_OUTPUT_BOUNDS.numPredict);
  assert.equal(OLLAMA_NUM_PREDICT, 10240);
});

test('Ollama chat request includes schema, think:false, temperature 0.1, finite num_predict', async () => {
  const schema = buildProviderJsonSchema();
  let captured = null;
  const doneLine = JSON.stringify({
    message: { content: '}' },
    done: true,
    prompt_eval_count: 111,
    eval_count: 22,
    total_duration: 3,
    load_duration: 4,
    prompt_eval_duration: 5,
    eval_duration: 6
  });
  const encoder = new TextEncoder();
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(`${JSON.stringify({ message: { content: '{"summary":"ok"' } })}\n`));
      controller.enqueue(encoder.encode(`${doneLine}\n`));
      controller.close();
    }
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    captured = JSON.parse(init.body);
    return { ok: true, body };
  };
  try {
    const result = await callAiProvider(
      { enabled: true, provider: 'ollama', model: 'qwen3.5:9b', base_url: 'http://127.0.0.1:11434' },
      { system: 'sys', user: 'usr' },
      { formatSchema: schema }
    );
    assert.equal(captured.stream, true);
    assert.equal(captured.think, false);
    assert.deepEqual(captured.format, schema);
    assert.equal(captured.options.temperature, 0.1);
    assert.equal(captured.options.num_predict, 10240);
    assert.equal(result.timing.prompt_eval_count, 111);
    assert.equal(result.timing.eval_count, 22);
    assert.equal(result.timing.total_duration, 3);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('missing Ollama done metrics are tolerated', async () => {
  const encoder = new TextEncoder();
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(`${JSON.stringify({ message: { content: 'hi' }, done: true })}\n`));
      controller.close();
    }
  });
  const stats = {};
  const text = await consumeProviderStream(body, {
    firstTokenTimeoutMs: 5_000,
    inactivityTimeoutMs: 5_000,
    totalDeadlineAt: Date.now() + 5_000,
    parseLine: parseOllamaNdjsonLine,
    stats
  });
  assert.equal(text, 'hi');
  assert.equal(stats.output_chars, 2);
  assert.equal(stats.provider_metrics, undefined);
});
