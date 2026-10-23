/**
 * Provider call timing / cancellation contract over real HTTP (node:http
 * transport against test-support/mockOllamaServer.js). Timeouts are scaled to
 * milliseconds through the hooks.policy seam; the semantics are production's.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { callAiProvider } from './client.js';
import { AI_FAILURE_CODES, aiFailure, isTransientAiFailure } from './timeouts.js';
import { startMockOllama } from '../../../test-support/mockOllamaServer.js';
import { createMemoryInferenceScheduler } from '../../../test-support/memoryInferenceScheduler.js';

function policy(overrides = {}) {
  return {
    connection_timeout_ms: 1000,
    first_token_timeout_ms: 300,
    inactivity_timeout_ms: 300,
    total_analysis_timeout_ms: 30_000,
    max_concurrent_ai_requests: 1,
    capacity_wait_timeout_ms: 10_000,
    provider_execution_timeout_ms: 10_000,
    auto_retry_max_attempts: 2,
    is_local: true,
    ...overrides
  };
}

function settings(baseUrl) {
  return { enabled: true, provider: 'ollama', model: 'qwen3.5:9b', base_url: baseUrl };
}

const MSG = { system: 's', user: 'u' };

async function waitFor(pred, ms = 2000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return pred();
}

test('regression: without the gate a healthy queued request fails first_token_timeout (production failure)', async () => {
  // One long generation (500ms) ahead in the provider queue; first-token budget 300ms.
  const ollama = await startMockOllama({
    capacity: 1,
    plan: (r) => (r.user === 'long' ? { promptEvalMs: 20, genMs: 500 } : { promptEvalMs: 20, genMs: 50 })
  });
  try {
    const p = policy();
    const long = callAiProvider(settings(ollama.baseUrl), { system: 's', user: 'long' }, { policy: p });
    await new Promise((r) => setTimeout(r, 30));
    const queued = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: p }).catch((e) => e);
    assert.equal(queued.code, AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT, 'queue wait inside the provider is billed as first-token latency');
    await long;
  } finally {
    await ollama.close();
  }
});

test('with the gate: the same overlap succeeds; queue wait is slot wait, first token is measured after acquisition', async () => {
  const ollama = await startMockOllama({
    capacity: 1,
    plan: (r) => (r.user === 'long' ? { promptEvalMs: 20, genMs: 500 } : { promptEvalMs: 20, genMs: 50 })
  });
  const scheduler = createMemoryInferenceScheduler();
  try {
    const p = policy();
    const long = callAiProvider(settings(ollama.baseUrl), { system: 's', user: 'long' }, { policy: p, scheduler });
    await new Promise((r) => setTimeout(r, 30));
    const queued = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: p, scheduler });
    await long;
    assert.ok(queued.timing.slot_wait_ms >= 400, `slot wait ${queued.timing.slot_wait_ms}`);
    assert.ok(queued.timing.first_token_ms < 300, `first token ${queued.timing.first_token_ms}`);
    assert.ok(queued.timing.provider_queue_ms < 50, 'no residual queueing inside the provider');
    assert.equal(ollama.stats().maxExecuting, 1);
    assert.equal(ollama.stats().maxQueued, 0, 'the provider never had to queue a TalonHound request');
    assert.equal(scheduler.stats().maxHolding, 1);
  } finally {
    await ollama.close();
  }
});

test('first_token_timeout with the slot held: request aborted, provider sees the close, slot released after it', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ fault: 'hang_headers' }) });
  const scheduler = createMemoryInferenceScheduler();
  try {
    const started = Date.now();
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy(), scheduler }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT);
    assert.ok(Date.now() - started < 1500);
    assert.equal(err.timing.cancel_outcome, 'closed');
    assert.ok(await waitFor(() => ollama.requests[0].clientClosedEarly));
    assert.equal(ollama.requests[0].outcome, 'cancelled_executing');
    const release = scheduler.events.find((e) => e.type === 'release');
    assert.ok(release.at >= ollama.requests[0].clientClosedAt - 5, 'slot released only after the socket closed');
    assert.equal(scheduler.stats().holding, 0);
  } finally {
    await ollama.close();
  }
});

test('stream stall after the first token: provider_inactivity_timeout and the stream is cancelled (socket closed)', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ fault: 'stall_after_first' }) });
  try {
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy() }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.PROVIDER_INACTIVITY_TIMEOUT);
    assert.equal(err.timing.cancel_outcome, 'closed');
    assert.ok(await waitFor(() => ollama.requests[0].clientClosedEarly), 'releaseLock alone used to leave this socket open');
    assert.ok(err.timing.output_chars > 0, 'partial output is reported');
  } finally {
    await ollama.close();
  }
});

test('provider disconnect mid-stream: transient provider_unreachable, no hang', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ fault: 'disconnect_mid_stream' }) });
  try {
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy() }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.PROVIDER_UNREACHABLE);
    assert.equal(isTransientAiFailure(err.code), true);
  } finally {
    await ollama.close();
  }
});

test('connection refused: provider_unreachable without waiting for any timeout', async () => {
  const ollama = await startMockOllama();
  const { baseUrl } = ollama;
  await ollama.close();
  const started = Date.now();
  const err = await callAiProvider(settings(baseUrl), MSG, { policy: policy({ first_token_timeout_ms: 5000 }) }).catch((e) => e);
  assert.equal(err.code, AI_FAILURE_CODES.PROVIDER_UNREACHABLE);
  assert.ok(Date.now() - started < 1000);
});

test('HTTP 503 (provider busy): provider_http_error with status, classified transient', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ fault: 'http_503' }) });
  try {
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy() }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.PROVIDER_HTTP_ERROR);
    assert.equal(err.http_status, 503);
    assert.equal(isTransientAiFailure(err.code, err.http_status), true);
    assert.equal(isTransientAiFailure(err.code, 400), false);
  } finally {
    await ollama.close();
  }
});

test('per-request execution limit: a streaming request that never finishes fails provider_execution_timeout', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ promptEvalMs: 10, genMs: 2000, chunks: 40 }) });
  try {
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy({ provider_execution_timeout_ms: 400 }) }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.PROVIDER_EXECUTION_TIMEOUT);
    assert.ok(await waitFor(() => ollama.requests[0].clientClosedEarly));
  } finally {
    await ollama.close();
  }
});

test('outer cancellation (worker shutdown) aborts the stream with its own reason and frees the slot', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ promptEvalMs: 10, genMs: 2000, chunks: 40 }) });
  const scheduler = createMemoryInferenceScheduler();
  try {
    const controller = new AbortController();
    setTimeout(() => controller.abort(aiFailure(AI_FAILURE_CODES.WORKER_SHUTDOWN)), 150);
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy(), scheduler, signal: controller.signal }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.WORKER_SHUTDOWN);
    assert.ok(await waitFor(() => ollama.requests[0].clientClosedEarly));
    assert.equal(scheduler.stats().holding, 0);
  } finally {
    await ollama.close();
  }
});

test('cancellation while waiting for capacity: no provider request is ever sent', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ promptEvalMs: 10, genMs: 400 }) });
  const scheduler = createMemoryInferenceScheduler();
  try {
    const first = callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy(), scheduler });
    const controller = new AbortController();
    setTimeout(() => controller.abort(aiFailure(AI_FAILURE_CODES.JOB_CANCELLED)), 50);
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy(), scheduler, signal: controller.signal }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.JOB_CANCELLED);
    assert.ok(err.timing.slot_wait_ms >= 40);
    await first;
    assert.equal(ollama.requests.length, 1);
  } finally {
    await ollama.close();
  }
});

test('capacity wait budget exhausted: ai_capacity_wait_timeout, never a provider timeout code', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ promptEvalMs: 10, genMs: 400 }) });
  const scheduler = createMemoryInferenceScheduler();
  try {
    const first = callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy(), scheduler });
    const err = await callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy(), scheduler, capacityWaitBudgetMs: 100 }).catch((e) => e);
    assert.equal(err.code, AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT);
    assert.equal(isTransientAiFailure(err.code), false, 'sustained congestion is not auto-retried');
    await first;
    assert.equal(ollama.requests.length, 1);
  } finally {
    await ollama.close();
  }
});

test('active deadline excludes capacity wait: a call queued longer than the remaining active budget still runs', async () => {
  const ollama = await startMockOllama({ capacity: 1, plan: () => ({ promptEvalMs: 10, genMs: 300 }) });
  const scheduler = createMemoryInferenceScheduler();
  try {
    const first = callAiProvider(settings(ollama.baseUrl), MSG, { policy: policy(), scheduler });
    // 250ms of active budget left, but ~300ms of it is spent waiting for the slot.
    const res = await callAiProvider(settings(ollama.baseUrl), MSG, {
      policy: policy(),
      scheduler,
      callDeadlineAt: Date.now() + 1300
    });
    await first;
    assert.ok(res.timing.slot_wait_ms >= 250);
    assert.ok(res.text.length > 0);
  } finally {
    await ollama.close();
  }
});

test('residual provider contention while holding the slot is detected and reported', async () => {
  // capacity 1 provider, but a request from "outside TalonHound" (no scheduler) occupies it.
  const ollama = await startMockOllama({ capacity: 1, plan: (r) => (r.user === 'external' ? { promptEvalMs: 10, genMs: 200 } : { promptEvalMs: 10, genMs: 20 }) });
  const scheduler = createMemoryInferenceScheduler();
  try {
    const external = callAiProvider(settings(ollama.baseUrl), { system: 's', user: 'external' }, { policy: policy() });
    await new Promise((r) => setTimeout(r, 20));
    const res = await callAiProvider(settings(ollama.baseUrl), MSG, {
      policy: policy({ first_token_timeout_ms: 1000, provider_contention_threshold_ms: 50 }),
      scheduler
    });
    await external;
    assert.ok(res.timing.provider_queue_ms > 100);
    assert.equal(res.timing.provider_contention, true);
  } finally {
    await ollama.close();
  }
});
