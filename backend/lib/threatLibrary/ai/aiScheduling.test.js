/**
 * Scheduling / timeout / retry policy contracts (pure, no database).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  AI_FAILURE_CODES,
  AI_FAILURE_MESSAGES,
  resolveAiTimeoutPolicy,
  inferenceResourceKey,
  isTransientAiFailure
} from './timeouts.js';
import { maskAiSettingsForClient } from './settings.js';
import { analyzeThreatDocument } from './analyze.js';
import { createCanonicalDocument } from '../canonicalDocument.js';
import { parseAiSchedulingSetting } from '../analysisConcurrency.js';
import { autoRetryDelayMs, decideAutoRetry, AUTO_RETRY_BASE_DELAY_MS, AUTO_RETRY_MAX_DELAY_MS } from '../autoRetry.js';

test('policy defaults: local Ollama gets capacity 1 (measured serial host), hosted providers 4', () => {
  const local = resolveAiTimeoutPolicy({ provider: 'ollama', base_url: 'http://192.168.1.8:11434' });
  assert.equal(local.max_concurrent_ai_requests, 1);
  assert.equal(local.capacity_wait_timeout_ms, 3_600_000);
  assert.equal(local.provider_execution_timeout_ms, 1_200_000);
  assert.equal(local.auto_retry_max_attempts, 2);
  assert.equal(local.first_token_timeout_ms, 300_000, 'first-response budget unchanged');
  assert.equal(local.total_analysis_timeout_ms, 1_800_000, 'active ceiling unchanged');
  const hosted = resolveAiTimeoutPolicy({ provider: 'openai', base_url: null });
  assert.equal(hosted.max_concurrent_ai_requests, 4);
  assert.ok(hosted.capacity_wait_timeout_ms < local.capacity_wait_timeout_ms);
});

test('policy: configured scheduling values are honoured and clamped', () => {
  const p = resolveAiTimeoutPolicy({ provider: 'ollama', max_concurrent_ai_requests: 3, capacity_wait_timeout_ms: 1, provider_execution_timeout_ms: 99_999_999, auto_retry_max_attempts: 9 });
  assert.equal(p.max_concurrent_ai_requests, 3);
  assert.equal(p.capacity_wait_timeout_ms, 10_000);
  assert.equal(p.provider_execution_timeout_ms, 7_200_000);
  assert.equal(p.auto_retry_max_attempts, 5);
});

test('capacity is per provider endpoint: models on the same host share it, trailing slash/case do not split it', () => {
  const a = inferenceResourceKey({ provider: 'ollama', base_url: 'http://192.168.1.8:11434/', model: 'qwen3.5:9b' });
  const b = inferenceResourceKey({ provider: 'ollama', base_url: 'HTTP://192.168.1.8:11434', model: 'llama3' });
  assert.equal(a, b);
  assert.notEqual(a, inferenceResourceKey({ provider: 'ollama', base_url: 'http://192.168.1.9:11434' }));
  assert.equal(inferenceResourceKey({ provider: 'ollama' }), 'ollama|http://127.0.0.1:11434');
});

test('transient classification: only provider/transport availability failures are retryable', () => {
  for (const code of ['first_token_timeout', 'provider_inactivity_timeout', 'connection_timeout', 'provider_unreachable', 'ai_capacity_unavailable', 'ai_capacity_lease_lost']) {
    assert.equal(isTransientAiFailure(code), true, code);
  }
  for (const code of ['ai_capacity_wait_timeout', 'provider_execution_timeout', 'total_analysis_deadline_exceeded', 'ai_validation', 'ai_output_schema_error', 'ai_output_parse_error', 'model_not_found', 'context_too_large', 'job_cancelled', 'worker_shutdown', 'job_ownership_lost', 'ai_generation_limit_exceeded']) {
    assert.equal(isTransientAiFailure(code), false, code);
  }
  assert.equal(isTransientAiFailure('provider_http_error', 503), true);
  assert.equal(isTransientAiFailure('provider_http_error', 429), true);
  assert.equal(isTransientAiFailure('provider_http_error', 400), false);
});

test('first_token_timeout message no longer blames model loading; every new code has a message', () => {
  assert.doesNotMatch(AI_FAILURE_MESSAGES[AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT], /loading/);
  for (const code of ['AI_CAPACITY_WAIT_TIMEOUT', 'AI_CAPACITY_UNAVAILABLE', 'AI_CAPACITY_LEASE_LOST', 'PROVIDER_EXECUTION_TIMEOUT', 'JOB_OWNERSHIP_LOST', 'WORKER_SHUTDOWN']) {
    assert.ok(AI_FAILURE_MESSAGES[AI_FAILURE_CODES[code]], code);
  }
});

test('automatic retry backoff: exponential, jittered within 25%, capped', () => {
  assert.equal(autoRetryDelayMs(1, () => 0), AUTO_RETRY_BASE_DELAY_MS);
  assert.equal(autoRetryDelayMs(2, () => 0), AUTO_RETRY_BASE_DELAY_MS * 2);
  assert.equal(autoRetryDelayMs(1, () => 1), AUTO_RETRY_BASE_DELAY_MS * 1.25);
  assert.equal(autoRetryDelayMs(20, () => 0), AUTO_RETRY_MAX_DELAY_MS);
});

test('automatic retry decision: transient + AI mode + attempts left', () => {
  assert.deepEqual(decideAutoRetry({ jobType: 'analyze', code: 'first_token_timeout', previousAttempt: 0, maxAttempts: 2 }), { retry: true, attempt: 1 });
  assert.equal(decideAutoRetry({ jobType: 'retry', code: 'provider_unreachable', previousAttempt: 2, maxAttempts: 2 }).reason, 'attempts_exhausted');
  assert.equal(decideAutoRetry({ jobType: 'analyze', code: 'ai_validation', maxAttempts: 2 }).reason, 'not_transient');
  assert.equal(decideAutoRetry({ jobType: 'refresh_extraction', code: 'first_token_timeout', maxAttempts: 2 }).reason, 'job_mode_not_retryable');
  assert.equal(decideAutoRetry({ jobType: 'analyze', code: 'first_token_timeout', maxAttempts: 0 }).retry, false, '0 disables');
});

test('settings validation: integers in range, null resets to the provider default', () => {
  assert.equal(parseAiSchedulingSetting('max_concurrent_ai_requests', '2'), 2);
  assert.equal(parseAiSchedulingSetting('max_concurrent_ai_requests', null), null);
  assert.equal(parseAiSchedulingSetting('auto_retry_max_attempts', 0), 0);
  assert.throws(() => parseAiSchedulingSetting('max_concurrent_ai_requests', 9), { code: 'invalid_max_concurrent_ai_requests', status: 400 });
  assert.throws(() => parseAiSchedulingSetting('capacity_wait_timeout_ms', 1.5), { code: 'invalid_capacity_wait_timeout_ms' });
  const masked = maskAiSettingsForClient({ enabled: true, provider: 'ollama', model: 'm', base_url: 'http://192.168.1.8:11434' });
  assert.equal(masked.max_concurrent_ai_requests, 1);
  assert.equal(masked.provider_execution_timeout_ms, 1_200_000);
});

function multiChunkDoc() {
  const prose = 'The operators rotate infrastructure between waves and reuse the loader with fresh configuration blobs. '.repeat(4);
  return createCanonicalDocument({
    title: 'Scheduling report',
    language: 'en',
    blocks: Array.from({ length: 16 }, (_, i) => ({ id: `b${i + 1}`, type: 'paragraph', page: 1, text: `${prose}Wave ${i + 1}.` }))
  });
}

const PAYLOAD = JSON.stringify({ summary: 'ok', entities: [], candidate_updates: [], relationships: [] });

test('every provider call of an analysis (chunks + synthesis) goes through the scheduler with its purpose', async () => {
  const scheduler = { acquire: async () => assert.fail('the scripted provider stands in for the client') };
  const calls = [];
  await analyzeThreatDocument(
    { enabled: true, provider: 'ollama', model: 'm', base_url: 'http://127.0.0.1:11434', max_input_chars: 1000 },
    { document: multiChunkDoc(), candidates: [] },
    {
      scheduler,
      reportId: 42,
      callProvider: async (_s, _m, hooks) => {
        calls.push({ scheduler: hooks.scheduler, purpose: hooks.purpose, reportId: hooks.reportId, budget: hooks.capacityWaitBudgetMs });
        return { text: PAYLOAD, timing: { total_ms: 1 } };
      }
    }
  );
  assert.ok(calls.length >= 3, `${calls.length} calls`);
  assert.ok(calls.every((c) => c.scheduler === scheduler && c.reportId === 42));
  assert.deepEqual([...new Set(calls.map((c) => c.purpose))].sort(), ['chunk', 'synthesis']);
  assert.ok(calls.every((c) => c.budget === 3_600_000));
});

test('capacity waits extend the active deadline and consume the cumulative capacity budget', async () => {
  const calls = [];
  const out = await analyzeThreatDocument(
    { enabled: true, provider: 'ollama', model: 'm', base_url: 'http://127.0.0.1:11434', max_input_chars: 1000 },
    { document: multiChunkDoc(), candidates: [] },
    {
      scheduler: {},
      analysisStartedAt: Date.now(),
      callProvider: async (_s, _m, hooks) => {
        calls.push({ deadline: hooks.callDeadlineAt, budget: hooks.capacityWaitBudgetMs, purpose: hooks.purpose });
        // Each call reports 10 minutes of capacity wait.
        return { text: PAYLOAD, timing: { total_ms: 1, slot_wait_ms: 600_000 } };
      }
    }
  );
  const chunkCalls = calls.filter((c) => c.purpose === 'chunk');
  assert.ok(chunkCalls[1].deadline - chunkCalls[0].deadline >= 600_000, 'the next chunk keeps its full active budget');
  assert.equal(chunkCalls[1].budget, 3_600_000 - 600_000);
  assert.ok(out.meta.ai_capacity_wait_ms >= 1_200_000);
  assert.ok(out.meta.active_elapsed_ms < out.meta.elapsed_ms + 1);
});

test('worker contract: DB-fenced ownership before the run, heartbeat, shutdown aborts and requeues, safety-net recovery', () => {
  const src = readFileSync(new URL('../../../threat-library-worker.js', import.meta.url), 'utf8');
  const claim = src.indexOf('claimJobOwnership(pool');
  const run = src.indexOf('runThreatLibraryJob(pool, {');
  assert.ok(claim > 0 && run > claim, 'ownership is claimed before the pipeline runs');
  assert.match(src, /duplicate delivery skipped/);
  assert.match(src, /startJobHeartbeat\(pool/);
  assert.match(src, /signal: controller\.signal/);
  assert.match(src, /run\.controller\.abort\(aiFailure\(AI_FAILURE_CODES\.WORKER_SHUTDOWN\)\)/);
  assert.match(src, /requeueAfterShutdown/);
  assert.match(src, /maybeScheduleAutoRetry\(pool/);
  assert.match(src.slice(src.indexOf('const safetyTimer')), /recoverInterruptedAnalysisJobs/);
});

test('probe contract: the connection test takes a capacity slot and never unloads the model', () => {
  const src = readFileSync(new URL('./probe.js', import.meta.url), 'utf8');
  assert.match(src, /scheduler: deps\.scheduler/);
  assert.doesNotMatch(src, /keepAlive: '0'/);
  const routes = readFileSync(new URL('../../../routes/threatLibrary.js', import.meta.url), 'utf8');
  assert.match(routes, /probeAiProvider\(settings, \{ scheduler:/);
});

test('pipeline contract: the shared scheduler is the default for every analysis', () => {
  const src = readFileSync(new URL('../pipeline.js', import.meta.url), 'utf8');
  assert.match(src, /deps\.inferenceScheduler === undefined \? getInferenceScheduler\(pool\)/);
  assert.match(src, /scheduler: inferenceScheduler/);
});
