/**
 * Streaming AI HTTP client with connection / first-token / inactivity watches.
 * Ollama uses native /api/chat streaming + keep_alive (server-side only).
 */

import {
  AI_FAILURE_CODES,
  aiFailure,
  classifyProviderHttpError,
  sanitizeProviderHttpError,
  resolveAiTimeoutPolicy,
  resolveHeaderWaitMs,
  inferenceResourceKey
} from './timeouts.js';
import { assertAiReady } from './settings.js';
import { AI_OUTPUT_BOUNDS } from './contract.js';
import { nodeHttpTransport } from './providerHttp.js';
import { createServiceLogger } from '../../appLogger.js';

const log = createServiceLogger('threat-library-ai');

/** Bound on waiting for a cancelled request's socket to close before the slot is released. */
export const CANCEL_CLOSE_WAIT_MS = 5000;

/**
 * Idle probe (quarantine release): budget for a 1-token request to start
 * streaming. Served within it ⇒ the provider has a free execution slot.
 * Covers a cold model load (≤ 8s measured) with margin.
 */
export const IDLE_PROBE_TIMEOUT_MS = 20_000;

/**
 * Failures after which the provider has certainly finished with the request:
 * it answered with an error status / error line. Everything else that happens
 * after the request was sent (our timeouts, cancellation, shutdown, lost
 * lease or ownership, resets) leaves provider-side termination unproven.
 */
const PROVIDER_FINISHED_CODES = new Set([AI_FAILURE_CODES.PROVIDER_HTTP_ERROR, AI_FAILURE_CODES.MODEL_NOT_FOUND, AI_FAILURE_CODES.CONTEXT_TOO_LARGE]);

/**
 * Quarantine instead of release: a local (capacity-limited) provider, the
 * request reached it, and nothing proves the provider stopped executing it.
 * Closing the socket is not proof — a lost FIN or a provider that ignores
 * the disconnect keeps generating.
 * @param {Error & { code?: string, timing?: object }} err
 * @param {object} policy
 */
export function requiresSlotQuarantine(err, policy) {
  if (!policy?.is_local) return false;
  if (err?.timing?.request_sent !== true) return false;
  return !PROVIDER_FINISHED_CODES.has(err?.code);
}

/**
 * Prove the provider can serve a request right now: a 1-token request, sent
 * from inside the quarantined slot, must start streaming within the budget.
 * A provider still executing an abandoned request queues it instead.
 * @param {object} settings
 * @param {object} policy
 * @param {Function} transport
 * @returns {Promise<boolean>}
 */
export async function verifyProviderIdle(settings, policy, transport = nodeHttpTransport) {
  const endpoint = resolveProviderEndpoint(settings);
  const budgetMs = Number(policy?.idle_probe_timeout_ms) || IDLE_PROBE_TIMEOUT_MS;
  const messages = [{ role: 'user', content: 'Reply with OK.' }];
  let body;
  const headers = { 'content-type': 'application/json' };
  if (endpoint.kind === 'ollama_stream') {
    body = { model: settings.model, stream: true, think: false, keep_alive: '15m', options: { temperature: 0, num_predict: 1 }, messages };
  } else if (endpoint.kind === 'anthropic_stream') {
    headers['x-api-key'] = String(settings.api_key || '');
    headers['anthropic-version'] = '2023-06-01';
    body = { model: settings.model, max_tokens: 1, stream: true, messages };
  } else {
    if (settings.api_key) headers.authorization = `Bearer ${settings.api_key}`;
    body = { model: settings.model, max_tokens: 1, stream: true, messages };
  }
  const controller = new AbortController();
  // The probe bounds itself: even a transport that ignored the abort could
  // never leave a quarantined slot stuck "being verified".
  let timer;
  const expired = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = aiFailure(AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT);
      controller.abort(err);
      reject(err);
    }, budgetMs);
  });
  expired.catch(() => {});
  let call = null;
  try {
    call = transport(endpoint.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      connectTimeoutMs: policy?.connection_timeout_ms
    });
    const res = await Promise.race([call.response, expired]);
    if (!res.ok) return false;
    const reader = res.body?.getReader?.();
    if (reader) {
      while (true) {
        const { done } = await Promise.race([reader.read(), expired]);
        if (done) break;
      }
    }
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
    if (!controller.signal.aborted) controller.abort(aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
  }
}

/** Provider-side queue time (ms) above which a slot holder reports residual contention. */
export const PROVIDER_CONTENTION_THRESHOLD_MS = 5000;

/** Last-resort Ollama generation ceiling. See AI_OUTPUT_BOUNDS.numPredict. */
export const OLLAMA_NUM_PREDICT = AI_OUTPUT_BOUNDS.numPredict;

/** Provider stop reasons that mean "token ceiling reached", not a natural end. */
const LENGTH_STOP_REASONS = new Set(['length', 'max_tokens']);

/**
 * True when the provider stopped because the generation token ceiling was
 * reached (Ollama done_reason "length" / eval_count >= num_predict, OpenAI
 * finish_reason "length", Anthropic stop_reason "max_tokens"). Output cut at
 * the ceiling is incomplete by construction: the remainder was never generated.
 * @param {{ done_reason?: string|null, eval_count?: number, num_predict?: number }|null|undefined} timing
 */
export function isGenerationLimitHit(timing) {
  if (!timing || typeof timing !== 'object') return false;
  if (timing.done_reason && LENGTH_STOP_REASONS.has(String(timing.done_reason))) return true;
  const evalCount = Number(timing.eval_count);
  const numPredict = Number(timing.num_predict);
  return Number.isFinite(evalCount) && Number.isFinite(numPredict) && numPredict > 0 && evalCount >= numPredict;
}

function withDoneReason(acc, reason) {
  if (!reason) return;
  acc.provider_metrics = { ...(acc.provider_metrics || {}), done_reason: String(reason).slice(0, 32) };
}

/**
 * @param {object} settings
 */
export function resolveProviderEndpoint(settings) {
  const provider = settings.provider;
  if (provider === 'openai') {
    return {
      kind: 'openai_stream',
      url: `${(settings.base_url || 'https://api.openai.com/v1').replace(/\/$/, '')}/chat/completions`
    };
  }
  if (provider === 'anthropic') {
    return {
      kind: 'anthropic_stream',
      url: `${(settings.base_url || 'https://api.anthropic.com').replace(/\/$/, '')}/v1/messages`
    };
  }
  if (provider === 'ollama') {
    const base = (settings.base_url || 'http://127.0.0.1:11434').replace(/\/$/, '');
    return { kind: 'ollama_stream', url: `${base}/api/chat`, base };
  }
  const base = String(settings.base_url || '').replace(/\/$/, '');
  return { kind: 'openai_stream', url: `${base}/chat/completions` };
}

/**
 * @param {Response} res
 * @param {number} connectionTimeoutMs
 * @param {AbortSignal} signal
 */
async function waitForHeaders(fetchPromise, connectionTimeoutMs, signal, timeoutError = () => aiFailure(AI_FAILURE_CODES.CONNECTION_TIMEOUT)) {
  let timer;
  try {
    return await Promise.race([
      fetchPromise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(timeoutError());
        }, connectionTimeoutMs);
        if (signal) {
          const onAbort = () => {
            clearTimeout(timer);
            reject(signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
          };
          if (signal.aborted) onAbort();
          else signal.addEventListener('abort', onAbort, { once: true });
        }
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read a streaming body with first-token + inactivity watchdogs.
 * @param {ReadableStream|null} body
 * @param {{
 *   firstTokenTimeoutMs: number,
 *   inactivityTimeoutMs: number,
 *   totalDeadlineAt: number,
 *   deadlineCode?: string,
 *   startedAt?: number,
 *   signal?: AbortSignal,
 *   onActivity?: (info: { bytes: number, firstToken: boolean }) => void,
 *   onChunkText?: (text: string) => void,
 *   parseLine?: (line: string, acc: { text: string }) => void
 * }} opts
 */
export async function consumeProviderStream(body, opts) {
  if (!body || typeof body.getReader !== 'function') {
    throw aiFailure(AI_FAILURE_CODES.INVALID_AI_RESPONSE, 'AI provider returned no stream body');
  }

  const reader = body.getReader();
  const decoder = new TextDecoder();
  // Activity callbacks are fire-and-forget (the stream must not wait on a
  // progress write); a rejection must never become an unhandled rejection.
  const notifyActivity = (info) => {
    try {
      const pending = opts.onActivity?.(info);
      if (pending && typeof pending.catch === 'function') pending.catch(() => {});
    } catch { /* progress is best-effort */ }
  };
  let buffer = '';
  let text = '';
  let thinking = 0;
  let providerMetrics = null;
  let gotFirst = false;
  let firstTokenAt = null;
  let lastActivity = Date.now();
  // First-token budget runs from when the request was sent (not from when
  // headers arrived), so header wait + body wait never exceed one budget.
  const started = Number(opts.startedAt) > 0 ? Number(opts.startedAt) : Date.now();
  const tickMs = Math.min(
    1000,
    Math.max(
      50,
      Math.min(
        Math.floor(opts.firstTokenTimeoutMs / 4) || 250,
        Math.floor(opts.inactivityTimeoutMs / 4) || 250
      )
    )
  );

  const checkWatchdogs = () => {
    if (opts.signal?.aborted) {
      throw opts.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED);
    }
    const now = Date.now();
    if (now > opts.totalDeadlineAt) {
      throw aiFailure(opts.deadlineCode || AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE);
    }
    if (!gotFirst && now - started > opts.firstTokenTimeoutMs) {
      throw aiFailure(AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT);
    }
    if (gotFirst && now - lastActivity > opts.inactivityTimeoutMs) {
      throw aiFailure(AI_FAILURE_CODES.PROVIDER_INACTIVITY_TIMEOUT);
    }
  };

  // Poll watchdogs while waiting on read() — never call read() concurrently.
  let pendingRead = null;
  const readWithWatchdog = async () => {
    while (true) {
      checkWatchdogs();
      if (!pendingRead) {
        pendingRead = reader.read().then((r) => {
          pendingRead = null;
          return { type: 'read', r };
        });
      }
      const race = await Promise.race([
        pendingRead,
        new Promise((resolve) => setTimeout(() => resolve({ type: 'tick' }), tickMs))
      ]);
      if (race.type === 'tick') continue;
      return race.r;
    }
  };

  try {
    while (true) {
      const { done, value } = await readWithWatchdog();
      if (done) break;
      if (!value || value.byteLength === 0) continue;

      if (!gotFirst) {
        gotFirst = true;
        firstTokenAt = Date.now();
        notifyActivity({ bytes: value.byteLength, firstToken: true });
      } else {
        notifyActivity({ bytes: value.byteLength, firstToken: false });
      }
      lastActivity = Date.now();

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (opts.parseLine) {
          const before = text;
          const acc = { text, thinking, provider_metrics: providerMetrics };
          opts.parseLine(trimmed, acc);
          text = acc.text;
          thinking = acc.thinking || thinking;
          if (acc.provider_metrics) providerMetrics = acc.provider_metrics;
          if (text !== before) {
            lastActivity = Date.now();
            opts.onChunkText?.(text.slice(before.length));
          }
        } else {
          text += `${trimmed}\n`;
          opts.onChunkText?.(trimmed);
        }
      }
    }
    if (buffer.trim()) {
      if (opts.parseLine) {
        const acc = { text, thinking, provider_metrics: providerMetrics };
        opts.parseLine(buffer.trim(), acc);
        text = acc.text;
        thinking = acc.thinking || thinking;
        if (acc.provider_metrics) providerMetrics = acc.provider_metrics;
      } else {
        text += buffer;
      }
    }
  } catch (err) {
    // Cancel the body so the socket closes and the provider stops generating;
    // releasing the lock alone leaves the response stream (and the provider's
    // work) running. Bounded so cleanup can never mask the original error.
    if (opts.stats) opts.stats.partial_output_chars = text.length;
    await Promise.race([
      reader.cancel(err).catch(() => {}),
      new Promise((resolve) => setTimeout(resolve, 1000))
    ]);
    throw err;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }

  if (!gotFirst) {
    throw aiFailure(AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT);
  }
  if (opts.stats) {
    opts.stats.first_token_ms = firstTokenAt ? firstTokenAt - started : null;
    opts.stats.thinking_chars = thinking;
    opts.stats.output_chars = text.length;
    if (providerMetrics) opts.stats.provider_metrics = providerMetrics;
  }
  return text;
}

function parseOpenAiSseLine(line, acc) {
  if (line === 'data: [DONE]' || line === '[DONE]') return;
  let payload = line;
  if (payload.startsWith('data:')) payload = payload.slice(5).trim();
  if (!payload || payload[0] !== '{') return;
  try {
    const json = JSON.parse(payload);
    const delta = json.choices?.[0]?.delta?.content || json.choices?.[0]?.message?.content || '';
    if (delta) acc.text += delta;
    withDoneReason(acc, json.choices?.[0]?.finish_reason);
  } catch {
    /* ignore partial json */
  }
}

function parseAnthropicSseLine(line, acc) {
  if (!line.startsWith('data:')) return;
  const payload = line.slice(5).trim();
  if (!payload || payload[0] !== '{') return;
  try {
    const json = JSON.parse(payload);
    if (json.type === 'content_block_delta' && json.delta?.text) {
      acc.text += json.delta.text;
    } else if (json.type === 'content_block_start' && json.content_block?.text) {
      acc.text += json.content_block.text;
    } else if (json.type === 'message_delta') {
      withDoneReason(acc, json.delta?.stop_reason);
    }
  } catch {
    /* ignore */
  }
}

function pickOllamaMetrics(json) {
  if (!json || json.done !== true) return null;
  const keys = [
    'prompt_eval_count',
    'eval_count',
    'total_duration',
    'load_duration',
    'prompt_eval_duration',
    'eval_duration'
  ];
  const out = {};
  let any = false;
  for (const key of keys) {
    const n = Number(json[key]);
    if (Number.isFinite(n)) {
      out[key] = n;
      any = true;
    }
  }
  if (typeof json.done_reason === 'string' && json.done_reason) {
    out.done_reason = json.done_reason.slice(0, 32);
    any = true;
  }
  return any ? out : null;
}

export function parseOllamaNdjsonLine(line, acc) {
  if (!line || line[0] !== '{') return;
  try {
    const json = JSON.parse(line);
    const piece = json.message?.content || json.response || '';
    if (piece) acc.text += piece;
    // Reasoning models stream "thinking" separately; it never reaches the JSON output.
    if (json.message?.thinking) acc.thinking = (acc.thinking || 0) + String(json.message.thinking).length;
    const metrics = pickOllamaMetrics(json);
    if (metrics) acc.provider_metrics = metrics;
    if (json.error) {
      const err = aiFailure(AI_FAILURE_CODES.PROVIDER_HTTP_ERROR, String(json.error));
      throw err;
    }
  } catch (err) {
    if (err?.code) throw err;
    /* ignore partial */
  }
}

/**
 * Build the provider request body (no transport concerns).
 * @param {object} settings
 * @param {{ kind: string }} endpoint
 * @param {{ system: string, user: string }} messages
 * @param {object} hooks
 * @param {number} numPredict
 */
function buildProviderRequest(settings, endpoint, messages, hooks, numPredict) {
  if (endpoint.kind === 'ollama_stream') {
    return {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: settings.model,
        stream: true,
        // Prefer JSON Schema when provided (Ollama structured outputs); else json mode.
        format: hooks.formatSchema || 'json',
        // Reasoning models (qwen3.x, deepseek-r1, …) otherwise spend minutes on
        // hidden "thinking" before the constrained JSON starts. Extraction does
        // not need chain-of-thought; older Ollama versions ignore the field.
        think: false,
        keep_alive: hooks.keepAlive || '15m',
        options: {
          temperature: 0.1,
          // Last-resort token ceiling; schema maxItems should stop generation first.
          num_predict: numPredict
        },
        messages: [
          { role: 'system', content: messages.system },
          { role: 'user', content: messages.user }
        ]
      })
    };
  }
  if (endpoint.kind === 'anthropic_stream') {
    return {
      headers: {
        'content-type': 'application/json',
        'x-api-key': String(settings.api_key || ''),
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: settings.model,
        max_tokens: 8192,
        stream: true,
        system: messages.system,
        messages: [{ role: 'user', content: messages.user }]
      })
    };
  }
  const headers = { 'content-type': 'application/json' };
  if (settings.api_key) headers.authorization = `Bearer ${settings.api_key}`;
  return {
    headers,
    body: JSON.stringify({
      model: settings.model,
      temperature: 0.1,
      stream: true,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: messages.system },
        { role: 'user', content: messages.user }
      ]
    })
  };
}

/** Ollama reports wall time from request receipt; what load/prompt/eval do not explain is its own queue. */
export function providerQueueMs(metrics) {
  if (!metrics || !Number.isFinite(Number(metrics.total_duration))) return null;
  const ns =
    Number(metrics.total_duration) -
    (Number(metrics.load_duration) || 0) -
    (Number(metrics.prompt_eval_duration) || 0) -
    (Number(metrics.eval_duration) || 0);
  return Math.max(0, Math.round(ns / 1e6));
}

const KNOWN_FAILURE_CODES = new Set(Object.values(AI_FAILURE_CODES));

function mapTransportError(err) {
  if (err?.code && KNOWN_FAILURE_CODES.has(err.code)) return err;
  if (err?.name === 'AbortError') return aiFailure(AI_FAILURE_CODES.JOB_CANCELLED);
  const msg = String(err?.message || err);
  const sysCode = String(err?.code || err?.cause?.code || '');
  if (/ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT/i.test(sysCode)) return aiFailure(AI_FAILURE_CODES.CONNECTION_TIMEOUT, msg);
  return aiFailure(AI_FAILURE_CODES.PROVIDER_UNREACHABLE, msg);
}

async function waitForClose(closed, ms) {
  if (!closed) return 'not_started';
  let timer;
  try {
    return await Promise.race([
      closed.then((v) => v || 'closed', () => 'closed'),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve('unconfirmed'), ms);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * One provider call:
 *   1. capacity wait (hooks.scheduler) — bounded by the capacity-wait budget,
 *      never counted as provider latency or against the active deadline;
 *   2. connect — connection_timeout_ms;
 *   3. first response — first_token_timeout_ms from the moment the request is
 *      sent (local: HTTP headers carry the first token; hosted: headers within
 *      connection_timeout_ms, then the first streamed text);
 *   4. stream inactivity — inactivity_timeout_ms between chunks;
 *   5. execution — provider_execution_timeout_ms for the whole request;
 *   6. active analysis deadline — hooks.callDeadlineAt (or analysisStartedAt +
 *      total_analysis_timeout_ms), shifted by this call's capacity wait.
 * Every failure aborts the request and waits (bounded) for the socket to
 * close before the inference slot is released.
 *
 * @param {object} settings
 * @param {{ system: string, user: string }} messages
 * @param {{
 *   onActivity?: Function,
 *   signal?: AbortSignal,
 *   analysisStartedAt?: number,
 *   callDeadlineAt?: number,
 *   keepAlive?: string,
 *   formatSchema?: object,
 *   numPredict?: number,
 *   scheduler?: { acquire: Function },
 *   capacityWaitBudgetMs?: number,
 *   onCapacityWait?: Function,
 *   onCapacityAcquired?: Function,
 *   purpose?: string,
 *   reportId?: number|null,
 *   transport?: Function,
 *   policy?: object
 * }} [hooks]
 */
export async function callAiProvider(settings, messages, hooks = {}) {
  assertAiReady(settings);
  // hooks.policy: a pre-resolved policy (tests / tools need sub-second timeouts
  // below the production clamps); production callers never pass it.
  const policy = hooks.policy || resolveAiTimeoutPolicy(settings);
  const endpoint = resolveProviderEndpoint(settings);
  const telemetry = {
    purpose: hooks.purpose || null,
    report_id: hooks.reportId ?? null,
    provider: endpoint.kind,
    model: settings.model || null
  };

  let lease = null;
  let slotWaitMs = 0;
  if (hooks.scheduler) {
    const waitStartedAt = Date.now();
    const budget = hooks.capacityWaitBudgetMs != null ? Number(hooks.capacityWaitBudgetMs) : policy.capacity_wait_timeout_ms;
    try {
      lease = await hooks.scheduler.acquire({
        resourceKey: inferenceResourceKey(settings),
        capacity: policy.max_concurrent_ai_requests,
        maxWaitMs: Math.max(0, budget),
        signal: hooks.signal,
        purpose: hooks.purpose,
        reportId: hooks.reportId,
        onWaiting: hooks.onCapacityWait,
        // A waiter at the head of the queue probes quarantined slots.
        verifyIdle: () => verifyProviderIdle(settings, policy, hooks.transport || nodeHttpTransport),
        // Local providers are fail-closed: an expired or unverified slot is
        // never handed out by time (inferenceScheduler.js).
        failClosed: policy.is_local === true,
        maxExecutionMs: policy.provider_execution_timeout_ms
      });
    } catch (err) {
      const failure = mapTransportError(err);
      failure.timing = { ...(failure.timing || {}), slot_wait_ms: Date.now() - waitStartedAt };
      log.warn('AI request not started', { ...telemetry, code: failure.code, slot_wait_ms: failure.timing.slot_wait_ms });
      throw failure;
    }
    slotWaitMs = lease.waitMs;
    if (lease.maxPosition > 0) {
      try {
        await hooks.onCapacityAcquired?.({ wait_ms: slotWaitMs });
      } catch { /* progress is best-effort */ }
    }
  }

  try {
    const result = await executeProviderCall(settings, messages, hooks, { policy, endpoint, lease, slotWaitMs, telemetry });
    if (lease) await lease.release();
    return result;
  } catch (err) {
    if (lease) {
      if (requiresSlotQuarantine(err, policy) && typeof lease.quarantine === 'function') {
        // The provider may still be executing the aborted request: the slot
        // stays occupied until it is verified idle, at most until the
        // request's worst-case execution bound (from when it was sent).
        const startedAt = Number(err.timing?.request_started_at) || Date.now();
        const floorMs = Math.min(1000, policy.provider_execution_timeout_ms);
        const holdMs = Math.max(floorMs, startedAt + policy.provider_execution_timeout_ms - Date.now());
        await lease.quarantine({ holdMs, reason: err.code });
        err.timing = { ...(err.timing || {}), slot_quarantined: true };
        // First probe right away (background; the caller gets its error now).
        // Later probes come from whichever waiter reaches the head of the queue.
        if (typeof hooks.scheduler?.verifyQuarantine === 'function') {
          const resourceKey = inferenceResourceKey(settings);
          hooks.scheduler
            .verifyQuarantine(resourceKey, () => verifyProviderIdle(settings, policy, hooks.transport || nodeHttpTransport))
            .catch(() => {});
        }
      } else {
        await lease.release();
      }
    }
    throw err;
  }
}

async function executeProviderCall(settings, messages, hooks, ctx) {
  const { policy, endpoint, lease, slotWaitMs, telemetry } = ctx;
  const analysisStartedAt = hooks.analysisStartedAt || Date.now();
  const globalDeadlineAt = analysisStartedAt + policy.total_analysis_timeout_ms;
  const hookedDeadline = Number(hooks.callDeadlineAt);
  // Deadlines measure active time: this call's capacity wait is added back.
  const activeDeadlineAt =
    (Number.isFinite(hookedDeadline) && hookedDeadline > 0 ? Math.min(globalDeadlineAt, hookedDeadline) : globalDeadlineAt) +
    slotWaitMs;
  const requestStartedAt = Date.now();
  const executionDeadlineAt = requestStartedAt + policy.provider_execution_timeout_ms;
  const totalDeadlineAt = Math.min(activeDeadlineAt, executionDeadlineAt);
  const deadlineCode =
    executionDeadlineAt < activeDeadlineAt
      ? AI_FAILURE_CODES.PROVIDER_EXECUTION_TIMEOUT
      : AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE;
  const slotTiming = {
    slot_wait_ms: slotWaitMs,
    ...(lease
      ? {
          slot_max_position: lease.maxPosition ?? 0,
          slot_holders_at_acquire: lease.holdersAtAcquire ?? null,
          slot_capacity: lease.capacity ?? null
        }
      : {})
  };

  if (activeDeadlineAt - Date.now() <= 1000) {
    throw Object.assign(aiFailure(AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE), { timing: { ...slotTiming } });
  }

  const controller = new AbortController();
  const onOuterAbort = () => controller.abort(hooks.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
  if (hooks.signal) {
    if (hooks.signal.aborted) onOuterAbort();
    else hooks.signal.addEventListener('abort', onOuterAbort, { once: true });
  }
  const offLeaseLost = lease?.onLost?.((err) => controller.abort(err)) || null;

  const promptChars = String(messages.system || '').length + String(messages.user || '').length;
  const numPredict = Number(hooks.numPredict) > 0 ? Number(hooks.numPredict) : OLLAMA_NUM_PREDICT;
  const transport = hooks.transport || nodeHttpTransport;

  let call = null;
  let headersAt = null;
  const stats = {};
  try {
    const request = buildProviderRequest(settings, endpoint, messages, hooks, numPredict);
    call = transport(endpoint.url, {
      method: 'POST',
      headers: request.headers,
      body: request.body,
      signal: controller.signal,
      connectTimeoutMs: policy.connection_timeout_ms
    });

    let res;
    try {
      const headerBudgetMs = policy.is_local ? policy.first_token_timeout_ms : resolveHeaderWaitMs(policy);
      const headerWaitMs = Math.min(headerBudgetMs, Math.max(totalDeadlineAt - Date.now(), 1000));
      const limitedByDeadline = headerWaitMs < headerBudgetMs;
      res = await waitForHeaders(call.response, headerWaitMs, controller.signal, () => {
        if (limitedByDeadline) return aiFailure(deadlineCode);
        // Local providers withhold headers until the first token is ready.
        return aiFailure(policy.is_local ? AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT : AI_FAILURE_CODES.CONNECTION_TIMEOUT);
      });
      headersAt = Date.now();
    } catch (err) {
      throw mapTransportError(err);
    }

    if (!res.ok) {
      let bodyText = '';
      try {
        bodyText = await res.text();
      } catch {
        bodyText = '';
      }
      const code = classifyProviderHttpError(res.status, bodyText);
      const diagnostic = sanitizeProviderHttpError(res.status, bodyText);
      const err = aiFailure(code, `AI provider error (${res.status}): ${diagnostic.message}`);
      err.http_status = diagnostic.http_status;
      err.provider_error = diagnostic;
      throw err;
    }

    const parseLine =
      endpoint.kind === 'ollama_stream'
        ? parseOllamaNdjsonLine
        : endpoint.kind === 'anthropic_stream'
          ? parseAnthropicSseLine
          : parseOpenAiSseLine;

    const text = await consumeProviderStream(res.body, {
      firstTokenTimeoutMs: policy.first_token_timeout_ms,
      inactivityTimeoutMs: policy.inactivity_timeout_ms,
      totalDeadlineAt,
      deadlineCode,
      startedAt: requestStartedAt,
      signal: controller.signal,
      onActivity: hooks.onActivity,
      parseLine,
      stats
    });

    const timing = {
      total_ms: Date.now() - requestStartedAt,
      headers_ms: headersAt ? headersAt - requestStartedAt : null,
      first_token_ms: stats.first_token_ms ?? null,
      stream_ms: headersAt ? Date.now() - headersAt : null,
      prompt_chars: promptChars,
      output_chars: stats.output_chars ?? text.length,
      thinking_chars: stats.thinking_chars ?? 0,
      provider: endpoint.kind,
      ...slotTiming,
      ...(endpoint.kind === 'ollama_stream' ? { num_predict: numPredict } : {}),
      ...(stats.provider_metrics || {})
    };
    timing.generation_limit_hit = isGenerationLimitHit(timing);
    const queueMs = providerQueueMs(stats.provider_metrics);
    if (queueMs != null) {
      timing.provider_queue_ms = queueMs;
      if (lease && queueMs > (Number(policy.provider_contention_threshold_ms) || PROVIDER_CONTENTION_THRESHOLD_MS)) {
        // We held the TalonHound slot, yet the provider still queued the
        // request: something outside TalonHound uses the same inference host.
        timing.provider_contention = true;
        log.warn('residual provider contention while holding AI capacity', {
          ...telemetry,
          provider_queue_ms: queueMs,
          slot_wait_ms: slotWaitMs
        });
      }
    }
    log.info('AI request completed', {
      ...telemetry,
      slot_wait_ms: slotWaitMs,
      headers_ms: timing.headers_ms,
      first_token_ms: timing.first_token_ms,
      total_ms: timing.total_ms,
      provider_queue_ms: timing.provider_queue_ms ?? null,
      prompt_eval_count: timing.prompt_eval_count ?? null,
      eval_count: timing.eval_count ?? null,
      done_reason: timing.done_reason ?? null
    });
    return { text, policy, timing };
  } catch (rawErr) {
    // A deliberate abort (shutdown, cancel, lost lease) surfaces from the
    // socket as ECONNRESET / "aborted": report the reason we aborted with.
    const abortReason = controller.signal.aborted ? controller.signal.reason : null;
    const err = abortReason?.code && KNOWN_FAILURE_CODES.has(abortReason.code) && !KNOWN_FAILURE_CODES.has(rawErr?.code)
      ? abortReason
      : mapTransportError(rawErr);
    // Stop the outstanding request before reporting (and before the caller
    // releases the inference slot): abort destroys the socket, the provider
    // sees the close and drops the work.
    if (!controller.signal.aborted) controller.abort(err);
    const cancelOutcome = await waitForClose(call?.closed, Number(policy.cancel_close_wait_ms) || CANCEL_CLOSE_WAIT_MS);
    err.timing = {
      ...(err.timing || {}),
      total_ms: Date.now() - requestStartedAt,
      headers_ms: headersAt ? headersAt - requestStartedAt : null,
      prompt_chars: promptChars,
      output_chars: stats.partial_output_chars ?? 0,
      provider: endpoint.kind,
      ...slotTiming,
      cancel_outcome: cancelOutcome,
      request_started_at: requestStartedAt,
      // Did any of the request reach the provider? (connect failures: no.)
      request_sent: typeof call?.sent === 'function' ? call.sent() === true : Boolean(call)
    };
    if (cancelOutcome === 'unconfirmed') {
      log.warn('cancelled AI request socket did not confirm close', { ...telemetry, code: err.code });
    }
    log.warn('AI request failed', {
      ...telemetry,
      code: err.code || null,
      http_status: err.http_status ?? null,
      slot_wait_ms: slotWaitMs,
      headers_ms: err.timing.headers_ms,
      total_ms: err.timing.total_ms,
      cancel_outcome: cancelOutcome
    });
    throw err;
  } finally {
    if (hooks.signal) hooks.signal.removeEventListener?.('abort', onOuterAbort);
    offLeaseLost?.();
  }
}
