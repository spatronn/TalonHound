/**
 * Streaming AI HTTP client with connection / first-token / inactivity watches.
 * Ollama uses native /api/chat streaming + keep_alive (server-side only).
 */

import {
  AI_FAILURE_CODES,
  aiFailure,
  classifyProviderHttpError,
  resolveAiTimeoutPolicy
} from './timeouts.js';
import { assertAiReady } from './settings.js';

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
async function waitForHeaders(fetchPromise, connectionTimeoutMs, signal) {
  let timer;
  try {
    return await Promise.race([
      fetchPromise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(aiFailure(AI_FAILURE_CODES.CONNECTION_TIMEOUT));
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
  let buffer = '';
  let text = '';
  let gotFirst = false;
  let lastActivity = Date.now();
  const started = Date.now();
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
      throw aiFailure(AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE);
    }
    if (!gotFirst && now - started > opts.firstTokenTimeoutMs) {
      throw aiFailure(AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT);
    }
    if (gotFirst && now - lastActivity > opts.inactivityTimeoutMs) {
      throw aiFailure(AI_FAILURE_CODES.PROVIDER_INACTIVITY_TIMEOUT);
    }
  };

  // Poll watchdogs while waiting on read()
  const readWithWatchdog = async () => {
    while (true) {
      checkWatchdogs();
      const race = await Promise.race([
        reader.read().then((r) => ({ type: 'read', r })),
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
        opts.onActivity?.({ bytes: value.byteLength, firstToken: true });
      } else {
        opts.onActivity?.({ bytes: value.byteLength, firstToken: false });
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
          const acc = { text };
          opts.parseLine(trimmed, acc);
          text = acc.text;
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
        const acc = { text };
        opts.parseLine(buffer.trim(), acc);
        text = acc.text;
      } else {
        text += buffer;
      }
    }
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
    }
  } catch {
    /* ignore */
  }
}

function parseOllamaNdjsonLine(line, acc) {
  if (!line || line[0] !== '{') return;
  try {
    const json = JSON.parse(line);
    const piece = json.message?.content || json.response || '';
    if (piece) acc.text += piece;
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
 * @param {object} settings
 * @param {{ system: string, user: string }} messages
 * @param {{
 *   onActivity?: Function,
 *   signal?: AbortSignal,
 *   analysisStartedAt?: number,
 *   keepAlive?: string
 * }} [hooks]
 */
export async function callAiProvider(settings, messages, hooks = {}) {
  assertAiReady(settings);
  const policy = resolveAiTimeoutPolicy(settings);
  const endpoint = resolveProviderEndpoint(settings);
  const analysisStartedAt = hooks.analysisStartedAt || Date.now();
  const totalDeadlineAt = analysisStartedAt + policy.total_analysis_timeout_ms;
  const controller = new AbortController();
  const onOuterAbort = () => controller.abort(hooks.signal.reason || aiFailure(AI_FAILURE_CODES.JOB_CANCELLED));
  if (hooks.signal) {
    if (hooks.signal.aborted) onOuterAbort();
    else hooks.signal.addEventListener('abort', onOuterAbort, { once: true });
  }

  const remainingTotal = Math.max(totalDeadlineAt - Date.now(), 1000);
  if (remainingTotal <= 1000) {
    throw aiFailure(AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE);
  }

  try {
    let fetchPromise;
    if (endpoint.kind === 'ollama_stream') {
      fetchPromise = fetch(endpoint.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model: settings.model,
          stream: true,
          format: 'json',
          keep_alive: hooks.keepAlive || '15m',
          options: { temperature: 0.1 },
          messages: [
            { role: 'system', content: messages.system },
            { role: 'user', content: messages.user }
          ]
        }),
        signal: controller.signal
      });
    } else if (endpoint.kind === 'anthropic_stream') {
      fetchPromise = fetch(endpoint.url, {
        method: 'POST',
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
        }),
        signal: controller.signal
      });
    } else {
      const headers = { 'content-type': 'application/json' };
      if (settings.api_key) headers.authorization = `Bearer ${settings.api_key}`;
      fetchPromise = fetch(endpoint.url, {
        method: 'POST',
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
        }),
        signal: controller.signal
      });
    }

    let res;
    try {
      res = await waitForHeaders(fetchPromise, policy.connection_timeout_ms, controller.signal);
    } catch (err) {
      if (err?.code) throw err;
      if (err?.name === 'AbortError') throw aiFailure(AI_FAILURE_CODES.CONNECTION_TIMEOUT);
      const msg = String(err?.message || err);
      if (/ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|fetch failed|network/i.test(msg)) {
        throw aiFailure(AI_FAILURE_CODES.PROVIDER_UNREACHABLE, msg);
      }
      throw aiFailure(AI_FAILURE_CODES.PROVIDER_UNREACHABLE, msg);
    }

    if (!res.ok) {
      let bodyText = '';
      try {
        bodyText = await res.text();
      } catch {
        bodyText = '';
      }
      const code = classifyProviderHttpError(res.status, bodyText);
      throw aiFailure(code, `AI provider error (${res.status})`);
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
      signal: controller.signal,
      onActivity: hooks.onActivity,
      parseLine
    });

    return { text, policy };
  } catch (err) {
    if (err?.code) throw err;
    if (err?.name === 'AbortError') {
      throw aiFailure(AI_FAILURE_CODES.JOB_CANCELLED);
    }
    throw err;
  } finally {
    if (hooks.signal) hooks.signal.removeEventListener?.('abort', onOuterAbort);
  }
}
