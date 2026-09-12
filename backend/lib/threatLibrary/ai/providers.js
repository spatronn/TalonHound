/**
 * AI provider abstraction for Threat Library.
 * Supports OpenAI, Anthropic, Ollama, and generic OpenAI-compatible endpoints.
 * Never logs API keys.
 */

import { AI_PROVIDERS } from '../constants.js';
import { buildSystemPrompt, buildUserPrompt } from './prompts.js';
import { validateAiAnalysis } from './schema.js';
import { chunkCanonicalDocument, flattenCanonicalText, collectBlockIds } from '../canonicalDocument.js';

/**
 * @param {object} settings row from threat_library_ai_settings
 */
export function maskAiSettingsForClient(settings) {
  if (!settings) {
    return {
      enabled: false,
      provider: 'openai_compatible',
      base_url: null,
      model: null,
      timeout_ms: 60000,
      max_input_chars: 120000,
      api_key_configured: false,
      masked_key: null,
      privacy_ack_at: null
    };
  }
  const key = String(settings.api_key || '');
  return {
    enabled: settings.enabled === true,
    provider: settings.provider,
    base_url: settings.base_url || null,
    model: settings.model || null,
    timeout_ms: settings.timeout_ms || 60000,
    max_input_chars: settings.max_input_chars || 120000,
    api_key_configured: key.length > 0,
    masked_key: key ? maskKey(key) : null,
    privacy_ack_at: settings.privacy_ack_at || null
  };
}

function maskKey(k) {
  const s = String(k);
  if (s.length <= 8) return '••••••••';
  return `${s.slice(0, 3)}••••${s.slice(-4)}`;
}

/**
 * @param {object} settings
 */
export function assertAiReady(settings) {
  if (!settings || settings.enabled !== true) {
    const err = new Error('AI analysis is not enabled. Configure an AI provider in Threat Library settings.');
    err.code = 'ai_not_configured';
    throw err;
  }
  if (!AI_PROVIDERS.includes(settings.provider)) {
    const err = new Error(`Unsupported AI provider: ${settings.provider}`);
    err.code = 'ai_bad_provider';
    throw err;
  }
  if (!settings.model) {
    const err = new Error('AI model is not configured');
    err.code = 'ai_no_model';
    throw err;
  }
  const needsKey = settings.provider === 'openai' || settings.provider === 'anthropic' || settings.provider === 'openai_compatible';
  if (needsKey && !String(settings.api_key || '').trim() && settings.provider !== 'ollama') {
    // openai_compatible local may omit key; allow empty for ollama-like
    if (settings.provider !== 'openai_compatible') {
      const err = new Error('AI API key is not configured');
      err.code = 'ai_no_key';
      throw err;
    }
  }
  if ((settings.provider === 'ollama' || settings.provider === 'openai_compatible') && !settings.base_url) {
    if (settings.provider === 'ollama') {
      // default local
    } else {
      const err = new Error('Base URL is required for OpenAI-compatible providers');
      err.code = 'ai_no_base_url';
      throw err;
    }
  }
}

function resolveEndpoint(settings) {
  const provider = settings.provider;
  if (provider === 'openai') {
    return {
      url: `${(settings.base_url || 'https://api.openai.com/v1').replace(/\/$/, '')}/chat/completions`,
      kind: 'openai'
    };
  }
  if (provider === 'anthropic') {
    return {
      url: `${(settings.base_url || 'https://api.anthropic.com').replace(/\/$/, '')}/v1/messages`,
      kind: 'anthropic'
    };
  }
  if (provider === 'ollama') {
    const base = (settings.base_url || 'http://127.0.0.1:11434').replace(/\/$/, '');
    return { url: `${base}/v1/chat/completions`, kind: 'openai' };
  }
  // openai_compatible
  const base = String(settings.base_url || '').replace(/\/$/, '');
  return { url: `${base}/chat/completions`, kind: 'openai' };
}

/**
 * @param {object} settings
 * @param {{ system: string, user: string }} messages
 */
export async function callAiProvider(settings, messages) {
  assertAiReady(settings);
  const endpoint = resolveEndpoint(settings);
  const timeoutMs = Math.max(Number(settings.timeout_ms || 60000), 1000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    if (endpoint.kind === 'anthropic') {
      const res = await fetch(endpoint.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': String(settings.api_key || ''),
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: settings.model,
          max_tokens: 8192,
          system: messages.system,
          messages: [{ role: 'user', content: messages.user }]
        }),
        signal: controller.signal
      });
      if (!res.ok) {
        const err = new Error(`AI provider error (${res.status})`);
        err.code = 'ai_provider_error';
        err.status = res.status;
        throw err;
      }
      const data = await res.json();
      const text = (data.content || []).map((c) => c.text || '').join('\n');
      return { text, raw: data };
    }

    const headers = { 'content-type': 'application/json' };
    if (settings.api_key) headers.authorization = `Bearer ${settings.api_key}`;

    const res = await fetch(endpoint.url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: settings.model,
        temperature: 0.1,
        response_format: { type: 'json_object' },
        messages: [
          { role: 'system', content: messages.system },
          { role: 'user', content: messages.user }
        ]
      }),
      signal: controller.signal
    });
    if (!res.ok) {
      const err = new Error(`AI provider error (${res.status})`);
      err.code = 'ai_provider_error';
      err.status = res.status;
      throw err;
    }
    const data = await res.json();
    const text = data.choices?.[0]?.message?.content || '';
    return { text, raw: data };
  } catch (err) {
    if (err?.name === 'AbortError') {
      const e = new Error('AI provider request timed out');
      e.code = 'ai_timeout';
      throw e;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function extractJsonObject(text) {
  const raw = String(text || '').trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    const start = raw.indexOf('{');
    const end = raw.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try {
        return JSON.parse(raw.slice(start, end + 1));
      } catch {
        return null;
      }
    }
    return null;
  }
}

/**
 * Run semantic analysis against canonical document + deterministic candidates.
 * @param {object} settings
 * @param {{ document: object, candidates: object[] }} input
 */
export async function analyzeThreatDocument(settings, input) {
  assertAiReady(settings);
  const maxChars = Number(settings.max_input_chars || 120000);
  const chunks = chunkCanonicalDocument(input.document, {
    maxCharsPerChunk: Math.min(12000, Math.floor(maxChars / 2)),
    maxChunks: 6
  });
  // Prefer first N chunks joined under budget (avoid re-sending same content)
  const limitedDoc = {
    ...input.document,
    blocks: chunks.flat().slice(0, 400)
  };
  const blocksText = flattenCanonicalText(limitedDoc, { maxChars });
  const knownBlockIds = collectBlockIds(input.document);
  const knownCandidateKeys = new Set(
    (input.candidates || []).map((c) => `${c.candidate_type}\0${c.normalized_value}`)
  );

  const system = buildSystemPrompt();
  const user = buildUserPrompt({
    documentTitle: input.document.title,
    language: input.document.language,
    blocksText,
    candidates: input.candidates || []
  });

  const { text } = await callAiProvider(settings, { system, user });
  const json = extractJsonObject(text);
  if (!json) {
    return { ok: false, error: 'AI returned malformed JSON', rawTextPreview: String(text).slice(0, 200) };
  }
  return validateAiAnalysis(json, { knownBlockIds, knownCandidateKeys });
}
