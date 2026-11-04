/**
 * What model answered, and under which prompts and settings. Read once per run and
 * stored with the extraction ledger, so a later result can be traced to its model.
 */

import { createHash } from 'node:crypto';
import { AI_TEMPERATURE, resolveProviderEndpoint } from './client.js';
import { buildChunkPrompt, buildRepairPrompt, buildSynthesisPrompt, buildSystemPrompt } from './prompts.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './contract.js';

const IDENTITY_TIMEOUT_MS = 4000;

/**
 * Hash of the prompts themselves: the system text and the prompt templates.
 * @returns {string}
 */
export function promptFingerprint() {
  const h = createHash('sha256');
  h.update(buildSystemPrompt());
  for (const fn of [buildChunkPrompt, buildRepairPrompt, buildSynthesisPrompt]) h.update(fn.toString());
  return h.digest('hex');
}

function contextLengthOf(modelInfo) {
  for (const [key, value] of Object.entries(modelInfo || {})) {
    if (key.endsWith('.context_length') && Number.isFinite(Number(value))) return Number(value);
  }
  return null;
}

/**
 * Model digest and context length, best effort: a provider that cannot say leaves
 * them null, and analysis never waits on this for more than a few seconds.
 * @param {object} settings
 * @param {{ fetchImpl?: typeof fetch, timeoutMs?: number }} [deps]
 */
export async function fetchModelIdentity(settings, deps = {}) {
  const endpoint = resolveProviderEndpoint(settings);
  if (endpoint.kind !== 'ollama_stream') {
    return { digest: null, digest_status: 'not_available_for_provider', context_length: null };
  }
  const fetchImpl = deps.fetchImpl || fetch;
  const timeoutMs = deps.timeoutMs ?? IDENTITY_TIMEOUT_MS;
  const signal = () => AbortSignal.timeout(timeoutMs);
  try {
    const [tagsRes, showRes] = await Promise.all([
      fetchImpl(`${endpoint.base}/api/tags`, { signal: signal() }),
      fetchImpl(`${endpoint.base}/api/show`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: settings.model }), signal: signal() })
    ]);
    const tags = tagsRes.ok ? await tagsRes.json() : null;
    const show = showRes.ok ? await showRes.json() : null;
    const entry = (tags?.models || []).find((m) => m.name === settings.model || m.model === settings.model);
    return {
      digest: entry?.digest || null,
      digest_status: entry?.digest ? 'reported' : 'not_reported',
      context_length: contextLengthOf(show?.model_info),
      quantization: show?.details?.quantization_level || null,
      parameter_size: show?.details?.parameter_size || null
    };
  } catch (err) {
    return { digest: null, digest_status: 'unreachable', context_length: null, error: String(err?.message || err).slice(0, 120) };
  }
}

/**
 * The ledger's record of one run's inference setup and result coverage.
 * @param {{ settings: object, identity?: object|null, meta?: object|null, degraded?: object|null }} input
 */
export function buildAiProvenance({ settings, identity = null, meta = null, degraded = null }) {
  const timing = Array.isArray(meta?.timing) ? meta.timing : [];
  const promptEval = timing.map((t) => Number(t.prompt_eval_count)).filter((n) => Number.isFinite(n) && n > 0);
  return {
    ai_invoked: true,
    provider: settings?.provider || null,
    model: settings?.model || null,
    model_digest: identity?.digest || null,
    model_digest_status: identity?.digest_status || 'not_read',
    schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
    prompt_hash: promptFingerprint(),
    inference: {
      temperature: AI_TEMPERATURE,
      // Not sent with requests, so the provider default applies.
      num_ctx: null,
      num_ctx_source: 'provider_default',
      context_length: identity?.context_length ?? null,
      max_input_chars: settings?.max_input_chars ?? null,
      max_prompt_eval_count: promptEval.length ? Math.max(...promptEval) : null
    },
    ai_calls: meta?.ai_calls ?? null,
    chunks_total: meta?.chunks_total ?? null,
    chunks_completed: meta?.chunks_completed ?? null,
    chunks_skipped_structured: meta?.chunks_skipped_structured ?? 0,
    chunk_failures: meta?.chunk_failures || [],
    targeted_retries: meta?.targeted_retries ?? 0,
    coverage: meta?.coverage || null,
    degraded: degraded || null
  };
}
