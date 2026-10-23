/**
 * Separate AI timeout concepts for Threat Library.
 * Do not collapse everything into a single wall-clock AbortController.
 */

export const AI_FAILURE_CODES = Object.freeze({
  PROVIDER_UNREACHABLE: 'provider_unreachable',
  CONNECTION_TIMEOUT: 'connection_timeout',
  FIRST_TOKEN_TIMEOUT: 'first_token_timeout',
  PROVIDER_INACTIVITY_TIMEOUT: 'provider_inactivity_timeout',
  TOTAL_ANALYSIS_DEADLINE: 'total_analysis_deadline_exceeded',
  PROVIDER_HTTP_ERROR: 'provider_http_error',
  INVALID_AI_RESPONSE: 'invalid_ai_response',
  MODEL_NOT_FOUND: 'model_not_found',
  CONTEXT_TOO_LARGE: 'context_too_large',
  JOB_CANCELLED: 'job_cancelled',
  AI_NOT_CONFIGURED: 'ai_not_configured',
  AI_VALIDATION: 'ai_validation',
  AI_OUTPUT_PARSE_ERROR: 'ai_output_parse_error',
  AI_OUTPUT_SCHEMA_ERROR: 'ai_output_schema_error',
  AI_OUTPUT_REFERENCE_ERROR: 'ai_output_reference_error',
  AI_GENERATION_LIMIT: 'ai_generation_limit_exceeded',
  AI_OUTPUT_BUDGET_EXCEEDED: 'ai_output_budget_exceeded',
  // Inference scheduling (inferenceScheduler.js): waiting for TalonHound-managed
  // capacity is never reported as a provider timeout.
  AI_CAPACITY_WAIT_TIMEOUT: 'ai_capacity_wait_timeout',
  AI_CAPACITY_UNAVAILABLE: 'ai_capacity_unavailable',
  AI_CAPACITY_LEASE_LOST: 'ai_capacity_lease_lost',
  PROVIDER_EXECUTION_TIMEOUT: 'provider_execution_timeout',
  // Job ownership (jobOwnership.js): the run stops without writing report state.
  JOB_OWNERSHIP_LOST: 'job_ownership_lost',
  WORKER_SHUTDOWN: 'worker_shutdown'
});

export const AI_FAILURE_MESSAGES = Object.freeze({
  [AI_FAILURE_CODES.PROVIDER_UNREACHABLE]: 'AI provider is unreachable from the TalonHound host',
  [AI_FAILURE_CODES.CONNECTION_TIMEOUT]: 'Timed out establishing a connection to the AI provider',
  [AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT]: 'AI provider did not start responding within the first-response timeout after the request was sent',
  [AI_FAILURE_CODES.PROVIDER_INACTIVITY_TIMEOUT]: 'AI provider stopped producing output (inactivity timeout)',
  [AI_FAILURE_CODES.TOTAL_ANALYSIS_DEADLINE]: 'Total analysis safety ceiling exceeded',
  [AI_FAILURE_CODES.PROVIDER_HTTP_ERROR]: 'AI provider returned an HTTP error',
  [AI_FAILURE_CODES.INVALID_AI_RESPONSE]: 'AI provider returned an invalid or incomplete response',
  [AI_FAILURE_CODES.MODEL_NOT_FOUND]: 'Configured AI model was not found on the provider',
  [AI_FAILURE_CODES.CONTEXT_TOO_LARGE]: 'Report context exceeded the provider/model limit',
  [AI_FAILURE_CODES.JOB_CANCELLED]: 'Analysis was cancelled',
  [AI_FAILURE_CODES.AI_NOT_CONFIGURED]: 'AI analysis is not configured or enabled',
  [AI_FAILURE_CODES.AI_VALIDATION]: 'AI response failed schema validation',
  [AI_FAILURE_CODES.AI_OUTPUT_PARSE_ERROR]: 'Could not parse AI response as JSON',
  [AI_FAILURE_CODES.AI_OUTPUT_SCHEMA_ERROR]: 'AI returned JSON that does not match the required schema',
  [AI_FAILURE_CODES.AI_OUTPUT_REFERENCE_ERROR]: 'AI response referenced unknown or forbidden identifiers',
  [AI_FAILURE_CODES.AI_GENERATION_LIMIT]: 'AI output reached the generation token ceiling before the JSON was complete',
  [AI_FAILURE_CODES.AI_OUTPUT_BUDGET_EXCEEDED]: 'AI output exceeded the per-chunk entity/relationship budget',
  [AI_FAILURE_CODES.AI_CAPACITY_WAIT_TIMEOUT]: 'Waited too long for AI capacity (other analyses were using the AI provider)',
  [AI_FAILURE_CODES.AI_CAPACITY_UNAVAILABLE]: 'AI capacity scheduler is unavailable',
  [AI_FAILURE_CODES.AI_CAPACITY_LEASE_LOST]: 'AI capacity lease was lost while the request was running',
  [AI_FAILURE_CODES.PROVIDER_EXECUTION_TIMEOUT]: 'AI provider request exceeded the per-request execution limit',
  [AI_FAILURE_CODES.JOB_OWNERSHIP_LOST]: 'Analysis ownership moved to another worker',
  [AI_FAILURE_CODES.WORKER_SHUTDOWN]: 'Analysis was interrupted by a worker shutdown and will resume'
});

/**
 * Failures worth one bounded automatic retry: the provider or the transport
 * was temporarily unavailable. Validation, schema, budget, deadline, model and
 * context errors are permanent for the same input and are never retried.
 * Capacity-wait timeouts are not retried either: they mean sustained
 * congestion, and re-queueing would only add load.
 * @param {string|null|undefined} code
 * @param {number|null|undefined} [httpStatus]
 */
export function isTransientAiFailure(code, httpStatus) {
  switch (code) {
    case AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT:
    case AI_FAILURE_CODES.PROVIDER_INACTIVITY_TIMEOUT:
    case AI_FAILURE_CODES.CONNECTION_TIMEOUT:
    case AI_FAILURE_CODES.PROVIDER_UNREACHABLE:
    case AI_FAILURE_CODES.AI_CAPACITY_UNAVAILABLE:
    case AI_FAILURE_CODES.AI_CAPACITY_LEASE_LOST:
      return true;
    case AI_FAILURE_CODES.PROVIDER_HTTP_ERROR:
      return Number(httpStatus) >= 500 || Number(httpStatus) === 429;
    default:
      return false;
  }
}

/**
 * Inference capacity is a property of the provider endpoint, not of the
 * model: a second model on the same Ollama host shares its GPU and queue.
 * @param {object} settings
 */
export function inferenceResourceKey(settings) {
  const provider = String(settings?.provider || 'unknown');
  let base = String(settings?.base_url || '').trim().toLowerCase().replace(/\/+$/, '');
  if (!base) {
    base = provider === 'ollama'
      ? 'http://127.0.0.1:11434'
      : provider === 'anthropic'
        ? 'https://api.anthropic.com'
        : provider === 'openai'
          ? 'https://api.openai.com/v1'
          : '';
  }
  return `${provider}|${base}`;
}

/**
 * @param {string|null|undefined} baseUrl
 */
export function isLikelyLocalAiBaseUrl(baseUrl) {
  const raw = String(baseUrl || '').trim().toLowerCase();
  if (!raw) return false;
  try {
    const u = new URL(raw);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0') return true;
    if (/^10\.\d+\.\d+\.\d+$/.test(host)) return true;
    if (/^192\.168\.\d+\.\d+$/.test(host)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$/.test(host)) return true;
    if (host.endsWith('.local') || host.endsWith('.lan') || host.endsWith('.internal')) return true;
    return false;
  } catch {
    return false;
  }
}

/**
 * @param {object} settings
 */
export function isLocalAiProvider(settings) {
  if (!settings) return false;
  if (settings.provider === 'ollama') return true;
  return isLikelyLocalAiBaseUrl(settings.base_url);
}

function clamp(n, min, max, fallback) {
  const v = Number(n);
  if (!Number.isFinite(v)) return fallback;
  return Math.min(max, Math.max(min, v));
}

/**
 * Resolve effective timeout policy.
 * Legacy `timeout_ms` seeds inactivity when newer columns are unset.
 * @param {object} settings
 */
export function resolveAiTimeoutPolicy(settings) {
  const local = isLocalAiProvider(settings);
  const legacy = Number(settings?.timeout_ms);

  // Local default capacity 1: the production Ollama host was measured to run
  // one request at a time (provider queue = the other request's runtime).
  // Execution limit: num_predict 10240 at ~17 tok/s plus the longest observed
  // prompt evaluation (~164s) is ~13 min; 20 min leaves headroom.
  const defaults = local
    ? {
        connection_timeout_ms: 30_000,
        first_token_timeout_ms: 300_000,
        inactivity_timeout_ms: 300_000,
        total_analysis_timeout_ms: 1_800_000,
        max_concurrent_ai_requests: 1,
        capacity_wait_timeout_ms: 3_600_000,
        provider_execution_timeout_ms: 1_200_000
      }
    : {
        connection_timeout_ms: 15_000,
        first_token_timeout_ms: 120_000,
        inactivity_timeout_ms: 180_000,
        total_analysis_timeout_ms: 900_000,
        max_concurrent_ai_requests: 4,
        capacity_wait_timeout_ms: 900_000,
        provider_execution_timeout_ms: 600_000
      };

  const inactivityFallback = Number.isFinite(legacy) && legacy > 0
    ? Math.max(legacy, defaults.inactivity_timeout_ms)
    : defaults.inactivity_timeout_ms;

  const firstTokenFallback = Number.isFinite(legacy) && legacy > 0
    ? Math.max(legacy, defaults.first_token_timeout_ms)
    : defaults.first_token_timeout_ms;

  return {
    connection_timeout_ms: clamp(
      settings?.connection_timeout_ms,
      1000,
      120_000,
      defaults.connection_timeout_ms
    ),
    first_token_timeout_ms: clamp(
      settings?.first_token_timeout_ms,
      5000,
      1_800_000,
      firstTokenFallback
    ),
    inactivity_timeout_ms: clamp(
      settings?.inactivity_timeout_ms,
      5000,
      1_800_000,
      inactivityFallback
    ),
    total_analysis_timeout_ms: clamp(
      settings?.total_analysis_timeout_ms,
      60_000,
      7_200_000,
      defaults.total_analysis_timeout_ms
    ),
    max_concurrent_ai_requests: Math.trunc(clamp(
      settings?.max_concurrent_ai_requests,
      1,
      8,
      defaults.max_concurrent_ai_requests
    )),
    capacity_wait_timeout_ms: clamp(
      settings?.capacity_wait_timeout_ms,
      10_000,
      14_400_000,
      defaults.capacity_wait_timeout_ms
    ),
    provider_execution_timeout_ms: clamp(
      settings?.provider_execution_timeout_ms,
      30_000,
      7_200_000,
      defaults.provider_execution_timeout_ms
    ),
    auto_retry_max_attempts: Math.trunc(clamp(settings?.auto_retry_max_attempts, 0, 5, 2)),
    is_local: local
  };
}

/**
 * Wall-clock reserved for one bounded repair after a primary provider call.
 * Production 30-minute ceiling → 180s (warm repair of a schema-capped payload).
 * Never more than 15% of the total ceiling so short test/policy budgets still run.
 * @param {ReturnType<typeof resolveAiTimeoutPolicy>} policy
 */
export function resolveRecoveryReserveMs(policy) {
  const total = Number(policy?.total_analysis_timeout_ms) || 1_800_000;
  return Math.min(180_000, Math.max(10_000, Math.floor(total * 0.15)));
}

/**
 * Do not start a primary chunk unless at least this much remains after the reserve.
 * Production → 120s, which is below the 249s healthy-chunk observation so a
 * later chunk still starts; short budgets scale to 10% of the ceiling.
 * @param {ReturnType<typeof resolveAiTimeoutPolicy>} policy
 */
export function resolveMinPrimaryCallMs(policy) {
  const total = Number(policy?.total_analysis_timeout_ms) || 1_800_000;
  return Math.min(120_000, Math.max(5_000, Math.floor(total * 0.1)));
}

/**
 * Minimum remaining global budget required to start a repair call.
 * Production keeps the historical 60s floor; short budgets use the reserve.
 * @param {ReturnType<typeof resolveAiTimeoutPolicy>} policy
 */
export function resolveMinRepairMs(policy) {
  return Math.min(60_000, resolveRecoveryReserveMs(policy));
}

/**
 * How long to wait for HTTP response headers from the provider.
 * Local Ollama often withholds headers until prompt processing / model load
 * completes — that latency belongs to first-token budget, not TCP connect.
 * @param {ReturnType<typeof resolveAiTimeoutPolicy>} policy
 */
export function resolveHeaderWaitMs(policy) {
  if (policy?.is_local) {
    return Math.max(
      Number(policy.connection_timeout_ms) || 0,
      Number(policy.first_token_timeout_ms) || 0
    );
  }
  return Number(policy.connection_timeout_ms) || 15_000;
}

/**
 * Provider defaults suggested in Settings UI when switching provider.
 * @param {string} provider
 */
export function defaultTimeoutsForProvider(provider) {
  return resolveAiTimeoutPolicy({ provider, base_url: provider === 'ollama' ? 'http://127.0.0.1:11434' : null });
}

/**
 * @param {string} code
 * @param {string} [detail]
 */
export function aiFailure(code, detail) {
  const err = new Error(detail || AI_FAILURE_MESSAGES[code] || code);
  err.code = code;
  return err;
}

/**
 * Map provider HTTP status / message into a stable failure code.
 * @param {number} status
 * @param {string} [bodyText]
 */
export function classifyProviderHttpError(status, bodyText = '') {
  const body = String(bodyText || '').toLowerCase();
  if (status === 404 || body.includes('model') && body.includes('not found')) {
    return AI_FAILURE_CODES.MODEL_NOT_FOUND;
  }
  if (status === 413 || body.includes('context length') || body.includes('too large') || body.includes('maximum context')) {
    return AI_FAILURE_CODES.CONTEXT_TOO_LARGE;
  }
  return AI_FAILURE_CODES.PROVIDER_HTTP_ERROR;
}

const PROVIDER_ERROR_MESSAGE_MAX = 400;

function stripSecrets(text) {
  return String(text || '')
    .replace(/bearer\s+[a-z0-9._-]+/gi, 'bearer [redacted]')
    .replace(/authorization:\s*[^\n]*/gi, 'authorization: [redacted]')
    .replace(/api[_-]?key["']?\s*[:=]\s*["']?[^\s"',}]+/gi, 'api_key=[redacted]');
}

/**
 * Bounded, sanitized provider HTTP error for persistence / progress.
 * Unwraps Ollama's `{ error: "<json string>" }` envelope. Never keeps
 * authorization headers, API keys, or an unbounded body.
 * @param {number} status
 * @param {string} [bodyText]
 */
export function sanitizeProviderHttpError(status, bodyText = '') {
  const raw = stripSecrets(String(bodyText || '')).slice(0, 2000);
  let node = raw;
  for (let i = 0; i < 4; i += 1) {
    if (typeof node === 'string') {
      try {
        node = JSON.parse(node);
      } catch {
        break;
      }
      continue;
    }
    if (node && typeof node === 'object' && typeof node.error === 'string') {
      node = node.error;
      continue;
    }
    break;
  }
  const inner =
    node && typeof node === 'object'
      ? (node.error && typeof node.error === 'object' ? node.error : node)
      : null;
  const message = stripSecrets(
    inner && typeof inner === 'object'
      ? inner.message || inner.error || ''
      : typeof node === 'string'
        ? node
        : raw
  ).replace(/\s+/g, ' ').trim();
  return {
    http_status: Number(status) || 0,
    code: inner && inner.code != null ? String(inner.code).slice(0, 64) : null,
    type: inner && inner.type != null ? String(inner.type).slice(0, 64) : null,
    message: (message || 'provider http error').slice(0, PROVIDER_ERROR_MESSAGE_MAX)
  };
}
