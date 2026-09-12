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
  AI_OUTPUT_REFERENCE_ERROR: 'ai_output_reference_error'
});

export const AI_FAILURE_MESSAGES = Object.freeze({
  [AI_FAILURE_CODES.PROVIDER_UNREACHABLE]: 'AI provider is unreachable from the TalonHound host',
  [AI_FAILURE_CODES.CONNECTION_TIMEOUT]: 'Timed out establishing a connection to the AI provider',
  [AI_FAILURE_CODES.FIRST_TOKEN_TIMEOUT]: 'AI provider did not start responding within the first-response timeout (model may still be loading)',
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
  [AI_FAILURE_CODES.AI_OUTPUT_REFERENCE_ERROR]: 'AI response referenced unknown or forbidden identifiers'
});

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

  const defaults = local
    ? {
        connection_timeout_ms: 30_000,
        first_token_timeout_ms: 300_000,
        inactivity_timeout_ms: 300_000,
        total_analysis_timeout_ms: 1_800_000
      }
    : {
        connection_timeout_ms: 15_000,
        first_token_timeout_ms: 120_000,
        inactivity_timeout_ms: 180_000,
        total_analysis_timeout_ms: 900_000
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
    is_local: local
  };
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
