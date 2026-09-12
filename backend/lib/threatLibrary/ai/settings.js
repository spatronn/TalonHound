/**
 * Threat Library AI settings helpers (client-safe masking + readiness).
 */

import { AI_PROVIDERS } from '../constants.js';
import { AI_FAILURE_CODES, aiFailure, resolveAiTimeoutPolicy, defaultTimeoutsForProvider } from './timeouts.js';

function maskKey(k) {
  const s = String(k);
  if (s.length <= 8) return '••••••••';
  return `${s.slice(0, 3)}••••${s.slice(-4)}`;
}

/**
 * @param {object} settings row from threat_library_ai_settings
 */
export function maskAiSettingsForClient(settings) {
  if (!settings) {
    const defaults = defaultTimeoutsForProvider('openai_compatible');
    return {
      enabled: false,
      provider: 'openai_compatible',
      base_url: null,
      model: null,
      timeout_ms: defaults.inactivity_timeout_ms,
      connection_timeout_ms: defaults.connection_timeout_ms,
      first_token_timeout_ms: defaults.first_token_timeout_ms,
      inactivity_timeout_ms: defaults.inactivity_timeout_ms,
      total_analysis_timeout_ms: defaults.total_analysis_timeout_ms,
      max_input_chars: 120000,
      api_key_configured: false,
      masked_key: null,
      privacy_ack_at: null,
      timeout_policy: defaults
    };
  }
  const key = String(settings.api_key || '');
  const policy = resolveAiTimeoutPolicy(settings);
  return {
    enabled: settings.enabled === true,
    provider: settings.provider,
    base_url: settings.base_url || null,
    model: settings.model || null,
    // legacy field retained for older clients; maps to inactivity
    timeout_ms: policy.inactivity_timeout_ms,
    connection_timeout_ms: policy.connection_timeout_ms,
    first_token_timeout_ms: policy.first_token_timeout_ms,
    inactivity_timeout_ms: policy.inactivity_timeout_ms,
    total_analysis_timeout_ms: policy.total_analysis_timeout_ms,
    max_input_chars: settings.max_input_chars || 120000,
    api_key_configured: key.length > 0,
    masked_key: key ? maskKey(key) : null,
    privacy_ack_at: settings.privacy_ack_at || null,
    timeout_policy: policy
  };
}

/**
 * @param {object} settings
 */
export function assertAiReady(settings) {
  if (!settings || settings.enabled !== true) {
    throw aiFailure(AI_FAILURE_CODES.AI_NOT_CONFIGURED);
  }
  if (!AI_PROVIDERS.includes(settings.provider)) {
    throw aiFailure(AI_FAILURE_CODES.AI_NOT_CONFIGURED, `Unsupported AI provider: ${settings.provider}`);
  }
  if (!settings.model) {
    throw aiFailure(AI_FAILURE_CODES.AI_NOT_CONFIGURED, 'AI model is not configured');
  }
  if (settings.provider === 'openai' || settings.provider === 'anthropic') {
    if (!String(settings.api_key || '').trim()) {
      throw aiFailure(AI_FAILURE_CODES.AI_NOT_CONFIGURED, 'AI API key is not configured');
    }
  }
  if (settings.provider === 'openai_compatible' && !settings.base_url) {
    throw aiFailure(AI_FAILURE_CODES.AI_NOT_CONFIGURED, 'Base URL is required for OpenAI-compatible providers');
  }
}
