/**
 * Threat Library shared constants and confidence policy.
 */

export const THREAT_LIBRARY_QUEUE_NAME =
  process.env.THREAT_LIBRARY_QUEUE_NAME || 'threat-library';

export const SOURCE_TYPES = Object.freeze(['url', 'pdf', 'thib']);

export const TLP_VALUES = Object.freeze(['clear', 'green', 'amber', 'amber_strict', 'red']);

export const TLP_DISPLAY = Object.freeze({
  clear: 'TLP:CLEAR',
  green: 'TLP:GREEN',
  amber: 'TLP:AMBER',
  amber_strict: 'TLP:AMBER+STRICT',
  red: 'TLP:RED'
});

export const ASSESSMENTS = Object.freeze([
  'malicious',
  'suspicious',
  'context_only',
  'unknown',
  'invalid'
]);

export const CANDIDATE_ROLES = Object.freeze([
  'command_and_control',
  'redirector',
  'payload_hosting',
  'malware_download',
  'phishing',
  'tracking',
  'malicious_infrastructure',
  'delivery',
  'legitimate_service',
  'hosting_platform',
  'victim',
  'reference',
  'security_tool',
  'unknown'
]);

export const ENTITY_TYPES = Object.freeze([
  'threat_actor',
  'malware',
  'campaign',
  'tool',
  'vulnerability',
  'infrastructure',
  'organization',
  'attack_pattern'
]);

export const ANALYSIS_STAGES = Object.freeze([
  'fetching',
  'extracting',
  'candidates',
  'analyzing',
  'matching',
  'review_required',
  'ready',
  'failed'
]);

/** Central confidence / review policy (documented for operators). */
export const CONFIDENCE_POLICY = Object.freeze({
  /** AI confidence >= this and assessment malicious/suspicious → high_confidence bucket */
  HIGH: 0.85,
  /** Below this with unknown assessment → needs_review */
  REVIEW_FLOOR: 0.4,
  /** Auto-suggest "approve all high-confidence malicious" threshold */
  AUTO_APPROVE_SUGGEST: 0.9
});

export const URL_FETCH_MAX_BYTES = Math.max(
  Number(process.env.THREAT_LIBRARY_URL_MAX_BYTES || 8_388_608),
  1024
);

export const PDF_MAX_BYTES = Math.max(
  Number(process.env.THREAT_LIBRARY_PDF_MAX_BYTES || 25_165_824),
  1024
);

export const THIB_MAX_BYTES = Math.max(
  Number(process.env.THREAT_LIBRARY_THIB_MAX_BYTES || 10_485_760),
  1024
);

export const URL_FETCH_TIMEOUT_MS = Math.max(
  Number(process.env.THREAT_LIBRARY_URL_TIMEOUT_MS || 30000),
  1000
);

export const URL_ALLOWED_CONTENT_TYPES = Object.freeze([
  'text/html',
  'application/xhtml+xml',
  'text/plain',
  'application/pdf'
]);

export const AI_PROVIDERS = Object.freeze(['openai', 'anthropic', 'ollama', 'openai_compatible']);

export const THIB_FORMAT = 'talonhound-intelligence-bundle';
export const THIB_SPEC_VERSION = '1.0';

export const IOC_SOURCE_NAME = 'Threat_Library';

/**
 * Normalize legacy TLP WHITE → CLEAR (TLP 2.0).
 * @param {string} value
 */
export function normalizeTlp(value) {
  const raw = String(value || '').trim().toLowerCase().replace(/^tlp:/, '').replace(/\s+/g, '_');
  if (raw === 'white') return 'clear';
  if (raw === 'amber+strict' || raw === 'amber-strict') return 'amber_strict';
  if (TLP_VALUES.includes(raw)) return raw;
  return 'clear';
}

/**
 * Derive match_state / review bucket from assessment + confidence + existing match.
 * @param {{ assessment: string, confidence: number|null, matchedIocId: number|null, valid: boolean }} input
 */
export function deriveMatchState(input) {
  if (!input.valid) return 'invalid';
  if (input.assessment === 'invalid') return 'invalid';
  if (input.assessment === 'context_only') return 'context_only';
  if (input.matchedIocId != null) return 'existing';
  const conf = input.confidence == null ? null : Number(input.confidence);
  if (
    conf != null &&
    conf < CONFIDENCE_POLICY.REVIEW_FLOOR &&
    (input.assessment === 'unknown' || input.assessment === 'suspicious')
  ) {
    return 'needs_review';
  }
  if (input.assessment === 'unknown' && (conf == null || conf < CONFIDENCE_POLICY.HIGH)) {
    return 'needs_review';
  }
  return 'new';
}

/**
 * @param {string} name
 */
export function normalizeEntityName(name) {
  return String(name || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}
