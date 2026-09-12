/**
 * AI provider facade for Threat Library.
 * Implementation lives in analyze.js / client.js / timeouts.js.
 */

export {
  analyzeThreatDocument,
  buildAnalysisChunks,
  candidatesForChunk,
  callAiProvider,
  maskAiSettingsForClient,
  assertAiReady,
  processAiResponseText,
  validateAiAnalysis,
  THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION
} from './analyze.js';

export {
  resolveAiTimeoutPolicy,
  defaultTimeoutsForProvider,
  isLocalAiProvider,
  AI_FAILURE_CODES,
  AI_FAILURE_MESSAGES
} from './timeouts.js';

export { normalizeConfidence, normalizeAiAnalysisInput } from './normalize.js';
export { extractJsonObject } from './extract.js';
export { probeAiProvider } from './probe.js';
