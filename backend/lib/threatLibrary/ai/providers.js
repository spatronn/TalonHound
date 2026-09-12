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
  assertAiReady
} from './analyze.js';

export {
  resolveAiTimeoutPolicy,
  defaultTimeoutsForProvider,
  isLocalAiProvider,
  AI_FAILURE_CODES,
  AI_FAILURE_MESSAGES
} from './timeouts.js';
