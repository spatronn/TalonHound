/**
 * Tiny structured-output probe for configured AI providers (no report data).
 */

import { callAiProvider } from './client.js';
import { processAiResponseText } from './schema.js';
import { buildProviderJsonSchema, THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './contract.js';
import { assertAiReady } from './settings.js';

export async function probeAiProvider(settings) {
  assertAiReady(settings);
  const system =
    'Return only JSON. confidence must be a number between 0 and 1. No markdown.';
  const user = [
    'Return exactly this shape:',
    '{"summary":"probe ok","report_type":"probe","language":"en","tlp":"CLEAR","confidence":0.9,"entities":[{"entity_type":"malware","name":"ProbeMalware","confidence":0.8,"evidence_block_ids":["b001"]}],"candidate_updates":[],"relationships":[]}'
  ].join('\n');

  const started = Date.now();
  const { text } = await callAiProvider(
    settings,
    { system, user },
    {
      analysisStartedAt: started,
      keepAlive: '0',
      formatSchema: buildProviderJsonSchema()
    }
  );
  const processed = processAiResponseText(text, {
    knownBlockIds: new Set(['b001']),
    knownCandidateKeys: new Set()
  });
  return {
    ok: processed.ok === true,
    elapsed_ms: Date.now() - started,
    schema_version: THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION,
    extract_method: processed.extract_method || null,
    error: processed.ok ? null : processed.error || 'probe_failed',
    details: processed.details || [],
    summary: processed.ok ? processed.value?.summary : null
  };
}
