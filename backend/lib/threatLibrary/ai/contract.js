/**
 * Threat Library semantic AI contract version (independent of product VERSION).
 *
 * v4: evidence-model input (source_assertion / occurrences / parser-derived
 * metadata), deterministic candidates are sent as resolved context and the
 * model classifies only `ai_needed` candidates; candidate_id is mandatory in
 * candidate_updates; body prompts exclude header/footer/navigation blocks.
 * v5: source-scope + relation semantics (authoritative indicator sections vs
 * provider/service usage vs direct malicious assertions).
 */
export const THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION = 'threat-library-semantic-v5';

export const CANDIDATE_ROLE_VALUES = Object.freeze([
  'command_and_control',
  'redirector',
  'payload_hosting',
  'malware_download',
  'phishing',
  'tracking',
  'malicious_infrastructure',
  'delivery',
  'malware_sample',
  'legitimate_service',
  'hosting_platform',
  'victim',
  'reference',
  'security_tool',
  'unknown'
]);

/**
 * Structured-output and Zod bounds.
 *
 * Chunk caps sit well above healthy production Threat Library outputs
 * (largest observed successful chunk ≈ 10.5k chars / 11 entities) so dense
 * reports still fit, while an 86k-character relationship dump cannot.
 *
 * Merged-analysis Zod caps stay at the pre-existing array ceilings so
 * concatenating several valid chunks cannot fail validation merely because
 * the per-chunk provider schema is tighter.
 *
 * Last-resort Ollama `num_predict` (10240): ≈4× the largest healthy chunk
 * in tokens (10.5k chars ≈ 2.6k tokens) and enough to close a schema-capped
 * JSON object. Typical bounded output finishes far earlier; this is only a
 * ceiling so generation cannot fill the loaded 32k context.
 */
export const AI_OUTPUT_BOUNDS = Object.freeze({
  summaryMaxLengthChunk: 4000,
  summaryMaxLengthMerged: 8000,
  reportTypeMaxLength: 64,
  languageMaxLength: 16,
  tlpMaxLength: 32,
  entityMaxItemsChunk: 80,
  entityMaxItemsMerged: 100,
  entityNameMaxLength: 300,
  entityAliasMaxItems: 20,
  entityAliasMaxLength: 200,
  entityDescriptionMaxLength: 2000,
  evidenceBlockIdMaxItems: 20,
  evidenceBlockIdMaxLength: 64,
  evidenceTextMaxLength: 1000,
  candidateUpdatesMaxItems: 500,
  candidateIdMaxLength: 64,
  candidateTypeMaxLength: 32,
  normalizedValueMaxLength: 2000,
  sectionMaxLength: 300,
  relationshipMaxItemsChunk: 80,
  relationshipMaxItemsMerged: 300,
  refMaxLength: 400,
  relationshipTypeMaxLength: 64,
  roleMaxLength: 64,
  numPredict: 10240
});

/**
 * Per-chunk candidate_updates ceiling: one update per TO-CLASSIFY plus one
 * optional role refinement per resolved indicator. Never below the supplied
 * workload; never above the Zod/provider absolute max.
 * @param {number} toClassifyCount
 * @param {number} resolvedCount
 */
export function candidateUpdatesMaxItemsForChunk(toClassifyCount, resolvedCount) {
  const classify = Math.max(0, Number(toClassifyCount) || 0);
  const resolved = Math.max(0, Number(resolvedCount) || 0);
  return Math.min(AI_OUTPUT_BOUNDS.candidateUpdatesMaxItems, Math.max(classify + resolved, 8));
}

/**
 * JSON Schema for provider structured-output (Ollama `format` object).
 * Kept in sync with Zod canonical fields in schema.js — every schema cap is
 * ≤ the corresponding Zod cap so a grammar-accepted payload cannot fail
 * solely for being "too large" at validation.
 * @param {{ maxCandidateUpdates?: number }} [opts]
 */
export function buildProviderJsonSchema(opts = {}) {
  const B = AI_OUTPUT_BOUNDS;
  const maxUpdates = Math.min(
    B.candidateUpdatesMaxItems,
    Math.max(1, Number(opts.maxCandidateUpdates) || B.candidateUpdatesMaxItems)
  );
  const evidenceText = { type: ['string', 'null'], maxLength: B.evidenceTextMaxLength };
  const evidenceBlocks = {
    type: 'array',
    maxItems: B.evidenceBlockIdMaxItems,
    items: { type: 'string', maxLength: B.evidenceBlockIdMaxLength }
  };

  return {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'entities', 'candidate_updates', 'relationships'],
    properties: {
      summary: { type: 'string', maxLength: B.summaryMaxLengthChunk },
      report_type: { type: ['string', 'null'], maxLength: B.reportTypeMaxLength },
      language: { type: ['string', 'null'], maxLength: B.languageMaxLength },
      tlp: { type: ['string', 'null'], maxLength: B.tlpMaxLength },
      confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
      entities: {
        type: 'array',
        maxItems: B.entityMaxItemsChunk,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['entity_type', 'name'],
          properties: {
            entity_type: {
              type: 'string',
              enum: [
                'threat_actor',
                'malware',
                'campaign',
                'tool',
                'vulnerability',
                'infrastructure',
                'organization',
                'attack_pattern'
              ]
            },
            name: { type: 'string', maxLength: B.entityNameMaxLength },
            aliases: {
              type: 'array',
              maxItems: B.entityAliasMaxItems,
              items: { type: 'string', maxLength: B.entityAliasMaxLength }
            },
            description: { type: ['string', 'null'], maxLength: B.entityDescriptionMaxLength },
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: evidenceBlocks,
            evidence_text: evidenceText
          }
        }
      },
      candidate_updates: {
        type: 'array',
        maxItems: maxUpdates,
        items: {
          type: 'object',
          additionalProperties: false,
          // candidate_id is the join key — a grammar-constrained model must not omit it.
          required: ['candidate_id', 'assessment'],
          properties: {
            candidate_id: { type: 'string', maxLength: B.candidateIdMaxLength },
            candidate_type: { type: 'string', maxLength: B.candidateTypeMaxLength },
            normalized_value: { type: 'string', maxLength: B.normalizedValueMaxLength },
            assessment: {
              type: 'string',
              enum: ['malicious', 'suspicious', 'context_only', 'unknown', 'invalid']
            },
            role: { type: 'string', enum: [...CANDIDATE_ROLE_VALUES] },
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: {
              type: 'array',
              maxItems: 10,
              items: { type: 'string', maxLength: B.evidenceBlockIdMaxLength }
            },
            evidence_text: evidenceText,
            section: { type: ['string', 'null'], maxLength: B.sectionMaxLength }
          }
        }
      },
      relationships: {
        type: 'array',
        maxItems: B.relationshipMaxItemsChunk,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['subject_kind', 'subject_ref', 'relationship_type', 'object_kind', 'object_ref'],
          properties: {
            subject_kind: { type: 'string', enum: ['entity', 'candidate'] },
            subject_ref: { type: 'string', maxLength: B.refMaxLength },
            relationship_type: { type: 'string', maxLength: B.relationshipTypeMaxLength },
            object_kind: { type: 'string', enum: ['entity', 'candidate'] },
            object_ref: { type: 'string', maxLength: B.refMaxLength },
            role: { type: ['string', 'null'], maxLength: B.roleMaxLength },
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: {
              type: 'array',
              maxItems: 10,
              items: { type: 'string', maxLength: B.evidenceBlockIdMaxLength }
            },
            evidence_text: evidenceText
          }
        }
      }
    }
  };
}
