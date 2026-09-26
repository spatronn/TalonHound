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
 *
 * Ollama 0.34.0 (llama.cpp GBNF) cannot compile JSON Schema `maxLength: 2000`
 * at all — even `{ type: "string", maxLength: 2000 }` returns HTTP 400
 * "Failed to initialize samplers: failed to parse grammar". 1999 and 2001
 * both compile. Provider grammar remaps 2000 → 1999; Zod keeps 2000.
 */
export const OLLAMA_UNPARSEABLE_MAX_LENGTH = 2000;
export const OLLAMA_SAFE_ALIAS_FOR_UNPARSEABLE_MAX_LENGTH = 1999;

/**
 * Provider-safe maxLength. Omits non-positive values. Remaps the one
 * integer Ollama 0.34.0 cannot compile so the rest of the bounded schema
 * can stay in the grammar.
 * @param {number} n
 * @returns {number|undefined}
 */
export function providerSafeMaxLength(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0) return undefined;
  if (v === OLLAMA_UNPARSEABLE_MAX_LENGTH) return OLLAMA_SAFE_ALIAS_FOR_UNPARSEABLE_MAX_LENGTH;
  return v;
}

function providerString(maxLength, { nullable = false } = {}) {
  const schema = nullable ? { type: ['string', 'null'] } : { type: 'string' };
  const safe = providerSafeMaxLength(maxLength);
  if (safe != null) schema.maxLength = safe;
  return schema;
}

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
  const evidenceText = providerString(B.evidenceTextMaxLength, { nullable: true });
  const evidenceBlocks = {
    type: 'array',
    maxItems: B.evidenceBlockIdMaxItems,
    items: providerString(B.evidenceBlockIdMaxLength)
  };

  return {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'entities', 'candidate_updates', 'relationships'],
    properties: {
      summary: providerString(B.summaryMaxLengthChunk),
      report_type: providerString(B.reportTypeMaxLength, { nullable: true }),
      language: providerString(B.languageMaxLength, { nullable: true }),
      tlp: providerString(B.tlpMaxLength, { nullable: true }),
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
            name: providerString(B.entityNameMaxLength),
            aliases: {
              type: 'array',
              maxItems: B.entityAliasMaxItems,
              items: providerString(B.entityAliasMaxLength)
            },
            description: providerString(B.entityDescriptionMaxLength, { nullable: true }),
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
            candidate_id: providerString(B.candidateIdMaxLength),
            candidate_type: providerString(B.candidateTypeMaxLength),
            normalized_value: providerString(B.normalizedValueMaxLength),
            assessment: {
              type: 'string',
              enum: ['malicious', 'suspicious', 'context_only', 'unknown', 'invalid']
            },
            role: { type: 'string', enum: [...CANDIDATE_ROLE_VALUES] },
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: {
              type: 'array',
              maxItems: 10,
              items: providerString(B.evidenceBlockIdMaxLength)
            },
            evidence_text: evidenceText,
            section: providerString(B.sectionMaxLength, { nullable: true })
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
            subject_ref: providerString(B.refMaxLength),
            relationship_type: providerString(B.relationshipTypeMaxLength),
            object_kind: { type: 'string', enum: ['entity', 'candidate'] },
            object_ref: providerString(B.refMaxLength),
            role: providerString(B.roleMaxLength, { nullable: true }),
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: {
              type: 'array',
              maxItems: 10,
              items: providerString(B.evidenceBlockIdMaxLength)
            },
            evidence_text: evidenceText
          }
        }
      }
    }
  };
}
