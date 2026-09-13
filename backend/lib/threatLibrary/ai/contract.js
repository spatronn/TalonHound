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
 * JSON Schema for provider structured-output (Ollama `format` object).
 * Kept in sync with Zod canonical fields in schema.js.
 */
export function buildProviderJsonSchema() {
  return {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'entities', 'candidate_updates', 'relationships'],
    properties: {
      summary: { type: 'string' },
      report_type: { type: ['string', 'null'] },
      language: { type: ['string', 'null'] },
      tlp: { type: ['string', 'null'] },
      confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
      entities: {
        type: 'array',
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
            name: { type: 'string' },
            aliases: { type: 'array', items: { type: 'string' } },
            description: { type: ['string', 'null'] },
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: { type: 'array', items: { type: 'string' } },
            evidence_text: { type: ['string', 'null'] }
          }
        }
      },
      candidate_updates: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          // candidate_id is the join key — a grammar-constrained model must not omit it.
          required: ['candidate_id', 'assessment'],
          properties: {
            candidate_id: { type: 'string' },
            candidate_type: { type: 'string' },
            normalized_value: { type: 'string' },
            assessment: {
              type: 'string',
              enum: ['malicious', 'suspicious', 'context_only', 'unknown', 'invalid']
            },
            role: { type: 'string', enum: [...CANDIDATE_ROLE_VALUES] },
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: { type: 'array', items: { type: 'string' } },
            evidence_text: { type: ['string', 'null'] },
            section: { type: ['string', 'null'] }
          }
        }
      },
      relationships: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['subject_kind', 'subject_ref', 'relationship_type', 'object_kind', 'object_ref'],
          properties: {
            subject_kind: { type: 'string', enum: ['entity', 'candidate'] },
            subject_ref: { type: 'string' },
            relationship_type: { type: 'string' },
            object_kind: { type: 'string', enum: ['entity', 'candidate'] },
            object_ref: { type: 'string' },
            role: { type: ['string', 'null'] },
            confidence: { type: ['number', 'null'], minimum: 0, maximum: 1 },
            evidence_block_ids: { type: 'array', items: { type: 'string' } },
            evidence_text: { type: ['string', 'null'] }
          }
        }
      }
    }
  };
}
