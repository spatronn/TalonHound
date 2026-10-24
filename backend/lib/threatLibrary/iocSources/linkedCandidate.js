/**
 * The one linked-IOC-Source candidate shape, shared by the document path
 * (txt / markdown / AsciiDoc / HTML / PDF) and the structured CSV / NDJSON
 * parsers. A linked pack is a source-scoped authoritative list: its rows are
 * `linked_source_ioc` assertions and never original-document occurrences.
 */

import { LINKED_SOURCE_IOC_ASSERTION } from './constants.js';

/**
 * @param {{ candidate_type: string, original_value?: string, normalized_value: string, assessment?: string,
 *   role?: string, confidence?: number, evidence_text?: string|null, section?: string|null, block_id?: string|null,
 *   page_number?: number|null, match_state?: string, evidence?: object, occurrences?: object[] }} c
 * @param {{ sourcePublicId?: string|null, filePath?: string|null }} [meta]
 */
export function toLinkedSourceCandidate(c, meta = {}) {
  const ev = c.evidence && typeof c.evidence === 'object' ? c.evidence : {};
  const occurrences = Array.isArray(c.occurrences) ? c.occurrences : Array.isArray(ev.occurrences) ? ev.occurrences : null;
  return {
    candidate_type: c.candidate_type,
    original_value: c.original_value ?? c.normalized_value,
    normalized_value: c.normalized_value,
    assessment: c.assessment === 'context_only' || c.assessment === 'invalid' ? c.assessment : 'malicious',
    role: c.role || 'malicious_infrastructure',
    confidence: c.confidence ?? 0.9,
    evidence_text: c.evidence_text || null,
    section: c.section || meta.filePath || 'linked_ioc_source',
    block_id: c.block_id || null,
    page_number: c.page_number ?? null,
    review_status: 'pending',
    match_state: c.match_state || 'new',
    is_ioc: true,
    source_assertion: LINKED_SOURCE_IOC_ASSERTION,
    has_original_document_occurrence: false,
    evidence: {
      ...ev,
      source_assertion: LINKED_SOURCE_IOC_ASSERTION,
      document_has_authoritative_scope: false,
      linked_source: true,
      linked_source_id: meta.sourcePublicId || null,
      linked_source_path: meta.filePath || null,
      is_direct_source_observable: true,
      occurrences: occurrences
        ? occurrences.map((o) => ({
            ...o,
            zone: o.zone || 'linked_ioc_source',
            asserted: true,
            occurrence_kind: o.occurrence_kind || 'standalone_indicator_row'
          }))
        : [
            {
              zone: 'linked_ioc_source',
              asserted: true,
              occurrence_kind: 'standalone_indicator_row',
              surrounding_text: c.evidence_text || c.original_value || c.normalized_value
            }
          ]
    }
  };
}
