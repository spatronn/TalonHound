/**
 * Convert structured STIX evidence into linked-source candidate rows.
 */

import { LINKED_SOURCE_IOC_ASSERTION } from '../constants.js';
import { EVIDENCE_MEMBERSHIP } from './evidence.js';

const NETWORK_TYPES = new Set(['ip', 'ipv6', 'cidr', 'domain', 'url', 'md5', 'sha1', 'sha256']);

/**
 * @param {import('./evidence.js').StixEvidence[]} evidence
 * @param {{ sourcePublicId?: string, filePath?: string }} [meta]
 */
export function candidatesFromStixEvidence(evidence, meta = {}) {
  const out = [];
  const seen = new Set();

  for (const e of evidence || []) {
    if (!e) continue;
    if (e.membership === EVIDENCE_MEMBERSHIP.UNSUPPORTED) continue;
    if (e.membership === EVIDENCE_MEMBERSHIP.EXCLUDED) continue;

    const type = String(e.observable_type || '').toLowerCase();
    // email and other non-network types stay out of Indicator candidate lists
    // (they remain in evidence/summary as context_only).
    if (e.membership === EVIDENCE_MEMBERSHIP.CONTEXT_ONLY && !NETWORK_TYPES.has(type)) {
      continue;
    }
    if (e.membership === EVIDENCE_MEMBERSHIP.INDICATOR && !NETWORK_TYPES.has(type)) {
      continue;
    }
    if (e.membership === EVIDENCE_MEMBERSHIP.UNCERTAIN && !NETWORK_TYPES.has(type)) {
      continue;
    }

    const key = `${type}\0${e.normalized_value}`;
    // Prefer Indicator membership when the same value appears as context too.
    if (seen.has(key)) {
      const existing = out.find((c) => c.candidate_type === type && c.normalized_value === e.normalized_value);
      if (existing && e.membership === EVIDENCE_MEMBERSHIP.INDICATOR && existing.assessment !== 'malicious') {
        existing.assessment = 'malicious';
        existing.role = e.evidence_role || existing.role;
      }
      continue;
    }
    seen.add(key);

    const assessment =
      e.membership === EVIDENCE_MEMBERSHIP.INDICATOR
        ? 'malicious'
        : e.membership === EVIDENCE_MEMBERSHIP.CONTEXT_ONLY
          ? 'context_only'
          : e.membership === EVIDENCE_MEMBERSHIP.UNCERTAIN
            ? 'context_only'
            : 'invalid';

    if (assessment === 'invalid') continue;

    out.push({
      candidate_type: type === 'ipv6' ? 'ip' : type,
      original_value: e.original_value,
      normalized_value: type === 'ipv6' ? e.normalized_value : e.normalized_value,
      assessment,
      role: e.evidence_role || (assessment === 'malicious' ? 'malicious_infrastructure' : 'context'),
      confidence: assessment === 'malicious' ? 0.9 : 0.5,
      evidence_text: e.evidence_locator || e.stix_object_id || null,
      section: meta.filePath || 'linked_ioc_source',
      block_id: e.stix_object_id || null,
      page_number: null,
      review_status: 'pending',
      match_state: 'new',
      is_ioc: assessment === 'malicious',
      source_assertion: LINKED_SOURCE_IOC_ASSERTION,
      has_original_document_occurrence: false,
      evidence: {
        source_assertion: LINKED_SOURCE_IOC_ASSERTION,
        document_has_authoritative_scope: false,
        linked_source: true,
        linked_source_id: meta.sourcePublicId || null,
        linked_source_path: meta.filePath || null,
        is_direct_source_observable: assessment === 'malicious',
        stix: {
          source_format: e.source_format,
          object_id: e.stix_object_id,
          locator: e.evidence_locator,
          object_semantics: e.object_semantics,
          membership: e.membership,
          diagnostics: e.diagnostics,
          meta: e.meta || {}
        },
        occurrences: [
          {
            zone: 'linked_ioc_source',
            asserted: assessment === 'malicious',
            occurrence_kind:
              assessment === 'malicious' ? 'standalone_indicator_row' : 'stix_context_observable',
            surrounding_text: e.evidence_locator || e.original_value
          }
        ]
      }
    });
  }

  return out;
}
