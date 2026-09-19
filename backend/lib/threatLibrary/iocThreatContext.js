/**
 * IOC Threat Context — the canonical read + public shape shared by the HTTP
 * route (GET /api/ioc/:id/threat-context, IOC Details "Threat Context") and
 * MCP get_ioc_context. One SQL path (store.getIocThreatContext), one
 * serializer, so every interface exposes the same Threat Library claims and
 * relationships. Persisted data only: never fetches, re-parses or re-analyzes
 * a report.
 */

import { getIocThreatContext } from './store.js';
import { TLP_DISPLAY } from './constants.js';

function tlpDisplay(tlp) {
  return TLP_DISPLAY[tlp] || tlp;
}

export function serializeThreatContextClaim(c) {
  return {
    role: c.role,
    assessment: c.assessment,
    confidence: c.confidence,
    evidence_text: c.evidence_text,
    section: c.section,
    page_number: c.page_number,
    report: {
      id: c.report_public_id,
      title: c.report_title,
      published_at: c.published_at,
      tlp: c.tlp,
      tlp_display: tlpDisplay(c.tlp),
      source_name: c.source_name,
      source_type: c.source_type
    }
  };
}

/**
 * Relationship rows join threat_relationships with the report and both entity
 * endpoints. Internal FK columns (report_id, *_entity_id, *_candidate_id,
 * block_id) are not part of the public shape; IOC endpoints keep their ioc_id
 * because that is the id every IOC read already exposes.
 */
export function serializeThreatContextRelationship(r) {
  return {
    id: r.public_id,
    relationship_type: r.relationship_type,
    role: r.role ?? null,
    confidence: r.confidence ?? null,
    evidence_text: r.evidence_text ?? null,
    section: r.section ?? null,
    page_number: r.page_number ?? null,
    subject_kind: r.subject_kind,
    subject_entity_name: r.subject_entity_name ?? null,
    subject_entity_type: r.subject_entity_type ?? null,
    subject_ioc_id: r.subject_ioc_id ?? null,
    subject_portable_ref: r.subject_portable_ref ?? null,
    object_kind: r.object_kind,
    object_entity_name: r.object_entity_name ?? null,
    object_entity_type: r.object_entity_type ?? null,
    object_ioc_id: r.object_ioc_id ?? null,
    object_portable_ref: r.object_portable_ref ?? null,
    // Flat alias kept for the IOC Details section, which reads rel.report_title.
    report_title: r.report_title,
    report: {
      id: r.report_public_id,
      title: r.report_title,
      tlp: r.tlp,
      tlp_display: tlpDisplay(r.tlp)
    },
    created_at: r.created_at
  };
}

export function serializeIocThreatContext(ctx) {
  return {
    claims: (ctx?.claims || []).map(serializeThreatContextClaim),
    relationships: (ctx?.relationships || []).map(serializeThreatContextRelationship)
  };
}

/**
 * Read + serialize in one call. Errors propagate: a failed read must surface as
 * a failure, never as an empty "no threat context" answer.
 */
export async function loadIocThreatContext(pool, iocId) {
  const ctx = await getIocThreatContext(pool, iocId);
  return serializeIocThreatContext(ctx);
}
