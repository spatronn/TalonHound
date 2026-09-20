/**
 * IOC Threat Context — the canonical read + public shape shared by the HTTP
 * route (GET /api/ioc/:id/threat-context, IOC Details "Threat Context") and
 * MCP get_ioc_context. One SQL path (store.getIocThreatContext), one
 * serializer, so every interface exposes the same Threat Library claims and
 * relationships. Persisted data only: never fetches, re-parses or re-analyzes
 * a report.
 *
 * Evidence precedence a reader should apply, strongest first:
 *   1. explicit relationship (relationships[])
 *   2. IOC-specific claim (claims[].role / assessment / confidence)
 *   3. IOC-specific occurrence (claims[].occurrences[])
 *   4. report summary (claims[].report.summary)
 *   5. report-level entity co-mention (claims[].report.entities[])
 * A report title or a report-level entity alone never attributes the IOC.
 */

import { getIocThreatContext } from './store.js';
import { TLP_DISPLAY } from './constants.js';
import { serializePublicationDate } from './publicationDate.js';
import { findArtifactLinkedIocsByIocId } from '../fileArtifacts/read.js';

// Bounds for the per-claim report context. Persisted evidence already caps
// occurrences at 40 per candidate (evidencePolicy.buildCandidateEvidenceRecord,
// surrounding_text <= 200 chars); the report detail API shows 12. A Threat
// Context answer needs the first few in document order, so 5 per claim, with
// occurrence_count carrying the persisted total so a reader can tell when the
// list is cut. Reports carry single-digit entity counts in practice; 20 keeps
// the payload bounded without hiding a real actor/malware roster.
export const THREAT_CONTEXT_MAX_OCCURRENCES = 5;
export const THREAT_CONTEXT_MAX_ENTITIES = 20;
export const THREAT_CONTEXT_MAX_SUMMARY_CHARS = 2000;
export const THREAT_CONTEXT_MAX_TEXT_CHARS = 300;

function tlpDisplay(tlp) {
  return TLP_DISPLAY[tlp] || tlp;
}

function boundedText(v, max) {
  if (v === null || v === undefined) return null;
  const str = String(v);
  if (!str) return null;
  return str.length > max ? str.slice(0, max) : str;
}

/**
 * IOC-specific occurrence: where THIS candidate value appears in the report.
 * Allow-list of analyst-facing fields only; block ids, parser relation markers
 * and typing/zone reasons stay internal. Persisted document order is kept.
 */
export function serializeThreatContextOccurrence(o) {
  return {
    zone: o?.zone || null,
    section_heading: boundedText(o?.section_heading, THREAT_CONTEXT_MAX_TEXT_CHARS),
    page: o?.page ?? null,
    form: o?.form || null,
    surrounding_text: boundedText(o?.surrounding_text, THREAT_CONTEXT_MAX_TEXT_CHARS)
  };
}

function claimOccurrences(evidence) {
  const list = Array.isArray(evidence?.occurrences) ? evidence.occurrences : [];
  return {
    occurrence_count: Number.isFinite(Number(evidence?.occurrence_count))
      ? Number(evidence.occurrence_count)
      : list.length,
    occurrences: list.slice(0, THREAT_CONTEXT_MAX_OCCURRENCES).map(serializeThreatContextOccurrence)
  };
}

/**
 * Report-level entity: co-mentioned in the same report. NOT an IOC
 * relationship — it lives under report.entities and never under relationships.
 */
export function serializeThreatContextEntity(e) {
  return {
    id: e.public_id,
    entity_type: e.entity_type,
    name: e.name,
    description: boundedText(e.description, THREAT_CONTEXT_MAX_TEXT_CHARS)
  };
}

function groupEntitiesByReport(entityRows) {
  const byReport = new Map();
  for (const row of Array.isArray(entityRows) ? entityRows : []) {
    const key = String(row.report_id);
    if (!byReport.has(key)) byReport.set(key, []);
    const bucket = byReport.get(key);
    if (bucket.length < THREAT_CONTEXT_MAX_ENTITIES) bucket.push(serializeThreatContextEntity(row));
  }
  return byReport;
}

export function serializeThreatContextClaim(c, entitiesByReport = new Map()) {
  const { occurrence_count, occurrences } = claimOccurrences(c.evidence);
  return {
    role: c.role,
    assessment: c.assessment,
    confidence: c.confidence,
    evidence_text: c.evidence_text,
    section: c.section,
    page_number: c.page_number,
    // IOC-specific context: where this value appears in the report.
    occurrence_count,
    occurrences,
    report: {
      id: c.report_public_id,
      title: c.report_title,
      // Publication date of the source (published_date = calendar day as
      // stated; precision 'date' = no time known). created_at = when
      // TalonHound imported the report — the ordering fallback.
      ...serializePublicationDate(c),
      created_at: c.report_created_at ?? null,
      tlp: c.tlp,
      tlp_display: tlpDisplay(c.tlp),
      source_name: c.source_name,
      source_type: c.source_type,
      // Persisted report summary (threat_reports.summary); null when none.
      summary: boundedText(c.report_summary, THREAT_CONTEXT_MAX_SUMMARY_CHARS),
      // Report-level co-mentions, bounded. Not evidence of a direct IOC link.
      entities: entitiesByReport.get(String(c.report_id)) || []
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
  const entitiesByReport = groupEntitiesByReport(ctx?.entities);
  return {
    claims: (ctx?.claims || []).map((c) => serializeThreatContextClaim(c, entitiesByReport)),
    relationships: (ctx?.relationships || []).map(serializeThreatContextRelationship)
  };
}

/**
 * Read + serialize in one call. Errors propagate: a failed read must surface as
 * a failure, never as an empty "no threat context" answer.
 *
 * For file-hash IOCs, expands to every proven exact-hash alias of the same file
 * artifact (via file_artifact_ioc_links) so Threat Library matches created
 * against MD5/SHA1 remain visible after canonicalization to SHA256. Non-file
 * IOCs and read-flag-off deployments keep the single-id path.
 */
export async function loadIocThreatContext(pool, iocId) {
  const primaryId = Number(iocId);
  let iocIds = Number.isFinite(primaryId) && primaryId > 0 ? [primaryId] : [];
  try {
    const linked = await findArtifactLinkedIocsByIocId(pool, iocId);
    const linkedIds = (linked?.linked_ioc_ids || [])
      .map((n) => Number(n))
      .filter((n) => Number.isFinite(n) && n > 0);
    if (linkedIds.length) {
      // Keep the requested IOC first so DISTINCT ON claim preference favors it.
      iocIds = [primaryId, ...linkedIds.filter((n) => n !== primaryId)].filter((n) => Number.isFinite(n) && n > 0);
    }
  } catch (err) {
    // Artifact tables / flag optional — fall back to the single IOC id.
    if (!(err && (err.code === '42P01' || String(err.message || '').includes('file_artifact')))) {
      throw err;
    }
  }
  const ctx = await getIocThreatContext(pool, iocIds.length ? iocIds : iocId);
  return serializeIocThreatContext(ctx);
}
