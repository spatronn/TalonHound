/**
 * MCP get_threat_report — bounded, read-only view of ONE persisted Threat
 * Library report for same-report drill-down after get_ioc_context.
 *
 * Reads the same store snapshot the report detail API uses
 * (loadReportSnapshot: fixed query count, no per-row reads) and serializes an
 * analyst allow-list: report metadata + summary, the indicator roster (paged,
 * document order), report-level entities and explicit relationships. Never
 * the full report body, artifacts, jobs, parser/evidence internals or failure
 * diagnostics. Persisted data only: no fetch, re-parse or model call.
 *
 * Same evidence semantics as threat_context: an indicator's own role /
 * assessment is IOC-specific; entities are report-level co-mentions; only
 * `relationships` state an explicit link.
 */

import { getReportByPublicId, loadReportSnapshot } from './store.js';
import { TLP_DISPLAY } from './constants.js';
import { resolveReportPhase } from './reportPhase.js';
import {
  serializeThreatContextEntity,
  serializeThreatContextRelationship,
  THREAT_CONTEXT_MAX_SUMMARY_CHARS
} from './iocThreatContext.js';

export const THREAT_REPORT_INDICATOR_LIMIT_DEFAULT = 100;
export const THREAT_REPORT_INDICATOR_LIMIT_MAX = 500;
export const THREAT_REPORT_MAX_ENTITIES = 50;
export const THREAT_REPORT_MAX_RELATIONSHIPS = 100;

// Reports an analyst may read through MCP = the same set Threat Context
// claims are drawn from (store.getIocThreatContext).
export const THREAT_REPORT_READABLE_IMPORT_STATUSES = Object.freeze(['ready', 'imported', 'review_required']);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isThreatReportId(v) {
  return typeof v === 'string' && UUID_RE.test(v.trim());
}

export function clampIndicatorPage({ limit, offset } = {}) {
  const lim = Number.isFinite(Number(limit)) && Number(limit) > 0
    ? Math.min(Math.trunc(Number(limit)), THREAT_REPORT_INDICATOR_LIMIT_MAX)
    : THREAT_REPORT_INDICATOR_LIMIT_DEFAULT;
  const off = Number.isFinite(Number(offset)) && Number(offset) > 0 ? Math.trunc(Number(offset)) : 0;
  return { limit: lim, offset: off };
}

function boundedText(v, max) {
  if (v === null || v === undefined) return null;
  const str = String(v);
  if (!str) return null;
  return str.length > max ? str.slice(0, max) : str;
}

/** Indicator row = one persisted candidate; allow-listed, no evidence internals. */
export function serializeThreatReportIndicator(c) {
  const occurrenceCount = Number(c?.evidence?.occurrence_count);
  return {
    id: c.public_id,
    value: c.normalized_value,
    original_value: c.original_value ?? null,
    type: c.candidate_type,
    is_ioc: c.is_ioc !== false,
    assessment: c.assessment,
    role: c.role,
    confidence: c.confidence ?? null,
    section: c.section ?? null,
    page_number: c.page_number ?? null,
    evidence_text: c.evidence_text ?? null,
    occurrence_count: Number.isFinite(occurrenceCount) ? occurrenceCount : 0,
    // Same normalization the report detail API applies.
    review_status: c.review_status === 'created_ioc' ? 'approved' : (c.review_status ?? null),
    match_state: c.match_state ?? null,
    // Internal IOC id, the same id lookup_ioc / get_ioc_context expose.
    ioc_id: c.matched_ioc_id ?? null,
    ioc_type: c.matched_ioc_observable_type ?? null
  };
}

function relationshipRowsWithNames(snapshot) {
  const byId = new Map((snapshot.entities || []).map((e) => [String(e.id), e]));
  const r = snapshot.report;
  return (snapshot.relationships || []).map((rel) => {
    const se = byId.get(String(rel.subject_entity_id));
    const oe = byId.get(String(rel.object_entity_id));
    return {
      ...rel,
      report_public_id: r.public_id,
      report_title: r.title,
      tlp: r.tlp,
      subject_entity_name: se?.name ?? null,
      subject_entity_type: se?.entity_type ?? null,
      object_entity_name: oe?.name ?? null,
      object_entity_type: oe?.entity_type ?? null
    };
  });
}

/**
 * @param {{ report: object, candidates: object[], entities: object[], relationships: object[] }} snapshot
 * @param {{ limit?: number, offset?: number }} page
 */
export function serializeThreatReport(snapshot, page = {}) {
  const r = snapshot.report;
  const { limit, offset } = clampIndicatorPage(page);
  const candidates = Array.isArray(snapshot.candidates) ? snapshot.candidates : [];
  const entities = Array.isArray(snapshot.entities) ? snapshot.entities : [];
  const relationships = relationshipRowsWithNames(snapshot);
  const pageRows = candidates.slice(offset, offset + limit);

  return {
    id: r.public_id,
    title: r.title,
    source_name: r.source_name ?? null,
    source_type: r.source_type ?? null,
    source_url: r.source_url ?? null,
    published_at: r.published_at ?? null,
    language: r.language ?? null,
    tlp: r.tlp,
    tlp_display: TLP_DISPLAY[r.tlp] || r.tlp,
    tlp_source: r.tlp_source || 'default',
    summary: boundedText(r.summary, THREAT_CONTEXT_MAX_SUMMARY_CHARS),
    import_status: r.import_status,
    review_phase: resolveReportPhase(r),
    created_at: r.created_at,
    updated_at: r.updated_at ?? null,
    finalized_at: r.finalized_at ?? null,
    counts: {
      indicators: candidates.length,
      entities: entities.length,
      relationships: relationships.length
    },
    indicators: {
      total: candidates.length,
      offset,
      limit,
      returned: pageRows.length,
      has_more: offset + pageRows.length < candidates.length,
      items: pageRows.map(serializeThreatReportIndicator)
    },
    // Report-level co-mentions. Not evidence of a link to any single indicator.
    entities: entities.slice(0, THREAT_REPORT_MAX_ENTITIES).map(serializeThreatContextEntity),
    // Explicit links only (same shape as threat_context.relationships).
    relationships: relationships.slice(0, THREAT_REPORT_MAX_RELATIONSHIPS).map(serializeThreatContextRelationship)
  };
}

/**
 * Resolve + read + serialize. Returns the MCP service outcome envelope.
 * Errors propagate (store failure is a failure, never an empty report).
 */
export async function loadThreatReportForMcp(pool, { id, indicator_limit, indicator_offset } = {}, { errorCodes } = {}) {
  const codes = errorCodes || {};
  const publicId = typeof id === 'string' ? id.trim() : '';
  if (!isThreatReportId(publicId)) {
    return { status: 400, error: { code: codes.VALIDATION_ERROR || 'VALIDATION_ERROR', message: 'id must be a Threat Library report id (uuid) — see get_ioc_context.threat_context.claims[].report.id' } };
  }
  const report = await getReportByPublicId(pool, publicId);
  if (!report) {
    return { status: 404, error: { code: codes.REPORT_NOT_FOUND || 'REPORT_NOT_FOUND', message: 'Threat report not found' } };
  }
  if (!THREAT_REPORT_READABLE_IMPORT_STATUSES.includes(String(report.import_status || ''))) {
    return { status: 409, error: { code: codes.REPORT_NOT_READY || 'REPORT_NOT_READY', message: `Threat report is not readable yet (import_status=${report.import_status})` } };
  }
  const snapshot = await loadReportSnapshot(pool, report.id);
  return { status: 200, body: serializeThreatReport(snapshot, { limit: indicator_limit, offset: indicator_offset }) };
}
