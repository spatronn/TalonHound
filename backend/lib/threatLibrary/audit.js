/**
 * Threat Library audit event builders.
 *
 * One audit row per user action, never one per candidate. Bulk outcomes are
 * carried as a bounded, explicitly-counted sample inside metadata so the main
 * Audit Log is never flooded and truncation is never silent.
 *
 * TLP safety: only operational metadata is ever emitted from here — report
 * identity, counts, indicator values and IOC ids. Never the report body,
 * evidence paragraphs, PDF content, AI prompts/outputs or THIB payloads.
 */

import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY, AUDIT_STATUS } from '../auditConstants.js';
import { isTlpDowngrade } from './tlpPolicy.js';
import { redactUrlSecrets } from '../auditRedaction.js';
import { PROMOTION_OUTCOMES } from './promotion.js';

/** Max per-candidate outcome rows stored in one bulk event's metadata. */
export const AUDIT_RESULT_SAMPLE_LIMIT = 100;

export const THREAT_LIBRARY_WORKER_EXECUTOR = 'threat-library-worker';

const REVIEW_ACTION_AUDIT = Object.freeze({
  approve: { action: AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_APPROVED, target: 'approved' },
  approve_high_confidence_malicious: {
    action: AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_APPROVED,
    target: 'approved'
  },
  context_only: { action: AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_CONTEXT_ONLY, target: 'context_only' },
  ignore: { action: AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_IGNORED, target: 'ignored' },
  // Row-level analyst override: a Context Only row re-classified as an approved IOC candidate.
  promote_to_ioc: { action: AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_PROMOTED, target: 'approved' }
});

/** Entity columns for a report row: title is the display, public id the key. */
export function reportAuditEntity(report) {
  return {
    entityType: AUDIT_ENTITY.THREAT_REPORT,
    entityId: report?.public_id != null ? String(report.public_id) : null,
    entityDisplay: report?.title ? String(report.title) : null
  };
}

/**
 * Report identity snapshot for metadata. Persisted on every event so the row
 * stays meaningful after the report is deleted (no live join needed).
 */
export function reportAuditSnapshot(report) {
  if (!report) return {};
  return {
    report_id: report.id != null ? Number(report.id) : null,
    report_public_id: report.public_id != null ? String(report.public_id) : null,
    report_title: report.title ? String(report.title).slice(0, 512) : null,
    source_type: report.source_type || null,
    tlp: report.tlp || null
  };
}

/** Actor snapshot embedded in metadata (the actor columns remain canonical). */
export function initiatedBy(user) {
  if (!user) return null;
  return user.email || user.username || null;
}

/** Candidate type distribution over a selection: `{ ip: 80, domain: 12 }`. */
export function summarizeCandidateTypes(candidates) {
  const out = {};
  for (const c of Array.isArray(candidates) ? candidates : []) {
    const type = String(c?.candidate_type || 'unknown').toLowerCase();
    out[type] = (out[type] || 0) + 1;
  }
  return out;
}

/**
 * Bound per-candidate outcomes for metadata. Counts are always explicit so a
 * reader can tell when rows were omitted.
 */
export function boundedPromotionResults(results, candidatesById, limit = AUDIT_RESULT_SAMPLE_LIMIT) {
  const list = Array.isArray(results) ? results : [];
  const max = Math.max(0, Math.min(Number(limit) || 0, AUDIT_RESULT_SAMPLE_LIMIT));
  const shown = list.slice(0, max).map((r) => {
    const candidate = candidatesById?.get?.(Number(r.candidate_id)) || null;
    return {
      candidate_id: r.candidate_id != null ? Number(r.candidate_id) : null,
      type: candidate?.candidate_type || null,
      value: candidate?.normalized_value || candidate?.original_value || null,
      outcome: r.outcome || null,
      ioc_id: r.ioc_id != null ? Number(r.ioc_id) : null,
      ...(r.outcome === PROMOTION_OUTCOMES.FAILED && r.detail ? { error: String(r.detail).slice(0, 200) } : {})
    };
  });
  return {
    results_total: list.length,
    results_shown: shown.length,
    results_omitted: Math.max(0, list.length - shown.length),
    results: shown
  };
}

/** success: nothing failed · partial: some rows committed, some failed · failed: nothing usable committed. */
export function createIocsAuditStatus(summary) {
  const failed = Number(summary?.failed || 0);
  if (failed === 0) return AUDIT_STATUS.SUCCESS;
  const committed = Number(summary?.created || 0) + Number(summary?.already_existing || 0);
  return committed > 0 ? AUDIT_STATUS.PARTIAL : AUDIT_STATUS.FAILED;
}

/**
 * Parent event for one Create IOCs execution. Uses the backend-authoritative
 * summary/results produced after every row was persisted.
 */
export function buildCreateIocsAuditEvent({ report, summary, results, candidates, operationId, user }) {
  const byId = new Map((Array.isArray(candidates) ? candidates : []).map((c) => [Number(c.id), c]));
  const status = createIocsAuditStatus(summary);
  const bounded = boundedPromotionResults(results, byId);
  return {
    action: AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED,
    ...reportAuditEntity(report),
    severity: status === AUDIT_STATUS.SUCCESS ? AUDIT_SEVERITY.INFO : AUDIT_SEVERITY.WARNING,
    status,
    metadata: {
      ...reportAuditSnapshot(report),
      operation_id: operationId || null,
      initiated_by: initiatedBy(user),
      executed_by: 'backend',
      selected: Number(summary?.selected || 0),
      eligible: Number(summary?.eligible || 0),
      created: Number(summary?.created || 0),
      already_existing: Number(summary?.already_existing || 0),
      not_approved: Number(summary?.not_approved || 0),
      unsupported: Number(summary?.unsupported || 0),
      not_applicable: Number(summary?.not_applicable || 0),
      failed: Number(summary?.failed || 0),
      created_ioc_ids: (Array.isArray(results) ? results : [])
        .filter((r) => r.outcome === PROMOTION_OUTCOMES.CREATED && r.ioc_id != null)
        .map((r) => Number(r.ioc_id))
        .slice(0, AUDIT_RESULT_SAMPLE_LIMIT),
      candidate_types: summarizeCandidateTypes(candidates),
      ...bounded
    }
  };
}

/** Origin metadata attached to each `ioc.created` row produced by Create IOCs. */
export function iocCreatedOriginMetadata({ report, candidate, operationId, user }) {
  return {
    origin: 'threat_library',
    threat_report_id: report?.id != null ? Number(report.id) : null,
    threat_report_public_id: report?.public_id != null ? String(report.public_id) : null,
    threat_report_title: report?.title ? String(report.title).slice(0, 512) : null,
    threat_report_candidate_id: candidate?.id != null ? Number(candidate.id) : null,
    threat_library_operation_id: operationId || null,
    initiated_by: initiatedBy(user)
  };
}

export function reviewActionAudit(action) {
  return REVIEW_ACTION_AUDIT[String(action || '')] || null;
}

/**
 * Grouped event for Approve / Context only / Ignore / Approve high-confidence.
 * `candidates` are the selected rows as they were BEFORE the update.
 */
export function buildReviewAuditEvent({ report, action, requestedIds, candidates, user, skippedIds = [] }) {
  const mapping = reviewActionAudit(action);
  if (!mapping) return null;
  const rows = Array.isArray(candidates) ? candidates : [];
  // Rows the action refused (context-only / non-IOC on Approve) are neither changed nor already in state.
  const skipped = new Set((Array.isArray(skippedIds) ? skippedIds : []).map(Number));
  const applied = rows.filter((c) => !skipped.has(Number(c.id)));
  const changed = applied.filter((c) => String(c.review_status || 'pending') !== mapping.target).length;
  return {
    action: mapping.action,
    ...reportAuditEntity(report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(report),
      review_action: String(action),
      target_state: mapping.target,
      initiated_by: initiatedBy(user),
      selected: Array.isArray(requestedIds) ? requestedIds.length : rows.length,
      matched: rows.length,
      changed,
      already_in_state: applied.length - changed,
      skipped_context_only: skipped.size,
      candidate_types: summarizeCandidateTypes(rows),
      candidate_ids: rows.map((c) => Number(c.id)).slice(0, AUDIT_RESULT_SAMPLE_LIMIT),
      candidate_ids_total: rows.length
    }
  };
}

/** Final review summary counted over every candidate row of the report. */
export function summarizeFinalizeCandidates(candidates) {
  const summary = {
    total_candidates: 0,
    approved: 0,
    context_only: 0,
    ignored: 0,
    pending: 0,
    created: 0,
    already_existing: 0,
    unsupported: 0,
    failed: 0
  };
  for (const c of Array.isArray(candidates) ? candidates : []) {
    summary.total_candidates += 1;
    const review = String(c.review_status || 'pending').toLowerCase();
    if (review === 'approved' || review === 'created_ioc') summary.approved += 1;
    else if (review === 'context_only') summary.context_only += 1;
    else if (review === 'ignored') summary.ignored += 1;
    else summary.pending += 1;
    const outcome = String(c.promotion_outcome || (review === 'created_ioc' ? PROMOTION_OUTCOMES.CREATED : ''));
    if (outcome === PROMOTION_OUTCOMES.CREATED) summary.created += 1;
    else if (outcome === PROMOTION_OUTCOMES.ALREADY_EXISTING) summary.already_existing += 1;
    else if (outcome === PROMOTION_OUTCOMES.UNSUPPORTED) summary.unsupported += 1;
    else if (outcome === PROMOTION_OUTCOMES.FAILED) summary.failed += 1;
  }
  return summary;
}

export function buildFinalizeAuditEvent({ report, candidates, user }) {
  return {
    action: AUDIT_ACTION.THREAT_LIBRARY_REPORT_FINALIZED,
    ...reportAuditEntity(report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(user),
      ...summarizeFinalizeCandidates(candidates)
    }
  };
}

/** Source URL provenance change; credentials/tokens in either URL are masked. */
export function buildSourceUrlAuditEvent({ report, oldUrl, newUrl, user }) {
  return {
    action: AUDIT_ACTION.THREAT_LIBRARY_REPORT_SOURCE_URL_UPDATED,
    ...reportAuditEntity(report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    before: { source_url: redactUrlSecrets(oldUrl) },
    after: { source_url: redactUrlSecrets(newUrl) },
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(user),
      old_source_url: redactUrlSecrets(oldUrl),
      new_source_url: redactUrlSecrets(newUrl)
    }
  };
}

export function buildTlpAuditEvent({ report, oldTlp, oldSource, newTlp, user }) {
  return {
    action: AUDIT_ACTION.THREAT_LIBRARY_REPORT_TLP_UPDATED,
    ...reportAuditEntity(report),
    severity: isTlpDowngrade(oldTlp, newTlp) ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    before: { tlp: oldTlp || null, tlp_source: oldSource || null },
    after: { tlp: newTlp || null, tlp_source: 'manual' },
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(user),
      old_tlp: oldTlp || null,
      new_tlp: newTlp || null,
      old_tlp_source: oldSource || null,
      downgrade: isTlpDowngrade(oldTlp, newTlp)
    }
  };
}

/**
 * Report tag added/removed. Tags are campaign/threat context inherited (at read
 * time) by the report's IOC records; direct IOC tags are never written.
 */
export function buildReportTagAuditEvent({ report, tag, added, inheritingIocCount, user }) {
  return {
    action: added
      ? AUDIT_ACTION.THREAT_LIBRARY_REPORT_TAG_ADDED
      : AUDIT_ACTION.THREAT_LIBRARY_REPORT_TAG_REMOVED,
    ...reportAuditEntity(report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    before: added ? null : { tag: tag?.name || null },
    after: added ? { tag: tag?.name || null } : null,
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(user),
      tag_id: tag?.id ?? null,
      tag: tag?.name || null,
      inheriting_ioc_count: Number.isFinite(inheritingIocCount) ? inheritingIocCount : null
    }
  };
}

export function buildDeleteAuditEvent({ report, user }) {
  return {
    action: AUDIT_ACTION.THREAT_LIBRARY_REPORT_DELETED,
    ...reportAuditEntity(report),
    severity: AUDIT_SEVERITY.WARNING,
    status: AUDIT_STATUS.SUCCESS,
    before: {
      title: report?.title || null,
      source_type: report?.source_type || null,
      tlp: report?.tlp || null,
      source_url: redactUrlSecrets(report?.source_url),
      source_file_name: report?.source_file_name || null
    },
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(user)
    }
  };
}

export function buildThibExportAuditEvent({ report, bundle, user, confirmRed }) {
  const indicators = Array.isArray(bundle?.indicators) ? bundle.indicators.length : 0;
  return {
    action: AUDIT_ACTION.THREAT_LIBRARY_THIB_EXPORTED,
    ...reportAuditEntity(report),
    severity: report?.tlp === 'red' ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(user),
      indicator_count: indicators,
      entity_count: Array.isArray(bundle?.entities) ? bundle.entities.length : 0,
      relationship_count: Array.isArray(bundle?.relationships) ? bundle.relationships.length : 0,
      confirm_red: confirmRed === true,
      thib_spec_version: bundle?.thib_spec_version || bundle?.spec_version || null
    }
  };
}

/**
 * Import events. `details` carries only file/URL provenance — never content.
 */
export function buildImportAuditEvent({ sourceType, report, user, jobPublicId, details }) {
  const actionByType = {
    pdf: AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_PDF,
    url: AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_URL,
    thib: AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_THIB
  };
  const safeDetails = { ...(details || {}) };
  if (safeDetails.source_url) safeDetails.source_url = redactUrlSecrets(safeDetails.source_url);
  return {
    action: actionByType[sourceType] || AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORTED_URL,
    ...reportAuditEntity(report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(user),
      job_public_id: jobPublicId || null,
      ...safeDetails
    }
  };
}

/** Failed import attempt (no report row may exist yet). */
export function buildImportFailedAuditEvent({ sourceType, user, code, details }) {
  return {
    action: AUDIT_ACTION.THREAT_LIBRARY_REPORT_IMPORT_FAILED,
    entityType: AUDIT_ENTITY.THREAT_REPORT,
    entityId: null,
    entityDisplay: details?.file_name || details?.host || null,
    severity: AUDIT_SEVERITY.WARNING,
    status: AUDIT_STATUS.FAILED,
    metadata: {
      source_type: sourceType,
      initiated_by: initiatedBy(user),
      error_code: code || 'import_failed',
      ...(details || {})
    }
  };
}

/**
 * Worker-side analysis outcome. The initiating human stays the actor
 * (resolved from threat_library_jobs.requested_by); the worker is recorded
 * as executor in metadata and `source` is `worker`.
 */
export function buildAnalysisAuditEvent({ report, job, ok, code, summary, initiator }) {
  const status = ok ? AUDIT_STATUS.SUCCESS : AUDIT_STATUS.FAILED;
  const cancelled = !ok && String(code || '') === 'job_cancelled';
  return {
    action: ok
      ? AUDIT_ACTION.THREAT_LIBRARY_REPORT_ANALYSIS_COMPLETED
      : AUDIT_ACTION.THREAT_LIBRARY_REPORT_ANALYSIS_FAILED,
    ...reportAuditEntity(report),
    severity: ok ? AUDIT_SEVERITY.INFO : AUDIT_SEVERITY.WARNING,
    status,
    source: 'worker',
    actor: initiator || null,
    metadata: {
      ...reportAuditSnapshot(report),
      initiated_by: initiatedBy(initiator),
      executed_by: THREAT_LIBRARY_WORKER_EXECUTOR,
      job_public_id: job?.public_id || null,
      job_type: job?.job_type || null,
      result: ok ? 'completed' : cancelled ? 'cancelled' : 'failed',
      error_code: ok ? null : (code || 'analysis_failed'),
      candidates_total: summary?.candidates_total ?? summary?.total ?? null,
      candidates_new: summary?.new ?? null,
      candidates_existing: summary?.existing ?? null,
      candidates_context_only: summary?.context_only ?? null,
      entities: summary?.entities ?? null
    }
  };
}

/**
 * Error category safe for audit metadata: never a message that might carry
 * SQL text, secrets or file paths.
 */
export function safeErrorCategory(err) {
  const code = String(err?.code || '').trim();
  if (/^[a-z0-9_]{2,64}$/i.test(code)) return code.toLowerCase();
  const name = String(err?.name || '').trim();
  if (name && name !== 'Error') return name.replace(/[^a-z0-9_]/gi, '_').toLowerCase().slice(0, 64);
  return 'internal_error';
}

/**
 * Context for a worker-emitted analysis event: report identity, job row and
 * the initiating user resolved from threat_library_jobs.requested_by (the
 * only place the request principal survives the queue boundary).
 */
export async function loadAnalysisAuditContext(pool, { reportId, jobId }) {
  const { rows: reports } = await pool.query(
    `SELECT id, public_id, title, source_type, tlp FROM threat_reports WHERE id = $1`,
    [reportId]
  );
  const report = reports[0] || null;
  const { rows: jobs } = await pool.query(
    `SELECT j.public_id, j.job_type, j.requested_by,
            u.public_id AS user_public_id, u.username AS user_username, u.role AS user_role, u.id AS user_id
     FROM threat_library_jobs j
     LEFT JOIN users u ON u.public_id = j.requested_by
     WHERE j.id = $1`,
    [jobId]
  );
  const job = jobs[0] || null;
  const initiator = job?.user_public_id
    ? {
        id: job.user_id != null ? Number(job.user_id) : null,
        publicId: String(job.user_public_id),
        username: job.user_username || null,
        email: job.user_username || null,
        role: job.user_role || null
      }
    : null;
  return { report, job, initiator };
}

/**
 * Emit the analysis outcome from the worker. Never throws: an audit failure
 * must not re-run or fail the job.
 */
export async function auditAnalysisOutcome(pool, auditService, { reportId, jobId, ok, code, summary }) {
  try {
    const ctx = await loadAnalysisAuditContext(pool, { reportId, jobId });
    if (!ctx.report) return;
    await auditService.auditLog(buildAnalysisAuditEvent({
      report: ctx.report,
      job: ctx.job,
      ok: ok === true,
      code,
      summary,
      initiator: ctx.initiator
    }));
  } catch (err) {
    console.warn('[threat-library-audit] analysis audit failed:', err?.message || err);
  }
}
