/**
 * Linked IOC Source analyst inspect / approve / dismiss — shared by the HTTP
 * Threat Library routes and MCP threat_library_review_ioc_source.
 *
 * Inspect queues the inspect job (same as POST …/ioc-sources/:id/inspect).
 * Approve transitions the source and queues the extract job (same as
 * POST /api/threat-library/ioc-sources/:id/approve). Dismiss only transitions
 * state (POST …/dismiss). Neither invents a parallel lifecycle.
 *
 * Approve requires lifecycle inspected|attached|extracted|failed|stale —
 * discovered packs must be inspected first (same gate as the UI).
 */

import { recordResolutionEvent } from './discoveryLedger.js';
import { AUDIT_ACTION, AUDIT_SEVERITY, AUDIT_STATUS } from '../../auditConstants.js';
import {
  initiatedBy,
  reportAuditEntity,
  reportAuditSnapshot
} from '../audit.js';
import { queueThreatLibraryAnalysis } from '../analysisConcurrency.js';
import { createJob } from '../store.js';
import { IOC_SOURCE_JOB_MODES } from './constants.js';
import {
  getIocSourceByPublicId,
  listSourceFiles,
  publicIocSource,
  setSelectedSourceFiles,
  transitionSource
} from './store.js';

function actorPublicId(actor) {
  return actor?.publicId || actor?.public_id || null;
}

async function writeAudit(audit, req, event) {
  if (typeof audit?.auditLog !== 'function') return;
  await audit.auditLog({ req, ...event });
}

async function queueIocSourceJob(pool, queue, report, source, jobType, actor, dispatchExtra = {}) {
  return queueThreatLibraryAnalysis(pool, queue, {
    reportId: report.id,
    jobType,
    requestedBy: actorPublicId(actor),
    jobPayload: { source_public_id: source.public_id },
    createJob,
    dispatch: {
      jobType,
      jobPayload: { source_public_id: source.public_id },
      ...dispatchExtra
    }
  });
}

/**
 * Queue inspection for a linked IOC Source (discovered → inspecting).
 * Same path as POST /api/threat-library/ioc-sources/:id/inspect.
 *
 * @param {import('pg').Pool} pool
 * @param {import('bullmq').Queue|null} queue
 * @param {{
 *   sourcePublicId: string,
 *   report: object,
 *   actor: object,
 *   audit?: object,
 *   req?: object,
 *   auditMetadataExtras?: object
 * }} opts
 */
export async function inspectLinkedIocSource(pool, queue, opts) {
  const source = await getIocSourceByPublicId(pool, opts.sourcePublicId);
  if (!source) {
    return { ok: false, status: 404, code: 'NOT_FOUND', error: 'IOC source not found' };
  }
  if (String(source.report_public_id) !== String(opts.report.public_id)) {
    return {
      ok: false,
      status: 409,
      code: 'SOURCE_REPORT_MISMATCH',
      error: 'IOC source does not belong to this report'
    };
  }
  if (opts.report?.finalized_at) {
    return {
      ok: false,
      status: 409,
      code: 'report_finalized',
      error: 'The report is finalized. Reopen it for review before inspecting or extracting its IOC Sources again.'
    };
  }
  // Match the HTTP inspect route: queue the job; the worker owns start_inspect.
  const { jobRow } = await queueIocSourceJob(
    pool,
    queue,
    opts.report,
    source,
    IOC_SOURCE_JOB_MODES.INSPECT,
    opts.actor
  );
  await writeAudit(opts.audit, opts.req, {
    action: AUDIT_ACTION.THREAT_LIBRARY_IOC_SOURCE_INSPECT_QUEUED,
    ...reportAuditEntity(opts.report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(opts.report),
      source_public_id: source.public_id,
      job_id: jobRow.public_id,
      initiated_by: initiatedBy(opts.actor),
      ...(opts.auditMetadataExtras || {})
    }
  });
  const files = await listSourceFiles(pool, source.id);
  return {
    ok: true,
    status: 202,
    source: publicIocSource(source, files),
    job_id: jobRow.public_id
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {import('bullmq').Queue|null} queue
 * @param {{
 *   sourcePublicId: string,
 *   report: object,
 *   actor: object,
 *   selectedPaths?: string[]|null,
 *   audit?: object,
 *   req?: object
 * }} opts
 */
export async function approveLinkedIocSource(pool, queue, opts) {
  const source = await getIocSourceByPublicId(pool, opts.sourcePublicId);
  if (!source) {
    return { ok: false, status: 404, code: 'NOT_FOUND', error: 'IOC source not found' };
  }
  if (String(source.report_public_id) !== String(opts.report.public_id)) {
    return {
      ok: false,
      status: 409,
      code: 'SOURCE_REPORT_MISMATCH',
      error: 'IOC source does not belong to this report'
    };
  }
  if (Array.isArray(opts.selectedPaths)) {
    await setSelectedSourceFiles(pool, source.id, opts.selectedPaths);
  }
  let updated;
  try {
    updated = await transitionSource(pool, source, 'approve', {
      approved_by: actorPublicId(opts.actor)
    });
  } catch (err) {
    if (err?.code === 'invalid_source_transition' || err?.code === 'report_finalized') {
      return { ok: false, status: 409, code: err.code, error: err.message };
    }
    throw err;
  }
  await writeAudit(opts.audit, opts.req, {
    action: AUDIT_ACTION.THREAT_LIBRARY_IOC_SOURCE_APPROVED,
    ...reportAuditEntity(opts.report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(opts.report),
      source_public_id: source.public_id,
      canonical_url: source.canonical_url,
      initiated_by: initiatedBy(opts.actor),
      ...(opts.auditMetadataExtras || {})
    }
  });
  const { jobRow } = await queueIocSourceJob(
    pool,
    queue,
    opts.report,
    updated || source,
    IOC_SOURCE_JOB_MODES.EXTRACT,
    opts.actor
  );
  await writeAudit(opts.audit, opts.req, {
    action: AUDIT_ACTION.THREAT_LIBRARY_IOC_SOURCE_EXTRACT_QUEUED,
    ...reportAuditEntity(opts.report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(opts.report),
      source_public_id: source.public_id,
      job_id: jobRow.public_id,
      ...(opts.auditMetadataExtras || {})
    }
  });
  const files = await listSourceFiles(pool, source.id);
  return {
    ok: true,
    status: 202,
    source: publicIocSource(updated || source, files),
    job_id: jobRow.public_id
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {{
 *   sourcePublicId: string,
 *   report: object,
 *   actor: object,
 *   audit?: object,
 *   req?: object
 * }} opts
 */
export async function dismissLinkedIocSource(pool, opts) {
  const source = await getIocSourceByPublicId(pool, opts.sourcePublicId);
  if (!source) {
    return { ok: false, status: 404, code: 'NOT_FOUND', error: 'IOC source not found' };
  }
  if (String(source.report_public_id) !== String(opts.report.public_id)) {
    return {
      ok: false,
      status: 409,
      code: 'SOURCE_REPORT_MISMATCH',
      error: 'IOC source does not belong to this report'
    };
  }
  let updated;
  try {
    const reason = String(opts.reason || '').trim().slice(0, 1000) || null;
    updated = await transitionSource(pool, source, 'dismiss', {
      dismissed_by: actorPublicId(opts.actor),
      dismissal_reason: reason
    });
    await recordResolutionEvent(pool, source.id, 'dismissal', { detail: reason, actorPublicId: actorPublicId(opts.actor) });
  } catch (err) {
    if (err?.code === 'invalid_source_transition' || err?.code === 'source_dismissed' || err?.code === 'report_finalized') {
      return { ok: false, status: 409, code: err.code, error: err.message };
    }
    throw err;
  }
  await writeAudit(opts.audit, opts.req, {
    action: AUDIT_ACTION.THREAT_LIBRARY_IOC_SOURCE_DISMISSED,
    ...reportAuditEntity(opts.report),
    severity: AUDIT_SEVERITY.INFO,
    status: AUDIT_STATUS.SUCCESS,
    metadata: {
      ...reportAuditSnapshot(opts.report),
      source_public_id: source.public_id,
      initiated_by: initiatedBy(opts.actor),
      dismissal_reason: String(opts.reason || '').trim().slice(0, 1000) || null,
      ...(opts.auditMetadataExtras || {})
    }
  });
  return {
    ok: true,
    status: 200,
    source: publicIocSource(updated || source)
  };
}
