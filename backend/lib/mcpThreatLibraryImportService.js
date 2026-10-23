/**
 * MCP Threat Library URL import (threat_library_import_url) and import status
 * (get_threat_library_import_status).
 *
 * The import is the Import Intelligence → URL → Start Import operation itself:
 * importThreatLibraryUrl (lib/threatLibrary/urlImportService.js) is the same
 * function POST /api/threat-library/import/url calls — same URL/SSRF policy,
 * canonical-URL duplicate identity under the advisory lock, report + analyze
 * job rows, analysis-slot dispatch onto the threat-library queue and the same
 * threat_library.report.* audit events (plus MCP key provenance). This module
 * only maps outcomes to MCP responses and reads persisted status back; it never
 * fetches, parses, extracts, reviews or promotes anything.
 */

import { importThreatLibraryUrl, URL_IMPORT_OUTCOMES } from './threatLibrary/urlImportService.js';
import { getReportByPublicId } from './threatLibrary/store.js';
import { IMPORT_DUPLICATE_MESSAGES } from './threatLibrary/importIdentity.js';
import { resolveReportPhase, REPORT_PHASES } from './threatLibrary/reportPhase.js';
import { TLP_DISPLAY } from './threatLibrary/constants.js';
import { safeErrorCategory } from './threatLibrary/audit.js';
import { THREAT_REPORT_READABLE_IMPORT_STATUSES, isThreatReportId } from './threatLibrary/mcpThreatReport.js';
import { mcpActorAuditFields } from './mcpIocService.js';

const FAILURE_TEXT_MAX = 500;

function bounded(v, max = FAILURE_TEXT_MAX) {
  if (v === null || v === undefined || v === '') return null;
  const s = String(v);
  return s.length > max ? s.slice(0, max) : s;
}

function iso(v) {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Analyst-facing processing state of one report (persisted columns only). */
export function serializeImportReportState(row) {
  const phase = resolveReportPhase(row);
  return {
    id: row.public_id,
    title: row.title ?? null,
    source_type: row.source_type ?? null,
    source_name: row.source_name ?? null,
    source_url: row.source_url ?? null,
    tlp: row.tlp ?? null,
    tlp_display: row.tlp ? (TLP_DISPLAY[row.tlp] || `TLP:${String(row.tlp).toUpperCase()}`) : null,
    import_status: row.import_status ?? null,
    analysis_status: row.analysis_status ?? null,
    // preparing | review_ready | finalized | failed (same mapping the UI uses).
    review_phase: phase,
    created_at: iso(row.created_at),
    finalized_at: iso(row.finalized_at),
    failure: phase === REPORT_PHASES.FAILED
      ? {
          stage: row.failure_stage ?? null,
          code: row.failure_code ?? null,
          reason: bounded(row.failure_reason)
        }
      : null
  };
}

export function serializeImportJobState(job) {
  if (!job) return null;
  return {
    id: job.public_id,
    job_type: job.job_type ?? null,
    status: job.status ?? null,
    stage: job.stage ?? null,
    // true once an analysis slot was assigned and the job is on the worker queue.
    dispatched_to_worker: job.bullmq_job_id != null,
    error_message: bounded(job.error_message),
    created_at: iso(job.created_at),
    finished_at: iso(job.finished_at)
  };
}

/** What the caller can do next, derived from the persisted phase only. */
function processingFlags(report) {
  const phase = report.review_phase;
  return {
    // Analysis finished and produced the reviewable indicator set; IOC review /
    // Create IOCs remain separate analyst actions.
    ingestion_complete: phase === REPORT_PHASES.REVIEW_READY || phase === REPORT_PHASES.FINALIZED,
    ingestion_failed: phase === REPORT_PHASES.FAILED,
    readable_with_get_threat_report: THREAT_REPORT_READABLE_IMPORT_STATUSES.includes(String(report.import_status || ''))
  };
}

async function loadLatestJob(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT public_id, job_type, status, stage, bullmq_job_id, error_message, created_at, finished_at
     FROM threat_library_jobs WHERE report_id = $1 ORDER BY id DESC LIMIT 1`,
    [reportId]
  );
  return rows[0] || null;
}

async function loadJobById(pool, jobId) {
  const { rows } = await pool.query(
    `SELECT public_id, job_type, status, stage, bullmq_job_id, error_message, created_at, finished_at
     FROM threat_library_jobs WHERE id = $1`,
    [jobId]
  );
  return rows[0] || null;
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ url: string }} args
 * @param {{ req?: object, user?: object, mcpAuth?: object, audit?: object }} ctx
 * @param {{ threatLibraryQueue?: import('bullmq').Queue|null }} [deps]
 */
export async function mcpThreatLibraryImportUrl(pool, args, ctx, deps = {}) {
  const req = ctx.req || null;
  const user = ctx.user || req?.user || null;
  const actorFields = mcpActorAuditFields(ctx.mcpAuth || req?.mcpAuth, user);
  const audit = ctx.audit || null;

  let result;
  try {
    result = await importThreatLibraryUrl(
      {
        pool,
        queue: deps.threatLibraryQueue || null,
        writeAudit: async (event) => {
          if (typeof audit?.auditLog !== 'function') return;
          await audit.auditLog({ req, ...event });
        },
        // Same principal resolution as the route's actorOf(req).
        resolveActor: async () => {
          if (typeof audit?.resolveActor === 'function') {
            const actor = await audit.resolveActor(req);
            if (actor) return actor;
          }
          return user;
        }
      },
      {
        url: args?.url,
        principal: user,
        auditDetails: { ...actorFields.metadataExtras, tool: 'threat_library_import_url' }
      }
    );
  } catch (err) {
    // Audited by the import service (threat_library.report.import_failed).
    // Only the safe error category is returned — never internal messages.
    return {
      status: 500,
      error: {
        code: 'IMPORT_FAILED',
        message: 'Threat Library URL import failed',
        reason: safeErrorCategory(err)
      }
    };
  }

  if (result.outcome === URL_IMPORT_OUTCOMES.INVALID_URL) {
    return { status: 400, error: { code: 'INVALID_URL', message: result.message } };
  }

  if (result.outcome === URL_IMPORT_OUTCOMES.ALREADY_IMPORTED) {
    const current = (await getReportByPublicId(pool, result.report.public_id)) || result.report;
    const report = serializeImportReportState(current);
    return {
      status: 200,
      body: {
        outcome: 'already_exists',
        already_imported: true,
        duplicate_reason: result.duplicateReason,
        message: IMPORT_DUPLICATE_MESSAGES[result.duplicateReason],
        report_id: report.id,
        job_id: null,
        source_url: result.sourceUrl,
        report,
        latest_job: serializeImportJobState(await loadLatestJob(pool, current.id)),
        ...processingFlags(report)
      }
    };
  }

  // Read back what the backend actually holds now (the worker may already
  // have picked the job up); nothing is inferred from the queue hand-off.
  const current = (await getReportByPublicId(pool, result.report.public_id)) || result.report;
  const job = (await loadJobById(pool, result.job.id)) || result.job;
  const report = serializeImportReportState(current);
  return {
    status: 202,
    body: {
      outcome: 'import_started',
      already_imported: false,
      duplicate_reason: null,
      message: 'Report import accepted. Fetching, extraction and analysis run in the background; '
        + 'poll get_threat_library_import_status with report_id, then use threat_library_get_review / '
        + 'threat_library_review_iocs / threat_library_create_iocs / threat_library_finalize_report for the analyst workflow.',
      report_id: report.id,
      job_id: job.public_id,
      source_url: result.sourceUrl,
      report,
      job: serializeImportJobState(job),
      ...processingFlags(report)
    }
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ report_id: string }} args
 */
export async function mcpGetThreatLibraryImportStatus(pool, args) {
  const id = String(args?.report_id || '').trim();
  if (!isThreatReportId(id)) {
    return { status: 400, error: { code: 'INVALID_REPORT_ID', message: 'report_id must be a Threat Library report uuid' } };
  }
  const row = await getReportByPublicId(pool, id);
  if (!row) return { status: 404, error: { code: 'NOT_FOUND', message: 'Threat report not found' } };
  const report = serializeImportReportState(row);
  return {
    status: 200,
    body: {
      report_id: report.id,
      report,
      latest_job: serializeImportJobState(await loadLatestJob(pool, row.id)),
      ...processingFlags(report)
    }
  };
}
