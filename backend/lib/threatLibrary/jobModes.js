/**
 * Threat Library pipeline job modes — the one explicit contract for what a
 * queued URL/PDF job is allowed to do. Persisted as threat_library_jobs.job_type
 * (migration 036) and carried as the BullMQ job name / `jobType`.
 *
 *   analyze             initial import: fetch / extract → candidates → AI → match
 *   retry               failure recovery: resume the failed pipeline (AI included),
 *                       reusing the stored document, candidates and completed chunks
 *   refresh_extraction  deterministic maintenance: re-extract candidates under the
 *                       current extractor contract and re-match. NEVER invokes a
 *                       model; AI-derived report data is left untouched
 *   rerun_ai            explicit AI re-analysis of a completed report (new analysis
 *                       run, so cached model output is not replayed)
 *
 * Unknown values are rejected by the worker (parseJobMode).
 */

export const THREAT_LIBRARY_JOB_MODES = Object.freeze({
  ANALYZE: 'analyze',
  RETRY: 'retry',
  REFRESH_EXTRACTION: 'refresh_extraction',
  RERUN_AI: 'rerun_ai'
});

/** Every mode the shared URL/PDF worker executes (all share the analysis slot budget). */
export const PIPELINE_JOB_MODES = Object.freeze(Object.values(THREAT_LIBRARY_JOB_MODES));

const PIPELINE_JOB_MODE_SET = new Set(PIPELINE_JOB_MODES);

export class UnknownJobModeError extends Error {
  constructor(value) {
    super(`Unknown Threat Library job mode: ${String(value).slice(0, 40)}`);
    this.name = 'UnknownJobModeError';
    this.code = 'unknown_job_mode';
  }
}

/**
 * @param {unknown} value
 * @returns {'analyze'|'retry'|'refresh_extraction'|'rerun_ai'}
 */
export function parseJobMode(value) {
  const mode = typeof value === 'string' ? value.trim() : '';
  if (!PIPELINE_JOB_MODE_SET.has(mode)) throw new UnknownJobModeError(value);
  return mode;
}

/** Whether a mode may call the configured model / provider. */
export function jobModeInvokesAi(mode) {
  return parseJobMode(mode) !== THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION;
}

/**
 * Report states each maintenance action accepts (analysis_status).
 *  - retry: a failed / cancelled pipeline execution (active states answer
 *    "already running"; orphaned active states are recovered by the route)
 *  - refresh_extraction: a committed review set (review_required) or a
 *    finalized report (ready). A finalized report stays finalized when the
 *    refresh has no review-relevant change; a semantic change returns it to
 *    review_required (resolveRefreshOutcomeStatus)
 *  - rerun_ai: review_required only; rerunning AI on a finalized report would
 *    reopen it without a deterministic reason, so it must be reopened deliberately
 */
export const MAINTENANCE_ALLOWED_STATUSES = Object.freeze({
  [THREAT_LIBRARY_JOB_MODES.RETRY]: Object.freeze(['failed', 'cancelled']),
  [THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION]: Object.freeze(['review_required', 'ready']),
  [THREAT_LIBRARY_JOB_MODES.RERUN_AI]: Object.freeze(['review_required'])
});

const NOT_ALLOWED = Object.freeze({
  [THREAT_LIBRARY_JOB_MODES.RETRY]: {
    code: 'retry_not_applicable',
    message: 'Retry recovers a failed analysis. Use Refresh extraction or Re-run AI analysis on a completed report.'
  },
  [THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION]: {
    code: 'refresh_extraction_not_allowed',
    message: 'Refresh extraction needs a completed report (review required or finalized). Use Retry for a failed analysis.'
  },
  [THREAT_LIBRARY_JOB_MODES.RERUN_AI]: {
    code: 'rerun_ai_not_allowed',
    message: 'Re-run AI analysis needs a report in review. A finalized report is not reopened implicitly; a failed analysis uses Retry.'
  }
});

/**
 * State guard for a maintenance action on a report (no I/O).
 * @param {{ analysis_status?: string|null, source_type?: string|null }|null} report
 * @param {string} mode
 * @returns {{ ok: true } | { ok: false, status: number, code: string, message: string }}
 */
export function evaluateMaintenanceAction(report, mode) {
  const allowed = MAINTENANCE_ALLOWED_STATUSES[mode];
  if (!allowed) throw new UnknownJobModeError(mode);
  if (!report) return { ok: false, status: 404, code: 'not_found', message: 'Report not found' };
  if (report.source_type === 'thib') {
    return { ok: false, status: 400, code: 'thib_not_reanalyzable', message: 'THIB imports do not use the analysis pipeline' };
  }
  const status = String(report.analysis_status || '').toLowerCase();
  if (allowed.includes(status)) return { ok: true };
  return { ok: false, status: 409, ...NOT_ALLOWED[mode], analysis_status: report.analysis_status || null };
}
