/**
 * Retry analysis: decide active stage before enqueue so UI can leave failed immediately.
 */

const TERMINAL_ANALYSIS = new Set(['ready', 'skipped', 'review_required', 'failed']);

export function isActiveAnalysisStatus(status) {
  const s = String(status || '').toLowerCase();
  if (!s) return false;
  return !TERMINAL_ANALYSIS.has(s);
}

const ENDED_JOB_STATUSES = new Set(['failed', 'cancelled']);

/**
 * An "active" analysis status left behind by a job that already ended: the
 * report still carries that job's failure while no job is queued or running
 * (a late progress write overwrote the terminal status). Retry must recover
 * it instead of answering "already running".
 *
 * Race-free without timing heuristics: every legitimate transition to an
 * active status (Retry, pipeline stages) clears `failure_code` in the same
 * UPDATE, so a concurrent Retry that just claimed the report is never seen
 * as orphaned.
 * @param {{
 *   report: { analysis_status?: string|null, failure_code?: string|null },
 *   activeJob?: object|null,
 *   latestJob?: { status?: string|null }|null
 * }} input
 */
export function isOrphanedActiveAnalysis({ report, activeJob = null, latestJob = null } = {}) {
  if (!report || !isActiveAnalysisStatus(report.analysis_status)) return false;
  if (activeJob) return false;
  if (!report.failure_code) return false;
  return Boolean(latestJob && ENDED_JOB_STATUSES.has(String(latestJob.status || '').toLowerCase()));
}

/**
 * Prefer AI-stage resume when document + candidates already exist (Retry Analysis contract).
 * @param {{ hasDocument?: boolean, candidateCount?: number }} opts
 */
export function resolveRetryStartStatus(opts = {}) {
  const hasDocument = opts.hasDocument === true;
  const candidateCount = Number(opts.candidateCount) || 0;
  if (hasDocument && candidateCount > 0) return 'analyzing';
  if (hasDocument) return 'extracting';
  return 'pending';
}

/**
 * Progress payload for an accepted retry — keeps earlier stages visually complete.
 */
export function buildRetryProgress(analysisStatus, carry = {}) {
  const stage = String(analysisStatus || 'pending');
  const preserved = {};
  if (carry.candidate_extraction_version) {
    preserved.candidate_extraction_version = carry.candidate_extraction_version;
  }
  const base = { stage, resumed: true, analysis_chunks_completed: 0, ...preserved };
  if (stage === 'analyzing') {
    return {
      ...base,
      reused_document: true,
      reused_candidates: true,
      analysis_chunks_total: null
    };
  }
  if (stage === 'extracting') {
    return { ...base, reused_document: true };
  }
  return base;
}
