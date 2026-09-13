/**
 * Report presentation phase — the single mapping from the persisted
 * `analysis_status` to what the candidate rows currently mean.
 *
 *   preparing    pending / fetching / extracting / analyzing / matching:
 *                rows are the deterministic extraction (or a previous run) and
 *                are still being classified, filtered and re-matched
 *   review_ready review_required: the resolved candidate set is committed and
 *                analyst review actions may mutate it
 *   finalized    ready / skipped: persisted final intelligence
 *   failed       failed (incl. cancelled): rows are whatever the last stage
 *                left behind — never a review set
 *
 * Candidate existence never implies review readiness; only the phase does.
 * The frontend mirrors this mapping (reportPhase.js) but prefers the
 * `candidate_state` / `review_phase` fields the API derives from here.
 */

export const REPORT_PHASES = Object.freeze({
  PREPARING: 'preparing',
  REVIEW_READY: 'review_ready',
  FINALIZED: 'finalized',
  FAILED: 'failed'
});

export const CANDIDATE_STATES = Object.freeze({
  PRELIMINARY: 'preliminary',
  REVIEW_READY: 'review_ready',
  FINALIZED: 'finalized'
});

export const REVIEW_NOT_READY_CODE = 'report_not_ready_for_review';

/**
 * @param {{ analysis_status?: string|null }|null|undefined} report
 * @returns {'preparing'|'review_ready'|'finalized'|'failed'}
 */
export function resolveReportPhase(report) {
  const status = String(report?.analysis_status || '').trim().toLowerCase();
  if (status === 'failed' || status === 'cancelled') return REPORT_PHASES.FAILED;
  if (status === 'review_required') return REPORT_PHASES.REVIEW_READY;
  if (status === 'ready' || status === 'skipped') return REPORT_PHASES.FINALIZED;
  return REPORT_PHASES.PREPARING;
}

/**
 * What the candidate rows of a report are right now.
 * @param {object} report
 * @returns {'preliminary'|'review_ready'|'finalized'}
 */
export function resolveCandidateState(report) {
  const phase = resolveReportPhase(report);
  if (phase === REPORT_PHASES.REVIEW_READY) return CANDIDATE_STATES.REVIEW_READY;
  if (phase === REPORT_PHASES.FINALIZED) return CANDIDATE_STATES.FINALIZED;
  return CANDIDATE_STATES.PRELIMINARY;
}

/** Review actions (approve / context only / ignore / create IOCs) need a stable set. */
export function isReviewMutationAllowed(report) {
  const phase = resolveReportPhase(report);
  return phase === REPORT_PHASES.REVIEW_READY || phase === REPORT_PHASES.FINALIZED;
}

/** Finalize needs a committed review set (idempotent on an already finalized report). */
export function isFinalizeAllowed(report) {
  return isReviewMutationAllowed(report);
}

/**
 * Controlled rejection payload for mutations on a moving candidate set.
 * @param {object} report
 */
export function reviewNotReadyError(report) {
  const phase = resolveReportPhase(report);
  const message =
    phase === REPORT_PHASES.FAILED
      ? 'Analysis failed before the final indicator set was prepared. Retry analysis before reviewing.'
      : 'The indicator set is still being refined. Review actions are available once analysis completes.';
  return {
    ok: false,
    status: 409,
    code: REVIEW_NOT_READY_CODE,
    error: message,
    phase,
    analysis_status: report?.analysis_status || null
  };
}
