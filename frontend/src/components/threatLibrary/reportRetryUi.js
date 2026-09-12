/**
 * Pure helpers for Threat Library Retry Analysis UI state sync.
 */

import { isProcessingStatus } from './stages.js';

/**
 * Apply an authoritative Retry API response onto local report/job state.
 * Clears stale failure fields when the response marks analysis active.
 */
export function applyRetryAcceptedState(response) {
  const report = response?.report ? { ...response.report } : null;
  if (!report) return { report: null, job: null, alreadyRunning: false };

  const alreadyRunning = response?.already_running === true
    || response?.code === 'analysis_already_running';

  // Defensive: never keep prior failure as "current" once retry accepted.
  if (isProcessingStatus(report) || alreadyRunning) {
    report.failure_stage = null;
    report.failure_reason = null;
    report.failure_code = null;
    report.failure_details = {};
  }

  const job = response?.job
    ? { ...response.job }
    : response?.job_id
      ? {
        public_id: response.job_id,
        status: 'queued',
        stage: report.analysis_status || 'analyzing',
        progress: report.analysis_progress || {}
      }
      : null;

  return { report, job, alreadyRunning };
}

export function processingSectionTitle(report) {
  const status = String(report?.analysis_status || '').toLowerCase();
  if (status === 'failed') return 'Processing failed';
  if (status === 'ready' || status === 'skipped') return 'Analysis complete';
  if (status === 'review_required') return 'Review required';
  if (status === 'cancelled') return 'Analysis cancelled';
  if (isProcessingStatus(report)) return 'Processing report';
  return 'Processing';
}

export function shouldShowFailedPanel(report) {
  return Boolean(report)
    && String(report.analysis_status || '').toLowerCase() === 'failed'
    && !isProcessingStatus(report);
}

export function shouldShowProcessingPanel(report) {
  return Boolean(report) && isProcessingStatus(report);
}

export function canShowRetryButton(report, { busy = false, canWrite = true } = {}) {
  if (!canWrite || !report) return false;
  if (busy) return false;
  if (isProcessingStatus(report)) return false;
  return String(report.analysis_status || '').toLowerCase() === 'failed';
}

/**
 * Ignore a status poll that still looks like the previous failed attempt
 * while a retry mutation has already moved UI to active (race guard).
 *
 * Prefer comparing updated_at from the accepted retry report; fall back to a
 * short time window after acceptance.
 */
export function shouldIgnoreStaleFailedPoll(currentReport, polledReport, opts = {}) {
  if (!isProcessingStatus(currentReport)) return false;
  if (!polledReport) return false;
  if (String(polledReport.analysis_status || '').toLowerCase() !== 'failed') return false;

  const acceptedUpdatedAt = opts.acceptedUpdatedAt;
  if (acceptedUpdatedAt && polledReport.updated_at) {
    const acceptedMs = new Date(acceptedUpdatedAt).getTime();
    const polledMs = new Date(polledReport.updated_at).getTime();
    if (Number.isFinite(acceptedMs) && Number.isFinite(polledMs) && polledMs < acceptedMs) {
      return true;
    }
  }

  const retryAcceptedAt = opts.retryAcceptedAt;
  if (!retryAcceptedAt) return false;
  const ageMs = Date.now() - Number(retryAcceptedAt);
  return ageMs >= 0 && ageMs < 5000;
}
