/**
 * Pure helpers for Threat Library Retry Analysis UI state sync and the
 * report maintenance actions (Refresh extraction / Re-run AI analysis).
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
  if (isRefreshExtractionInProgress(report, null)) return 'Refreshing extraction';
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

/*
 * Report maintenance actions (overflow menu). Three distinct operations:
 *   Retry analysis      failure recovery (failed reports only; see above)
 *   Refresh extraction  deterministic re-extraction + IOC matching; never AI
 *   Re-run AI analysis  explicit model re-analysis of a report in review
 * Visibility mirrors the backend guards in lib/threatLibrary/jobModes.js.
 */

export const MAINTENANCE_MODES = Object.freeze({
  REFRESH_EXTRACTION: 'refresh_extraction',
  RERUN_AI: 'rerun_ai'
});

const REFRESH_STATUSES = new Set(['review_required', 'ready']);

function maintenanceBase(report, { busy = false, canWrite = true } = {}) {
  if (!canWrite || !report || busy) return false;
  if (report.source_type === 'thib') return false;
  return !isProcessingStatus(report);
}

/** Refresh extraction: a committed review set or a finalized report (stays finalized). */
export function canShowRefreshExtraction(report, opts = {}) {
  if (!maintenanceBase(report, opts)) return false;
  return REFRESH_STATUSES.has(String(report.analysis_status || '').toLowerCase());
}

/** Re-run AI analysis: reports in review only — a finalized report is never reopened implicitly. */
export function canShowRerunAi(report, opts = {}) {
  if (!maintenanceBase(report, opts)) return false;
  return String(report.analysis_status || '').toLowerCase() === 'review_required';
}

export const REFRESH_EXTRACTION_CONFIRM = Object.freeze({
  title: 'Refresh extraction?',
  description: 'Re-runs deterministic extraction and IOC matching using the current extractor. AI analysis will not run.',
  detail: 'Review decisions on indicators that are still extracted are kept. Tags, entities, relationships and the summary are not changed.',
  confirmLabel: 'Refresh extraction',
  cancelLabel: 'Cancel'
});

export const RERUN_AI_CONFIRM = Object.freeze({
  title: 'Re-run AI analysis?',
  description: 'Runs AI analysis again and may change classifications, entities, tags, and relationships.',
  confirmLabel: 'Re-run AI analysis',
  cancelLabel: 'Cancel'
});

export function describeMaintenanceAccepted(mode) {
  if (mode === MAINTENANCE_MODES.REFRESH_EXTRACTION) return 'Refreshing extraction. AI analysis will not run.';
  if (mode === MAINTENANCE_MODES.RERUN_AI) return 'AI analysis queued. Showing live progress.';
  return 'Analysis queued.';
}

/** The running / last job is a deterministic refresh (report progress or job row). */
export function isRefreshExtractionInProgress(report, job) {
  const mode = report?.analysis_progress?.mode || job?.job_type || job?.progress?.mode || null;
  return mode === MAINTENANCE_MODES.REFRESH_EXTRACTION && isProcessingStatus(report);
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/**
 * Feedback once a maintenance job has finished (job row from status/detail).
 * @returns {{ message?: string, error?: string }|null}
 */
export function describeMaintenanceOutcome(job) {
  if (!job || job.job_type !== MAINTENANCE_MODES.REFRESH_EXTRACTION) return null;
  const status = String(job.status || '').toLowerCase();
  if (status === 'failed') {
    return { error: `Refresh extraction failed: ${job.error_message || 'unknown error'}. The report was not changed.` };
  }
  if (status !== 'completed') return null;
  const r = job.progress?.refresh || {};
  const added = Number(r.added) || 0;
  const removed = Number(r.removed) || 0;
  const updated = Number(r.updated) || 0;
  if (!added && !removed && !updated) return { message: 'Extraction refreshed. No indicator changes.' };
  const parts = [];
  if (added) parts.push(`${plural(added, 'indicator')} added`);
  if (removed) parts.push(`${plural(removed, 'indicator')} removed`);
  if (updated) parts.push(`${plural(updated, 'indicator')} updated`);
  return { message: `Extraction refreshed: ${parts.join(', ')}.` };
}
