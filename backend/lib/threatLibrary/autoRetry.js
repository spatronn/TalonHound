/**
 * Bounded automatic retry of transient AI analysis failures.
 *
 * Safe because a failed AI stage has written nothing irreversible:
 *  - deterministic candidates were reconciled before the AI stage and are
 *    reused by identity (pipeline.decideCandidateReuse);
 *  - completed semantic chunks are checkpointed per analysis run and reused;
 *  - matching, candidate reconcile and entity/relationship writes happen only
 *    after the AI stage succeeds, and the report is never finalized by a job.
 *
 * Bounded: only isTransientAiFailure codes, at most auto_retry_max_attempts
 * consecutive automatic attempts (a manual Retry starts a new sequence),
 * exponential backoff with jitter, one live pipeline job per report
 * (createExclusivePipelineJob), and every attempt still waits for AI
 * capacity through the shared scheduler — retries cannot storm the provider.
 */

import { isTransientAiFailure, resolveAiTimeoutPolicy } from './ai/timeouts.js';
import { createExclusivePipelineJob } from './analysisConcurrency.js';
import { THREAT_LIBRARY_JOB_MODES } from './jobModes.js';
import { buildRetryProgress } from './retryState.js';
import { getAiSettings, getReportById, updateJob, updateReportStatus } from './store.js';
import { createServiceLogger } from '../appLogger.js';

const log = createServiceLogger('threat-library-auto-retry');

export const AUTO_RETRY_BASE_DELAY_MS = 60_000;
export const AUTO_RETRY_MAX_DELAY_MS = 15 * 60_000;
export const AUTO_RETRY_JITTER_RATIO = 0.25;

const AI_JOB_MODES = new Set([
  THREAT_LIBRARY_JOB_MODES.ANALYZE,
  THREAT_LIBRARY_JOB_MODES.RETRY,
  THREAT_LIBRARY_JOB_MODES.RERUN_AI
]);

/**
 * @param {number} attempt 1-based
 * @param {() => number} [random]
 */
export function autoRetryDelayMs(attempt, random = Math.random) {
  const n = Math.max(1, Math.trunc(Number(attempt) || 1));
  const base = Math.min(AUTO_RETRY_MAX_DELAY_MS, AUTO_RETRY_BASE_DELAY_MS * 2 ** (n - 1));
  return Math.round(base + base * AUTO_RETRY_JITTER_RATIO * random());
}

/**
 * @param {{ jobType: string, code: string|null, httpStatus?: number|null, previousAttempt?: number, maxAttempts: number }} input
 */
export function decideAutoRetry({ jobType, code, httpStatus = null, previousAttempt = 0, maxAttempts }) {
  if (!AI_JOB_MODES.has(jobType)) return { retry: false, reason: 'job_mode_not_retryable' };
  if (!isTransientAiFailure(code, httpStatus)) return { retry: false, reason: 'not_transient' };
  const attempt = (Number(previousAttempt) || 0) + 1;
  if (attempt > (Number(maxAttempts) || 0)) return { retry: false, reason: 'attempts_exhausted', attempt: attempt - 1 };
  return { retry: true, attempt };
}

/**
 * Called by the worker after an analysis job returned { ok: false }.
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, jobType: string, jobPayload?: object|null, result: { code?: string, http_status?: number|null } }} input
 * @param {{ random?: () => number, now?: () => number }} [deps]
 */
export async function maybeScheduleAutoRetry(pool, input, deps = {}) {
  const settings = await getAiSettings(pool);
  const policy = resolveAiTimeoutPolicy(settings || {});
  const previousAttempt = Number(input.jobPayload?.auto_retry?.attempt) || 0;
  const decision = decideAutoRetry({
    jobType: input.jobType,
    code: input.result?.code || null,
    httpStatus: input.result?.http_status ?? null,
    previousAttempt,
    maxAttempts: policy.auto_retry_max_attempts
  });
  if (!decision.retry) {
    if (decision.reason === 'attempts_exhausted') {
      log.warn('automatic retries exhausted', { reportId: input.reportId, jobId: input.jobId, code: input.result?.code, attempts: decision.attempt });
    }
    return { scheduled: false, ...decision };
  }

  const report = await getReportById(pool, input.reportId);
  // Only a report this job left failed is retried (not cancelled / deleted / re-run meanwhile).
  if (!report || report.deleted_at || report.analysis_status !== 'failed' || report.cancel_requested_at) {
    return { scheduled: false, reason: 'report_state_changed' };
  }

  const now = (deps.now || Date.now)();
  const delayMs = autoRetryDelayMs(decision.attempt, deps.random);
  const notBefore = new Date(now + delayMs);
  const autoRetry = {
    attempt: decision.attempt,
    max_attempts: policy.auto_retry_max_attempts,
    reason_code: input.result?.code || null,
    failed_job_id: input.jobId,
    scheduled_for: notBefore.toISOString()
  };
  const { created, job } = await createExclusivePipelineJob(pool, {
    reportId: report.id,
    jobType: THREAT_LIBRARY_JOB_MODES.RETRY,
    requestedBy: null,
    jobPayload: { auto_retry: autoRetry },
    notBefore
  });
  if (!created) return { scheduled: false, reason: 'job_already_active', jobId: job?.id };

  // Same contract as a manual Retry: the extraction version is carried so the
  // stored candidates and completed chunk checkpoints are reused.
  const progress = {
    ...buildRetryProgress('pending', {
      candidate_extraction_version: report.analysis_progress?.candidate_extraction_version || null
    }),
    extraction_diagnostics: report.analysis_progress?.extraction_diagnostics || undefined,
    auto_retry: autoRetry
  };
  await updateJob(pool, job.id, {
    status: 'queued',
    stage: 'queued',
    progress: {
      ...progress,
      dispatch: {
        jobType: THREAT_LIBRARY_JOB_MODES.RETRY,
        sourceUrl: report.source_url || undefined,
        resumeAnalysis: true,
        jobPayload: { auto_retry: autoRetry }
      }
    }
  });
  // The failure stays on the report (failure_code / details) so the UI can
  // say why the retry is pending; the status leaves "failed".
  await updateReportStatus(pool, report.id, {
    analysis_status: 'pending',
    import_status: 'processing',
    analysis_progress: progress
  });
  log.info('automatic retry scheduled', {
    reportId: report.id,
    failedJobId: input.jobId,
    retryJobId: job.id,
    attempt: decision.attempt,
    max_attempts: policy.auto_retry_max_attempts,
    code: input.result?.code,
    delay_ms: delayMs
  });
  return { scheduled: true, attempt: decision.attempt, jobId: job.id, notBefore };
}
