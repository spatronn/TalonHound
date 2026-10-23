/**
 * Map pipeline / job stage to the operator checklist.
 * Stages come from analysis_status and job.stage — never fake timers.
 */

export const PROGRESS_CHECKLIST = Object.freeze([
  { key: 'fetching', label: 'Source fetched' },
  { key: 'extracting', label: 'Document extracted' },
  { key: 'candidates', label: 'IOC candidates' },
  { key: 'analyzing', label: 'Analyzing threat context' },
  { key: 'matching', label: 'Matching' },
  { key: 'review_required', label: 'Preparing review' }
]);

const STAGE_RANK = Object.freeze({
  pending: 0,
  queued: 0,
  fetching: 1,
  extracting: 2,
  candidates: 3,
  analyzing: 4,
  matching: 5,
  review_required: 6,
  ready: 7,
  skipped: 7,
  failed: -1
});

// Refresh extraction re-uses the stored document and never runs AI: the
// checklist must not show fetch / AI steps as done.
const REFRESH_SKIPPED_STEPS = new Set(['fetching', 'analyzing']);

function isRefreshMode(report, job) {
  const mode = report?.analysis_progress?.mode || job?.job_type || job?.progress?.mode || null;
  return mode === 'refresh_extraction';
}

export function resolveActiveStage(report, job) {
  const fromJob = String(job?.stage || '').trim().toLowerCase();
  const fromReport = String(report?.analysis_status || '').trim().toLowerCase();
  if (fromJob && fromJob !== 'failed') return fromJob;
  if (fromReport) return fromReport;
  return 'pending';
}

/**
 * @returns {{ key: string, label: string, state: 'done'|'active'|'pending'|'failed' }[]}
 */
export function buildProgressChecklist(report, job) {
  const steps = isRefreshMode(report, job)
    ? PROGRESS_CHECKLIST.filter((item) => !REFRESH_SKIPPED_STEPS.has(item.key))
    : PROGRESS_CHECKLIST;
  const stage = resolveActiveStage(report, job);
  const failed = stage === 'failed' || report?.analysis_status === 'failed' || job?.status === 'failed';
  const failureStage = String(report?.failure_stage || job?.stage || '').toLowerCase();
  const rank = STAGE_RANK[stage] ?? 0;
  const doneThreshold = stage === 'ready' || stage === 'skipped' ? 99 : rank;

  return steps.map((item, idx) => {
    const itemRank = STAGE_RANK[item.key] ?? idx + 1;
    if (failed && failureStage === item.key) {
      return { ...item, state: 'failed' };
    }
    if (failed && STAGE_RANK[failureStage] != null && itemRank < STAGE_RANK[failureStage]) {
      return { ...item, state: 'done' };
    }
    if (failed) {
      return { ...item, state: itemRank < rank ? 'done' : 'pending' };
    }
    if (doneThreshold >= 99 || itemRank < doneThreshold) return { ...item, state: 'done' };
    if (itemRank === doneThreshold) return { ...item, state: 'active' };
    return { ...item, state: 'pending' };
  });
}

/**
 * Automatic-retry note for a report waiting for its scheduled retry, or null.
 * @returns {string|null}
 */
export function describeAutoRetry(report) {
  const status = String(report?.analysis_status || '').toLowerCase();
  const retry = report?.analysis_progress?.auto_retry;
  if (status !== 'pending' || !retry) return null;
  const when = retry.scheduled_for ? new Date(retry.scheduled_for) : null;
  const at = when && !Number.isNaN(when.getTime())
    ? ` at ${when.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`
    : '';
  const reason = retry.reason_code ? ` after ${retry.reason_code}` : '';
  return `Automatic retry ${retry.attempt}/${retry.max_attempts}${reason} scheduled${at}; it resumes from completed chunks.`;
}

/**
 * Live AI-capacity note while an analysis waits for an inference slot, or null.
 * @returns {string|null}
 */
export function describeAiCapacityWait(progress) {
  if (!progress?.ai_capacity_waiting) return null;
  const parts = ['Waiting for AI capacity'];
  if (Number(progress.ai_capacity_position) > 0) parts.push(`position ${Number(progress.ai_capacity_position)}`);
  if (Number(progress.ai_capacity_active) > 0) parts.push(`${Number(progress.ai_capacity_active)} running`);
  return parts.join(' · ');
}

export function isProcessingStatus(report) {
  const status = String(report?.analysis_status || '').toLowerCase();
  if (!status) return true;
  return !['ready', 'skipped', 'review_required', 'failed'].includes(status);
}

export function statusLabel(report) {
  const a = String(report?.analysis_status || '').toLowerCase();
  const i = String(report?.import_status || '').toLowerCase();
  if (a === 'failed') return 'Failed';
  if (a === 'review_required') return 'Needs review';
  if (a === 'ready' || i === 'ready') return 'Ready';
  if (a === 'skipped') return 'Imported (bundle)';
  if (a === 'fetching') return 'Fetching';
  if (a === 'extracting' || a === 'candidates') return 'Extracting';
  if (a === 'analyzing') {
    const p = report?.analysis_progress || {};
    if (p.ai_capacity_waiting) return 'Waiting for AI capacity';
    if (p.analysis_chunks_total && p.current_chunk_index) {
      return `Analyzing ${p.current_chunk_index}/${p.analysis_chunks_total}`;
    }
    if (p.analysis_chunks_total && p.analysis_chunks_completed != null) {
      return `Analyzing ${p.analysis_chunks_completed}/${p.analysis_chunks_total}`;
    }
    return 'Analyzing';
  }
  if (a === 'matching') return 'Matching';
  if (a === 'pending' && report?.analysis_progress?.auto_retry) return 'Retry scheduled';
  if (a === 'pending' && report?.analysis_progress?.interrupted) return 'Queued (resuming)';
  if (a === 'pending') return 'Queued';
  return a || i || 'Unknown';
}
