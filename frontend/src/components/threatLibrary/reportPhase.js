/**
 * Report presentation phase for the Threat Library detail / list pages.
 *
 * The backend derives `review_phase` / `candidate_state` from the persisted
 * analysis_status (backend/lib/threatLibrary/reportPhase.js); this module
 * prefers those fields and falls back to the identical mapping for older
 * responses. Candidate rows exist before the AI stage and are rewritten until
 * `review_required`, so the phase — never the row count — decides whether the
 * page shows an actionable Review Indicators table.
 */

import { isProcessingStatus, statusLabel } from './stages.js';

export const REPORT_PHASES = Object.freeze({
  PREPARING: 'preparing',
  REVIEW_READY: 'review_ready',
  FINALIZED: 'finalized',
  FAILED: 'failed'
});

const PHASE_VALUES = new Set(Object.values(REPORT_PHASES));

export const REVIEW_NOT_READY_CODE = 'report_not_ready_for_review';

/**
 * @param {object|null|undefined} report
 * @returns {'preparing'|'review_ready'|'finalized'|'failed'}
 */
export function resolveReportPhase(report) {
  const fromApi = String(report?.review_phase || '').toLowerCase();
  if (PHASE_VALUES.has(fromApi)) return fromApi;
  const status = String(report?.analysis_status || '').trim().toLowerCase();
  if (status === 'failed' || status === 'cancelled') return REPORT_PHASES.FAILED;
  if (status === 'review_required') return REPORT_PHASES.REVIEW_READY;
  if (status === 'ready' || status === 'skipped') return REPORT_PHASES.FINALIZED;
  return REPORT_PHASES.PREPARING;
}

export function isReviewReady(report) {
  return resolveReportPhase(report) === REPORT_PHASES.REVIEW_READY;
}

/** Review table + review actions render only on a committed candidate set. */
export function canShowReviewTable(report) {
  const phase = resolveReportPhase(report);
  return phase === REPORT_PHASES.REVIEW_READY || phase === REPORT_PHASES.FINALIZED;
}

/** Finalize is offered only while the report awaits review. */
export function canFinalize(report) {
  return resolveReportPhase(report) === REPORT_PHASES.REVIEW_READY;
}

/** Section title for the indicator area, by phase — never the same label for different meanings. */
export function indicatorSectionTitle(report) {
  const phase = resolveReportPhase(report);
  if (phase === REPORT_PHASES.REVIEW_READY) return 'Review indicators';
  if (phase === REPORT_PHASES.FINALIZED) return 'Indicators';
  if (phase === REPORT_PHASES.FAILED) return 'Indicators not ready';
  return 'Indicators are being refined';
}

/**
 * Count label for the indicator area / metadata / list page.
 * @param {object} report
 * @param {{ reviewCount?: number|null, rawCount?: number|null }} [counts] overrides from loaded rows
 * @returns {{ label: string, value: number|null, text: string }}
 */
export function describeIndicatorCount(report, counts = {}) {
  const phase = resolveReportPhase(report);
  const raw = counts.rawCount ?? report?.raw_candidate_count ?? report?.indicator_count ?? null;
  const review = counts.reviewCount ?? report?.review_candidate_count ?? null;
  if (phase === REPORT_PHASES.PREPARING || phase === REPORT_PHASES.FAILED) {
    const value = raw == null ? null : Number(raw);
    return {
      label: 'Preliminary observables',
      value,
      text: value == null ? 'Preliminary observables: —' : `Preliminary observables: ${value}`
    };
  }
  const value = review == null ? (raw == null ? null : Number(raw)) : Number(review);
  const label = phase === REPORT_PHASES.FINALIZED ? 'Indicators' : 'Review candidates';
  return { label, value, text: value == null ? `${label}: —` : `${label}: ${value}` };
}

/** Compact list-page cell: never presents a preliminary count as a stable total. */
export function indicatorListCell(report) {
  const phase = resolveReportPhase(report);
  const raw = report?.raw_candidate_count ?? report?.indicator_count ?? null;
  const review = report?.review_candidate_count ?? null;
  if (phase === REPORT_PHASES.PREPARING) {
    if (raw == null || Number(raw) === 0) return 'Analyzing…';
    return `${Number(raw)} preliminary`;
  }
  if (phase === REPORT_PHASES.FAILED) {
    return raw == null || Number(raw) === 0 ? '—' : `${Number(raw)} preliminary`;
  }
  const value = review == null ? raw : review;
  return value == null ? '0' : String(Number(value));
}

/**
 * Human stage line for the preliminary card (no fake percentages).
 * @param {object} report
 * @param {object|null} job
 */
export function describeAnalysisStage(report, job) {
  const stage = String(job?.stage || report?.analysis_status || '').toLowerCase();
  const progress = report?.analysis_progress || job?.progress || {};
  const stageLabel = {
    pending: 'Queued',
    queued: 'Queued',
    fetching: 'Fetching source',
    extracting: 'Extracting document',
    candidates: 'Detecting IOC candidates',
    analyzing: 'Analyzing threat context',
    matching: 'Matching against local IOCs',
    review_required: 'Preparing review'
  }[stage] || statusLabel(report);
  let chunkLabel = null;
  const total = Number(progress.analysis_chunks_total);
  if (Number.isFinite(total) && total > 0) {
    const current = Number(progress.current_chunk_index);
    const done = Number(progress.analysis_chunks_completed);
    if (Number.isFinite(current) && current > 0) chunkLabel = `Semantic analysis: ${Math.min(current, total)} / ${total}`;
    else if (Number.isFinite(done)) chunkLabel = `Semantic analysis: ${Math.min(done, total)} / ${total}`;
  }
  return { stage, stageLabel, chunkLabel };
}

/**
 * Copy for the preliminary (preparing / failed) indicator card.
 * @param {object} report
 * @param {object|null} job
 * @param {{ rawCount?: number|null }} [counts]
 */
export function describePreliminaryState(report, job, counts = {}) {
  const phase = resolveReportPhase(report);
  const count = describeIndicatorCount(report, counts);
  const stage = describeAnalysisStage(report, job);
  if (phase === REPORT_PHASES.FAILED) {
    return {
      phase,
      title: 'Analysis failed before the final indicator set was prepared',
      lines: [
        'Preliminary observables were detected, but they have not completed semantic review.',
        count.text
      ],
      countText: count.text,
      stageLabel: null,
      chunkLabel: null
    };
  }
  const lines = [
    'Detected observables are still being classified and filtered. The final review set may contain fewer indicators.',
    count.text,
    `Current stage: ${stage.stageLabel}`
  ];
  if (stage.chunkLabel) lines.push(stage.chunkLabel);
  lines.push('The final review set will be available when analysis completes.');
  return {
    phase,
    title: 'Analysis in progress',
    lines,
    countText: count.text,
    stageLabel: stage.stageLabel,
    chunkLabel: stage.chunkLabel
  };
}

/**
 * A status poll that is older than the report already on screen (retry
 * accepted at T1, poll issued at T0 arriving later) must not roll the UI back.
 */
export function shouldIgnoreStalePoll(currentReport, polledReport) {
  if (!currentReport || !polledReport) return false;
  const cur = new Date(currentReport.updated_at || 0).getTime();
  const next = new Date(polledReport.updated_at || 0).getTime();
  if (!Number.isFinite(cur) || !Number.isFinite(next) || !cur || !next) return false;
  return next < cur;
}

/**
 * The full detail (candidate rows) is re-fetched when polling shows the report
 * left the preparing phase, or when the phase changed between two polls.
 */
export function shouldRefetchDetail(prevReport, nextReport) {
  if (!nextReport) return false;
  const prevPhase = prevReport ? resolveReportPhase(prevReport) : null;
  const nextPhase = resolveReportPhase(nextReport);
  if (prevPhase !== nextPhase) return true;
  return !isProcessingStatus(nextReport) && Boolean(prevReport && isProcessingStatus(prevReport));
}

/**
 * Latest-response-wins guard for overlapping detail fetches: a preliminary
 * response issued before the review-ready one must never overwrite it.
 */
export function createLatestOnly() {
  let seq = 0;
  return {
    next() {
      seq += 1;
      return seq;
    },
    isLatest(token) {
      return token === seq;
    }
  };
}
