/**
 * Preliminary vs. review-ready presentation: the page must never present an
 * intermediate candidate set as the final analyst review set.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REPORT_PHASES,
  REVIEW_NOT_READY_CODE,
  resolveReportPhase,
  canShowReviewTable,
  canFinalize,
  indicatorSectionTitle,
  describeIndicatorCount,
  indicatorListCell,
  describeAnalysisStage,
  describePreliminaryState,
  shouldIgnoreStalePoll,
  shouldRefetchDetail,
  createLatestOnly
} from './reportPhase.js';
import { applyRetryAcceptedState, canShowRetryButton } from './reportRetryUi.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const pageSrc = readFileSync(path.join(here, 'ThreatLibraryReportPage.jsx'), 'utf8');

const analyzing = {
  analysis_status: 'analyzing',
  review_phase: 'preparing',
  candidate_state: 'preliminary',
  raw_candidate_count: 56,
  review_candidate_count: 20,
  updated_at: '2026-09-13T10:00:00Z',
  analysis_progress: { analysis_chunks_total: 3, current_chunk_index: 1 }
};
const matching = { ...analyzing, analysis_status: 'matching', updated_at: '2026-09-13T10:05:00Z', analysis_progress: {} };
const reviewReady = {
  analysis_status: 'review_required',
  review_phase: 'review_ready',
  candidate_state: 'review_ready',
  raw_candidate_count: 56,
  review_candidate_count: 16,
  updated_at: '2026-09-13T10:06:00Z'
};
const finalized = { ...reviewReady, analysis_status: 'ready', review_phase: 'finalized', candidate_state: 'finalized', updated_at: '2026-09-13T11:00:00Z' };
const failed = { analysis_status: 'failed', review_phase: 'failed', raw_candidate_count: 56, review_candidate_count: 20, failure_stage: 'analyzing', updated_at: '2026-09-13T10:03:00Z' };

test('phase comes from the API field and falls back to the identical status mapping', () => {
  assert.equal(resolveReportPhase(analyzing), REPORT_PHASES.PREPARING);
  assert.equal(resolveReportPhase({ analysis_status: 'matching' }), REPORT_PHASES.PREPARING);
  assert.equal(resolveReportPhase({ analysis_status: 'review_required' }), REPORT_PHASES.REVIEW_READY);
  assert.equal(resolveReportPhase({ analysis_status: 'ready' }), REPORT_PHASES.FINALIZED);
  assert.equal(resolveReportPhase({ analysis_status: 'skipped' }), REPORT_PHASES.FINALIZED);
  assert.equal(resolveReportPhase({ analysis_status: 'failed' }), REPORT_PHASES.FAILED);
  // API field wins over a stale status spelling
  assert.equal(resolveReportPhase({ analysis_status: 'weird', review_phase: 'review_ready' }), REPORT_PHASES.REVIEW_READY);
  assert.equal(resolveReportPhase(null), REPORT_PHASES.PREPARING);
});

test('active analysis: preliminary message, raw count labelled preliminary, no review table, no actions', () => {
  assert.equal(canShowReviewTable(analyzing), false);
  assert.equal(canFinalize(analyzing), false);
  assert.equal(indicatorSectionTitle(analyzing), 'Indicators are being refined');
  const state = describePreliminaryState(analyzing, null);
  assert.equal(state.title, 'Analysis in progress');
  assert.equal(state.countText, 'Preliminary observables: 56');
  assert.equal(state.stageLabel, 'Analyzing threat context');
  assert.equal(state.chunkLabel, 'Semantic analysis: 1 / 3');
  assert.ok(state.lines.some((l) => /still being classified and filtered/.test(l)));
  assert.ok(state.lines.some((l) => /may contain fewer indicators/.test(l)));
  assert.ok(state.lines.some((l) => /available when analysis completes/.test(l)));
  // Candidate existence never means review readiness
  assert.equal(canShowReviewTable({ ...analyzing, review_candidate_count: 16, indicator_count: 56 }), false);
  // No implementation jargon in analyst copy
  for (const l of state.lines) assert.doesNotMatch(l, /zod|schema|semantic-v|chunk-00|evidence policy/i);
});

test('loaded rows override the polled raw count on the preliminary card', () => {
  const state = describePreliminaryState(analyzing, null, { rawCount: 44 });
  assert.equal(state.countText, 'Preliminary observables: 44');
  assert.equal(describeIndicatorCount(analyzing).text, 'Preliminary observables: 56');
  assert.equal(describeIndicatorCount({ analysis_status: 'fetching' }).text, 'Preliminary observables: —');
});

test('preparing review (matching) stays non-actionable until the set is committed', () => {
  assert.equal(resolveReportPhase(matching), REPORT_PHASES.PREPARING);
  assert.equal(canShowReviewTable(matching), false);
  assert.equal(canFinalize(matching), false);
  assert.equal(describePreliminaryState(matching, { stage: 'matching', progress: {} }).stageLabel, 'Matching against local IOCs');
  assert.equal(describeAnalysisStage(matching, { stage: 'review_required', progress: {} }).stageLabel, 'Preparing review');
});

test('review ready: Review indicators with the review count, actions and finalize available', () => {
  assert.equal(canShowReviewTable(reviewReady), true);
  assert.equal(canFinalize(reviewReady), true);
  assert.equal(indicatorSectionTitle(reviewReady), 'Review indicators');
  assert.equal(describeIndicatorCount(reviewReady).text, 'Review candidates: 16');
  assert.equal(describeIndicatorCount(reviewReady, { reviewCount: 16 }).label, 'Review candidates');
  assert.notEqual(describeIndicatorCount(reviewReady).label, describeIndicatorCount(analyzing).label, 'preliminary and review counts never share a label');
});

test('finalized: persisted indicators shown normally, finalize no longer offered', () => {
  assert.equal(canShowReviewTable(finalized), true);
  assert.equal(canFinalize(finalized), false);
  assert.equal(indicatorSectionTitle(finalized), 'Indicators');
  assert.equal(describeIndicatorCount(finalized).text, 'Indicators: 16');
  assert.equal(canShowReviewTable({ analysis_status: 'skipped' }), true);
});

test('transition without reload: analyzing → matching → review_required refetches the detail exactly at the phase change', () => {
  assert.equal(shouldRefetchDetail(analyzing, matching), false, 'both preparing: keep polling status only');
  assert.equal(shouldRefetchDetail(matching, reviewReady), true, 'phase changed: fetch the committed review set');
  assert.equal(shouldRefetchDetail(reviewReady, reviewReady), false);
  assert.equal(shouldRefetchDetail(analyzing, failed), true, 'failure is a phase change too');
  assert.equal(shouldRefetchDetail(null, reviewReady), true);
});

test('failure before review: not presented as a review set, retry offered, no finalize', () => {
  assert.equal(canShowReviewTable(failed), false);
  assert.equal(canFinalize(failed), false);
  assert.equal(indicatorSectionTitle(failed), 'Indicators not ready');
  const state = describePreliminaryState(failed, null);
  assert.equal(state.phase, REPORT_PHASES.FAILED);
  assert.match(state.title, /failed before the final indicator set was prepared/);
  assert.ok(state.lines.some((l) => /have not completed semantic review/.test(l)));
  assert.equal(state.countText, 'Preliminary observables: 56');
  assert.equal(canShowRetryButton(failed, { busy: false, canWrite: true }), true);
});

test('retry accepted: page returns to the preparing state immediately, review controls gone', () => {
  const applied = applyRetryAcceptedState({
    report: { ...failed, analysis_status: 'analyzing', review_phase: 'preparing', updated_at: '2026-09-13T10:10:00Z' },
    job_id: 'j1'
  });
  assert.equal(resolveReportPhase(applied.report), REPORT_PHASES.PREPARING);
  assert.equal(canShowReviewTable(applied.report), false);
  assert.equal(canShowRetryButton(applied.report, { canWrite: true }), false);
  assert.equal(applied.report.failure_reason, null);
  // The page clears previous rows on retry so a rebuilt set is never confused with the old one
  assert.match(pageSrc, /const applied = applyRetryAcceptedState\(data\);[\s\S]*?setCandidates\(\[\]\);\s*setSelected\(new Set\(\)\);/);
});

test('stale response race: an older poll or detail response never overwrites the newer report', () => {
  assert.equal(shouldIgnoreStalePoll(reviewReady, analyzing), true, 'analyzing poll issued before review_required arrives late');
  assert.equal(shouldIgnoreStalePoll(analyzing, reviewReady), false);
  assert.equal(shouldIgnoreStalePoll(reviewReady, { ...reviewReady }), false);
  assert.equal(shouldIgnoreStalePoll(null, reviewReady), false);
  assert.equal(shouldIgnoreStalePoll(reviewReady, { analysis_status: 'analyzing' }), false, 'no timestamps: cannot judge');

  const latest = createLatestOnly();
  const preliminaryRequest = latest.next();
  const finalRequest = latest.next();
  assert.equal(latest.isLatest(preliminaryRequest), false, 'preliminary response arriving after the final one is dropped');
  assert.equal(latest.isLatest(finalRequest), true);
  assert.match(pageSrc, /const token = latestDetail\.current\.next\(\);[\s\S]*?if \(!latestDetail\.current\.isLatest\(token\)\) return data;/);
});

test('list page: preliminary counts are labelled, final counts are the review count', () => {
  assert.equal(indicatorListCell(analyzing), '56 preliminary');
  assert.equal(indicatorListCell({ analysis_status: 'fetching', raw_candidate_count: 0 }), 'Analyzing…');
  assert.equal(indicatorListCell(reviewReady), '16');
  assert.equal(indicatorListCell(finalized), '16');
  assert.equal(indicatorListCell(failed), '56 preliminary');
  assert.equal(indicatorListCell({ analysis_status: 'ready', indicator_count: 9 }), '9', 'older API without review count falls back to rows');
});

test('backend rejection is handled as state, not as a generic error', () => {
  assert.equal(REVIEW_NOT_READY_CODE, 'report_not_ready_for_review');
  assert.match(pageSrc, /function applyNotReadyRejection\(err\)[\s\S]*?data\?\.code !== REVIEW_NOT_READY_CODE/);
  assert.match(pageSrc, /if \(!applyNotReadyRejection\(err\)\) setError\(err\?\.response\?\.data\?\.message \|\| 'Review action failed'\)/);
  assert.match(pageSrc, /if \(!applyNotReadyRejection\(err\)\) setError\(err\?\.response\?\.data\?\.message \|\| 'Finalize failed'\)/);
});

test('page structure: review table and actions are gated on the phase, preliminary card carries no actions', () => {
  assert.match(pageSrc, /const showReview = Boolean\(report\) && canShowReviewTable\(report\);/);
  assert.match(pageSrc, /const showPreliminary = Boolean\(report\) && !loading && \(phase === REPORT_PHASES\.PREPARING \|\| phase === REPORT_PHASES\.FAILED\);/);
  assert.match(pageSrc, /\{canWrite && canFinalize\(report\) \? \(/);
  assert.doesNotMatch(pageSrc, /candidates\.length > 0 \? \(\s*<ul/, 'no raw list outside the preliminary card');
  const card = pageSrc.slice(pageSrc.indexOf('function PreliminaryIndicatorsCard'), pageSrc.indexOf('export default function'));
  assert.doesNotMatch(card, /runReview|finalize\(|Approve|Create IOCs/);
  assert.match(card, /Show preliminary observables/);
  assert.match(card, /not final and may be removed, retyped or reclassified/);
  assert.match(card, /aria-busy=\{!failed\}/);
});
