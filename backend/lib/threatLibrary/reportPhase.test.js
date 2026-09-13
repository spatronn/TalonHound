/**
 * Report presentation phase + review/finalize guards.
 *
 * Candidate rows exist from the moment deterministic extraction is persisted
 * (before the AI stage) and are rewritten until `review_required`; the phase,
 * never the row count, decides whether they are a review set.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REPORT_PHASES,
  CANDIDATE_STATES,
  REVIEW_NOT_READY_CODE,
  resolveReportPhase,
  resolveCandidateState,
  isReviewMutationAllowed,
  isFinalizeAllowed,
  reviewNotReadyError
} from './reportPhase.js';
import { applyCandidateReviewActions, finalizeReport } from './reviewService.js';

const here = path.dirname(fileURLToPath(import.meta.url));

test('every persisted analysis_status maps to exactly one presentation phase', () => {
  const expected = {
    pending: 'preparing',
    queued: 'preparing',
    fetching: 'preparing',
    extracting: 'preparing',
    candidates: 'preparing',
    analyzing: 'preparing',
    matching: 'preparing',
    review_required: 'review_ready',
    ready: 'finalized',
    skipped: 'finalized',
    failed: 'failed',
    cancelled: 'failed'
  };
  for (const [status, phase] of Object.entries(expected)) {
    assert.equal(resolveReportPhase({ analysis_status: status }), phase, status);
  }
  assert.equal(resolveReportPhase({ analysis_status: '' }), REPORT_PHASES.PREPARING);
  assert.equal(resolveReportPhase(null), REPORT_PHASES.PREPARING);
});

test('candidate state: rows are preliminary while preparing and after failure, never review-ready by count', () => {
  assert.equal(resolveCandidateState({ analysis_status: 'analyzing', indicator_count: 56 }), CANDIDATE_STATES.PRELIMINARY);
  assert.equal(resolveCandidateState({ analysis_status: 'matching', indicator_count: 56 }), CANDIDATE_STATES.PRELIMINARY);
  assert.equal(resolveCandidateState({ analysis_status: 'failed', indicator_count: 56 }), CANDIDATE_STATES.PRELIMINARY);
  assert.equal(resolveCandidateState({ analysis_status: 'review_required', indicator_count: 16 }), CANDIDATE_STATES.REVIEW_READY);
  assert.equal(resolveCandidateState({ analysis_status: 'ready' }), CANDIDATE_STATES.FINALIZED);
  assert.equal(resolveCandidateState({ analysis_status: 'skipped' }), CANDIDATE_STATES.FINALIZED);
});

test('review mutations and finalize are allowed only on a committed review set', () => {
  for (const status of ['pending', 'fetching', 'extracting', 'analyzing', 'matching', 'failed']) {
    assert.equal(isReviewMutationAllowed({ analysis_status: status }), false, status);
    assert.equal(isFinalizeAllowed({ analysis_status: status }), false, status);
  }
  for (const status of ['review_required', 'ready', 'skipped']) {
    assert.equal(isReviewMutationAllowed({ analysis_status: status }), true, status);
    assert.equal(isFinalizeAllowed({ analysis_status: status }), true, status);
  }
  const err = reviewNotReadyError({ analysis_status: 'analyzing' });
  assert.equal(err.ok, false);
  assert.equal(err.status, 409);
  assert.equal(err.code, REVIEW_NOT_READY_CODE);
  assert.match(err.error, /still being refined/);
  assert.match(reviewNotReadyError({ analysis_status: 'failed' }).error, /Retry analysis/);
});

/** Fake pool: lookups return rows; UPDATE/INSERT/DELETE are recorded as writes. */
function fakePool(report, candidates = []) {
  const writes = [];
  return {
    writes,
    async query(sql, params) {
      if (/FROM threat_reports WHERE id = \$1/.test(sql) && /^\s*SELECT/i.test(sql)) {
        return { rows: report ? [report] : [] };
      }
      if (/FROM threat_report_candidates/.test(sql) && /^\s*SELECT/i.test(sql)) {
        return { rows: candidates };
      }
      writes.push({ sql, params });
      return { rows: [] };
    }
  };
}

test('backend guard: review actions on an analyzing report are rejected without touching rows', async () => {
  const pool = fakePool({ id: 6, analysis_status: 'analyzing' });
  const result = await applyCandidateReviewActions(pool, 6, { action: 'approve', candidateIds: [1, 2] });
  assert.equal(result.ok, false);
  assert.equal(result.status, 409);
  assert.equal(result.code, REVIEW_NOT_READY_CODE);
  assert.equal(pool.writes.length, 0, 'no UPDATE/SELECT beyond the report lookup');

  const bulk = await applyCandidateReviewActions(fakePool({ id: 6, analysis_status: 'matching' }), 6, { action: 'approve_high_confidence_malicious' });
  assert.equal(bulk.code, REVIEW_NOT_READY_CODE);

  const failed = await applyCandidateReviewActions(fakePool({ id: 6, analysis_status: 'failed' }), 6, { action: 'create_iocs', candidateIds: [1] });
  assert.equal(failed.code, REVIEW_NOT_READY_CODE);
});

test('backend guard: finalize is rejected while preparing or failed, accepted when review-ready', async () => {
  for (const status of ['analyzing', 'matching', 'failed']) {
    const pool = fakePool({ id: 6, analysis_status: status });
    const result = await finalizeReport(pool, 6);
    assert.equal(result.ok, false, status);
    assert.equal(result.code, REVIEW_NOT_READY_CODE, status);
    assert.equal(pool.writes.length, 0, status);
  }
  const pool = fakePool({ id: 6, analysis_status: 'review_required' });
  const result = await finalizeReport(pool, 6);
  assert.equal(result.ok, true);
  assert.equal(pool.writes.length, 1, 'status update issued');
  assert.match(pool.writes[0].sql, /UPDATE threat_reports/);
});

test('review-ready report accepts an approve action', async () => {
  const pool = fakePool({ id: 6, analysis_status: 'review_required' });
  const result = await applyCandidateReviewActions(pool, 6, { action: 'approve', candidateIds: [1, 2] });
  assert.equal(result.ok, true);
  assert.ok(pool.writes.some((w) => /review_status = 'approved'/.test(w.sql)));
});

test('routes surface the phase and both counts, and return the guard code', () => {
  const routeSrc = readFileSync(path.join(here, '..', '..', 'routes', 'threatLibrary.js'), 'utf8');
  assert.match(routeSrc, /review_phase: resolveReportPhase\(row\)/);
  assert.match(routeSrc, /candidate_state: resolveCandidateState\(row\)/);
  assert.match(routeSrc, /raw_candidate_count: row\.indicator_count/);
  assert.match(routeSrc, /review_candidate_count: row\.review_candidate_count/);
  // finalize route no longer ignores the service result
  assert.match(routeSrc, /const result = await finalizeReport\(pool, report\.id\);\s*if \(!result\.ok\)/);
  assert.match(routeSrc, /code: result\.code \|\| null/);
  // status + detail responses carry counts for the preliminary card
  assert.match(routeSrc, /report: publicReport\(await attachReportCounts\(pool, report\)\),\s*job: jobs\[0\]/);
});
