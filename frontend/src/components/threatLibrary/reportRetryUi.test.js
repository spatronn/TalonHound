/**
 * Threat Library Retry Analysis UI state sync helpers.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { isProcessingStatus } from './stages.js';
import {
  applyRetryAcceptedState,
  canShowRetryButton,
  processingSectionTitle,
  shouldIgnoreStaleFailedPoll,
  shouldShowFailedPanel,
  shouldShowProcessingPanel
} from './reportRetryUi.js';

test('retry from failed applies analyzing and clears stale error', () => {
  const applied = applyRetryAcceptedState({
    report: {
      analysis_status: 'analyzing',
      failure_code: null,
      failure_reason: null,
      analysis_progress: { stage: 'analyzing', resumed: true }
    },
    job_id: 'job-1',
    resumed: true
  });
  assert.equal(applied.report.analysis_status, 'analyzing');
  assert.equal(applied.report.failure_code, null);
  assert.equal(applied.report.failure_reason, null);
  assert.equal(isProcessingStatus(applied.report), true);
  assert.equal(shouldShowFailedPanel(applied.report), false);
  assert.equal(shouldShowProcessingPanel(applied.report), true);
  assert.equal(processingSectionTitle(applied.report), 'Processing report');
  assert.equal(canShowRetryButton(applied.report, { canWrite: true }), false);
  assert.ok(applied.job);
  assert.equal(applied.job.public_id, 'job-1');
});

test('retry button hidden while busy or processing', () => {
  const failed = { analysis_status: 'failed', failure_code: 'ai_validation' };
  assert.equal(canShowRetryButton(failed, { canWrite: true, busy: false }), true);
  assert.equal(canShowRetryButton(failed, { canWrite: true, busy: true }), false);
  assert.equal(canShowRetryButton({ analysis_status: 'analyzing' }, { canWrite: true }), false);
});

test('stale failed poll ignored briefly after retry accept', () => {
  const current = { analysis_status: 'analyzing', failure_code: null };
  const stale = {
    analysis_status: 'failed',
    failure_code: 'ai_validation',
    updated_at: '2026-09-12T10:00:00.000Z'
  };
  assert.equal(
    shouldIgnoreStaleFailedPoll(current, stale, {
      retryAcceptedAt: Date.now() - 500,
      acceptedUpdatedAt: '2026-09-12T10:00:05.000Z'
    }),
    true
  );
  assert.equal(
    shouldIgnoreStaleFailedPoll(current, stale, {
      retryAcceptedAt: Date.now() - 20_000,
      acceptedUpdatedAt: '2026-09-12T09:59:00.000Z'
    }),
    false
  );
  assert.equal(
    shouldIgnoreStaleFailedPoll(current, { analysis_status: 'matching' }, { retryAcceptedAt: Date.now() }),
    false
  );
});

test('new failure after active run shows failed panel', () => {
  const report = {
    analysis_status: 'failed',
    failure_code: 'ai_output_reference_error',
    failure_reason: 'bad ref'
  };
  assert.equal(shouldShowFailedPanel(report), true);
  assert.equal(shouldShowProcessingPanel(report), false);
  assert.equal(processingSectionTitle(report), 'Processing failed');
  assert.equal(canShowRetryButton(report, { canWrite: true }), true);
});

test('already_running response still clears failure display fields', () => {
  const applied = applyRetryAcceptedState({
    already_running: true,
    code: 'analysis_already_running',
    report: {
      analysis_status: 'analyzing',
      failure_code: 'ai_validation',
      failure_reason: 'old'
    },
    job_id: 'j2'
  });
  assert.equal(applied.alreadyRunning, true);
  assert.equal(applied.report.failure_code, null);
  assert.equal(applied.report.failure_reason, null);
});

test('progress stages remain done before analyzing on resume-shaped report', async () => {
  const { buildProgressChecklist } = await import('./stages.js');
  const items = buildProgressChecklist(
    {
      analysis_status: 'analyzing',
      analysis_progress: { stage: 'analyzing', reused_document: true, reused_candidates: true }
    },
    { status: 'queued', stage: 'analyzing' }
  );
  const byKey = Object.fromEntries(items.map((i) => [i.key, i.state]));
  assert.equal(byKey.fetching, 'done');
  assert.equal(byKey.extracting, 'done');
  assert.equal(byKey.candidates, 'done');
  assert.equal(byKey.analyzing, 'active');
  assert.equal(byKey.matching, 'pending');
});
