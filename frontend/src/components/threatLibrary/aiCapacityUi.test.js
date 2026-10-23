import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { statusLabel, describeAiCapacityWait, describeAutoRetry } from './stages.js';
import { describeAnalysisStage } from './reportPhase.js';
import { describeAnalysisFailureDetail } from './candidateReview.js';

test('waiting for an AI slot is labelled as capacity, not as a slow or loading model', () => {
  const report = {
    analysis_status: 'analyzing',
    analysis_progress: { ai_capacity_waiting: true, ai_capacity_position: 2, ai_capacity_active: 1, analysis_chunks_total: 4, current_chunk_index: 2 }
  };
  assert.equal(statusLabel(report), 'Waiting for AI capacity');
  assert.equal(describeAnalysisStage(report, null).stageLabel, 'Waiting for AI capacity');
  assert.equal(describeAiCapacityWait(report.analysis_progress), 'Waiting for AI capacity · position 2 · 1 running');
  // Once the slot is granted the normal chunk label returns.
  const running = { ...report, analysis_progress: { ...report.analysis_progress, ai_capacity_waiting: false } };
  assert.equal(statusLabel(running), 'Analyzing 2/4');
  assert.equal(describeAiCapacityWait(running.analysis_progress), null);
});

test('a scheduled automatic retry and a shutdown requeue are distinct from a fresh import', () => {
  const retry = {
    analysis_status: 'pending',
    failure_code: 'first_token_timeout',
    analysis_progress: { auto_retry: { attempt: 1, max_attempts: 2, reason_code: 'first_token_timeout', scheduled_for: '2026-10-23T18:00:00Z' } }
  };
  assert.equal(statusLabel(retry), 'Retry scheduled');
  assert.match(describeAutoRetry(retry), /^Automatic retry 1\/2 after first_token_timeout scheduled at .+; it resumes from completed chunks\.$/);
  assert.equal(statusLabel({ analysis_status: 'pending', analysis_progress: { interrupted: { reason: 'worker_shutdown' } } }), 'Queued (resuming)');
  assert.equal(statusLabel({ analysis_status: 'pending', analysis_progress: {} }), 'Queued');
  assert.equal(describeAutoRetry({ analysis_status: 'failed', analysis_progress: retry.analysis_progress }), null);
});

test('failure detail separates active analysis time from AI capacity wait and explains the code', () => {
  const lines = describeAnalysisFailureDetail({
    failure_code: 'ai_capacity_wait_timeout',
    failure_details: {
      progress: {
        analysis_chunks_total: 4,
        analysis_chunks_completed: 1,
        ai_calls: 2,
        elapsed_ms: 534000,
        active_elapsed_ms: 234000,
        ai_capacity_wait_ms: 300000,
        total_analysis_timeout_ms: 1800000
      }
    }
  });
  assert.ok(lines.includes('Active analysis 3.9 min of 30 min ceiling'));
  assert.ok(lines.includes('Waited 5 min for AI capacity (not counted against the ceiling)'));
  assert.ok(lines.some((l) => /Other analyses kept the AI provider busy/.test(l)));
  assert.ok(lines.includes('Retry Analysis will resume from completed checkpoints.'));
});

test('first_token_timeout detail no longer claims the model may still be loading', () => {
  const lines = describeAnalysisFailureDetail({ failure_code: 'first_token_timeout', failure_details: {} });
  assert.ok(lines.every((l) => !/loading/i.test(l)));
  assert.ok(lines.some((l) => /produced no output in time/.test(l)));
});

test('AI settings expose the provider capacity, capacity wait, execution limit and automatic retries', () => {
  const src = readFileSync(new URL('./ThreatLibraryAiSettings.jsx', import.meta.url), 'utf8');
  for (const field of ['max_concurrent_ai_requests', 'capacity_wait_timeout_ms', 'provider_execution_timeout_ms', 'auto_retry_max_attempts']) {
    assert.match(src, new RegExp(`setField\\('${field}'`), field);
  }
  assert.doesNotMatch(src, /Allows local model load time before the first token/);
});
