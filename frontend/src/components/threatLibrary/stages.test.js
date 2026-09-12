/**
 * Frontend Threat Library progress label helpers.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { statusLabel, buildProgressChecklist } from './stages.js';

test('analyzing status shows chunk progress when available', () => {
  const label = statusLabel({
    analysis_status: 'analyzing',
    analysis_progress: { analysis_chunks_total: 8, current_chunk_index: 3 }
  });
  assert.equal(label, 'Analyzing 3/8');
});

test('failed analyzing stage marks prior stages done', () => {
  const items = buildProgressChecklist(
    { analysis_status: 'failed', failure_stage: 'analyzing' },
    { status: 'failed', stage: 'analyzing' }
  );
  const byKey = Object.fromEntries(items.map((i) => [i.key, i.state]));
  assert.equal(byKey.fetching, 'done');
  assert.equal(byKey.extracting, 'done');
  assert.equal(byKey.candidates, 'done');
  assert.equal(byKey.analyzing, 'failed');
});

test('fetch success + extraction failure marks source done and extract failed', () => {
  const items = buildProgressChecklist(
    {
      analysis_status: 'failed',
      failure_stage: 'extracting',
      failure_code: 'source_verification_required'
    },
    { status: 'failed', stage: 'extracting' }
  );
  const byKey = Object.fromEntries(items.map((i) => [i.key, i.state]));
  assert.equal(byKey.fetching, 'done');
  assert.equal(byKey.extracting, 'failed');
  assert.equal(byKey.candidates, 'pending');
  assert.equal(byKey.analyzing, 'pending');
});

test('isProcessingStatus is false for failed and true for analyzing', async () => {
  const { isProcessingStatus } = await import('./stages.js');
  assert.equal(isProcessingStatus({ analysis_status: 'failed' }), false);
  assert.equal(isProcessingStatus({ analysis_status: 'analyzing' }), true);
  assert.equal(isProcessingStatus({ analysis_status: 'pending' }), true);
  assert.equal(isProcessingStatus({ analysis_status: 'review_required' }), false);
});
