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
