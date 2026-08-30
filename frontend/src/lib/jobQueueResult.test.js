import test from 'node:test';
import assert from 'node:assert/strict';
import {
  presentQueueJobResult,
  presentQueueJobReason,
  buildQueueJobDetailMetrics
} from './jobQueueResult.js';

test('Result column shows metric summary for success snapshot', () => {
  const view = presentQueueJobResult({
    state: 'success',
    result_summary: '85 new · 180 updated',
    result_code: 'COMPLETED_WITH_CHANGES',
    result: { available: true, result_summary: '85 new · 180 updated' }
  });
  assert.equal(view.text, '85 new · 180 updated');
  assert.equal(view.tone, 'success');
});

test('legacy null snapshot → Result unavailable', () => {
  const view = presentQueueJobResult({ state: 'success' });
  assert.equal(view.text, 'Result unavailable');
});

test('success Reason is em dash not Completed successfully', () => {
  const reason = presentQueueJobReason({ state: 'success', failed_reason: null });
  assert.equal(reason, '—');
  assert.notEqual(reason, 'Completed successfully');
});

test('failed Reason keeps sanitized message', () => {
  const reason = presentQueueJobReason({
    state: 'failed',
    failed_reason: 'rate_limit_exceeded',
    failure_type: 'fetch_error'
  });
  assert.equal(reason, '[fetch_error] rate_limit_exceeded');
});

test('detail metrics hide null and optional zeros', () => {
  const rows = buildQueueJobDetailMetrics({
    result_details: {
      checked: 100,
      new: 5,
      updated: 0,
      unchanged: 95,
      expired: 0,
      filtered: 0,
      failed: 0,
      fetched: null
    }
  });
  const labels = rows.map((r) => r.label);
  assert.ok(labels.includes('New'));
  assert.ok(labels.includes('Updated'));
  assert.ok(!labels.includes('Expired'));
  assert.ok(!labels.includes('Fetched'));
});
