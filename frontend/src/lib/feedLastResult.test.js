import test from 'node:test';
import assert from 'node:assert/strict';
import {
  presentFeedLastResult,
  resolveFeedLastResult,
  FEED_RESULT_TONE_COLORS
} from './feedLastResult.js';

test('Completed · No changes uses success tone (not warning)', () => {
  const result = resolveFeedLastResult({
    last_result: {
      status: 'completed',
      outcome: 'no_changes',
      checked: 25682,
      new: 0,
      updated: 0,
      unchanged: 25682,
      rejected: 0,
      message: 'No changes'
    }
  });
  const view = presentFeedLastResult(result);
  assert.equal(view.primary, 'Completed · No changes');
  assert.equal(view.primaryTone, 'success');
  assert.notEqual(view.primaryTone, 'warning');
  assert.match(view.secondary, /25,682 checked/);
  assert.match(view.secondary, /unchanged/);
  assert.equal(FEED_RESULT_TONE_COLORS[view.primaryTone], '#86efac');
});

test('Completed · No new data uses success tone', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_result: {
      status: 'completed',
      outcome: 'no_new_data',
      checked: 0,
      new: 0,
      updated: 0,
      unchanged: 0,
      rejected: 0,
      message: 'No new data'
    }
  }));
  assert.equal(view.primary, 'Completed · No new data');
  assert.equal(view.primaryTone, 'success');
});

test('formats new/updated/checked/unchanged', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_result: {
      status: 'completed',
      outcome: 'changes',
      checked: 14806,
      new: 10,
      updated: 6,
      unchanged: 14746,
      rejected: 0
    }
  }));
  assert.equal(view.primary, 'Completed · 10 new · 6 updated');
  assert.match(view.secondary, /14,806 checked/);
  assert.match(view.secondary, /14,746 unchanged/);
});

test('rejected records show as warnings', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_result: {
      status: 'completed_with_warnings',
      outcome: 'partial',
      checked: 2196,
      new: 10,
      updated: 0,
      unchanged: 2174,
      rejected: 12,
      message: '12 rejected'
    }
  }));
  assert.match(view.primary, /Completed with warnings/);
  assert.match(view.primary, /12 rejected/);
  assert.equal(view.primaryTone, 'warning');
});

test('failed result shows short error message', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_result: {
      status: 'failed',
      checked: 0,
      new: 0,
      updated: 0,
      unchanged: 0,
      rejected: 0,
      message: 'Authentication rejected'
    }
  }));
  assert.match(view.primary, /Failed/);
  assert.match(view.primary, /Authentication rejected/);
  assert.equal(view.primaryTone, 'danger');
});

test('missing metrics never render NaN or undefined', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_status: 'success',
    last_run_metrics: { available: true }
  }));
  assert.equal(String(view.primary).includes('undefined'), false);
  assert.equal(String(view.primary).includes('NaN'), false);
  assert.equal(String(view.secondary || '').includes('undefined'), false);
  assert.equal(String(view.secondary || '').includes('NaN'), false);
});

test('never run presentation', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({ last_status: 'never' }));
  assert.equal(view.primary, 'No successful run');
  assert.equal(view.primaryTone, 'neutral');
});
