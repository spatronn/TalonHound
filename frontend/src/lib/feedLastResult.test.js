import test from 'node:test';
import assert from 'node:assert/strict';
import {
  presentFeedLastResult,
  resolveFeedLastResult,
  reconcileLastResultWithHealth,
  FEED_RESULT_TONE_COLORS
} from './feedLastResult.js';

test('new + updated → Completed · X new · Y updated', () => {
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
  }), { healthState: 'success' });
  assert.equal(view.primary, 'Completed · 10 new · 6 updated');
  assert.equal(view.secondary, null);
  assert.equal(view.primaryTone, 'success');
});

test('new only — omit zero updated', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_result: {
      status: 'completed',
      outcome: 'changes',
      checked: 100,
      new: 27,
      updated: 0,
      unchanged: 0,
      rejected: 832
    }
  }), { healthState: 'success' });
  assert.equal(view.primary, 'Completed · 27 new');
  assert.equal(view.primary.includes('0 updated'), false);
  assert.equal(view.secondary, null);
});

test('updated only — omit zero new', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_result: {
      status: 'completed',
      outcome: 'changes',
      checked: 500,
      new: 0,
      updated: 247,
      unchanged: 0,
      rejected: 0
    }
  }), { healthState: 'success' });
  assert.equal(view.primary, 'Completed · 247 updated');
  assert.equal(view.primary.includes('0 new'), false);
});

test('Completed · No changes uses success tone (not warning)', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
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
  }), { healthState: 'success' });
  assert.equal(view.primary, 'Completed · No changes');
  assert.equal(view.primaryTone, 'success');
  assert.notEqual(view.primaryTone, 'warning');
  assert.equal(view.secondary, null);
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
  }), { healthState: 'success' });
  assert.equal(view.primary, 'Completed · No new data');
  assert.equal(view.primaryTone, 'success');
  assert.equal(view.secondary, null);
});

test('Healthy + high legacy rejected does not show Completed with warnings', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    health_state: 'success',
    last_result: {
      status: 'completed_with_warnings',
      outcome: 'partial',
      checked: 14877,
      new: 69,
      updated: 46,
      unchanged: 0,
      rejected: 14716,
      message: '14,716 rejected'
    }
  }), { healthState: 'success' });
  assert.equal(view.primary, 'Completed · 69 new · 46 updated');
  assert.equal(view.primaryTone, 'success');
  assert.equal(view.primary.includes('rejected'), false);
  assert.equal(view.primary.includes('Completed with warnings'), false);
  assert.equal(view.secondary, null);
});

test('Healthy + legacy warning with no changes → No changes', () => {
  const view = presentFeedLastResult({
    status: 'completed_with_warnings',
    outcome: 'partial',
    checked: 100,
    new: 0,
    updated: 0,
    unchanged: 0,
    rejected: 100,
    message: '100 rejected'
  }, { healthState: 'success' });
  assert.equal(view.primary, 'Completed · No changes');
  assert.equal(view.primaryTone, 'success');
});

test('real partial fetch → Completed with warnings', () => {
  const view = presentFeedLastResult({
    status: 'completed_with_warnings',
    outcome: 'partial',
    checked: 100,
    new: 5,
    updated: 0,
    rejected: 0,
    message: 'Partial fetch'
  }, { healthState: 'warning' });
  assert.equal(view.primary, 'Completed with warnings · Partial fetch');
  assert.equal(view.primaryTone, 'warning');
  assert.equal(view.secondary, null);
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
  }), { healthState: 'failed' });
  assert.match(view.primary, /^Failed · /);
  assert.match(view.primary, /Authentication/);
  assert.equal(view.primaryTone, 'danger');
  assert.equal(view.secondary, null);
});

test('missing metrics never render NaN or undefined', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({
    last_status: 'success',
    last_run_metrics: { available: true }
  }), { healthState: 'success' });
  assert.equal(String(view.primary).includes('undefined'), false);
  assert.equal(String(view.primary).includes('NaN'), false);
  assert.equal(String(view.secondary || '').includes('undefined'), false);
  assert.equal(String(view.secondary || '').includes('NaN'), false);
});

test('never run presentation', () => {
  const view = presentFeedLastResult(resolveFeedLastResult({ last_status: 'never' }), {
    healthState: 'never'
  });
  assert.equal(view.primary, 'No successful run');
  assert.equal(view.primaryTone, 'neutral');
});

test('reconcile prevents Healthy + Completed with warnings', () => {
  const reconciled = reconcileLastResultWithHealth({
    status: 'completed_with_warnings',
    outcome: 'partial',
    checked: 10,
    new: 2,
    updated: 1,
    rejected: 7,
    message: '7 rejected'
  }, 'success');
  assert.equal(reconciled.status, 'completed');
  assert.equal(reconciled.outcome, 'changes');
});

test('fallback legacy payload with high skipped stays completed', () => {
  const result = resolveFeedLastResult({
    last_status: 'success',
    job_type: 'urlhaus_import',
    last_run_metrics: {
      available: true,
      processed: 1000,
      inserted: 10,
      updated: 6,
      unchanged: 0,
      skipped: 984,
      failed: 0
    }
  });
  assert.equal(result.status, 'completed');
  assert.equal(result.unchanged, 984);
  assert.equal(result.filtered, 0);
  assert.equal(result.rejected, 0);
  const view = presentFeedLastResult(result, { healthState: 'success' });
  assert.equal(view.primary, 'Completed · 10 new · 6 updated');
});

test('tooltips distinguish unchanged / filtered / rejected', async () => {
  const { FEED_RESULT_METRIC_TOOLTIPS: tips } = await import('./feedLastResult.js');
  assert.match(tips.unchanged, /semantic source content did not change/i);
  assert.match(tips.filtered, /unsupported|outside accepted scope/i);
  assert.match(tips.rejected, /validation|persistence|technical failure/i);
  assert.equal(/records_skipped/i.test(tips.rejected), false);
});
