import test from 'node:test';
import assert from 'node:assert/strict';
import {
  presentFeedLastResult,
  resolveFeedLastResult,
  reconcileLastResultWithHealth,
  resolveLastResultHealthState,
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

// --- USOM: full-reconciliation health is a separate signal from Last Result ---

test('resolveLastResultHealthState prefers run_health_state over overlaid health_state', () => {
  assert.equal(
    resolveLastResultHealthState({ health_state: 'degraded', run_health_state: 'success' }),
    'success'
  );
});

test('resolveLastResultHealthState falls back to health_state on legacy payloads', () => {
  assert.equal(resolveLastResultHealthState({ health_state: 'warning' }), 'warning');
  assert.equal(resolveLastResultHealthState(null), null);
});

test('successful incremental is not shown as Failed when a separate full reconciliation failed', () => {
  // Reported scenario: latest run = incremental success (1 new); feed health degraded
  // solely because the last full reconciliation failed. Last Result must reflect the run.
  const feed = {
    health_state: 'degraded',
    run_health_state: 'success',
    reconciliation_health_state: 'degraded',
    reconciliation_warning: 'Latest full reconciliation failed.',
    last_result: {
      status: 'completed',
      outcome: 'changes',
      checked: 143,
      new: 1,
      updated: 0,
      unchanged: 142,
      rejected: 0
    }
  };
  const view = presentFeedLastResult(resolveFeedLastResult(feed), {
    healthState: resolveLastResultHealthState(feed)
  });
  assert.equal(view.primary, 'Completed · 1 new');
  assert.equal(view.primaryTone, 'success');
  assert.equal(view.primary.includes('Failed'), false);
});

test('genuinely failed last run still shows Failed even when feed is degraded', () => {
  // Latest run = failed full reconciliation; run health is failed, so Last Result is Failed.
  const feed = {
    health_state: 'degraded',
    run_health_state: 'failed',
    reconciliation_health_state: 'degraded',
    last_result: {
      status: 'failed',
      checked: 0,
      new: 0,
      updated: 0,
      unchanged: 0,
      rejected: 0,
      message: 'USOM API response has invalid totalCount'
    }
  };
  const view = presentFeedLastResult(resolveFeedLastResult(feed), {
    healthState: resolveLastResultHealthState(feed)
  });
  assert.match(view.primary, /^Failed · /);
  assert.equal(view.primaryTone, 'danger');
});

test('reconciliation-age warning does not downgrade a successful run to warnings', () => {
  const feed = {
    health_state: 'warning',
    run_health_state: 'success',
    reconciliation_health_state: 'warning',
    last_result: {
      status: 'completed',
      outcome: 'changes',
      checked: 200,
      new: 5,
      updated: 2,
      unchanged: 193,
      rejected: 0
    }
  };
  const view = presentFeedLastResult(resolveFeedLastResult(feed), {
    healthState: resolveLastResultHealthState(feed)
  });
  assert.equal(view.primary, 'Completed · 5 new · 2 updated');
  assert.equal(view.primaryTone, 'success');
});

test('degraded health from the run itself still forces Last Result to Failed', () => {
  // Non-USOM safety: when the run health is the failing signal, alignment still applies.
  const reconciled = reconcileLastResultWithHealth({
    status: 'completed',
    outcome: 'changes',
    checked: 10,
    new: 2,
    updated: 0,
    rejected: 0
  }, 'failed');
  assert.equal(reconciled.status, 'failed');
});

test('tooltips distinguish unchanged / filtered / rejected', async () => {
  const { FEED_RESULT_METRIC_TOOLTIPS: tips } = await import('./feedLastResult.js');
  assert.match(tips.unchanged, /semantic source content did not change/i);
  assert.match(tips.filtered, /unsupported|outside accepted scope/i);
  assert.match(tips.rejected, /validation|persistence|technical failure/i);
  assert.equal(/records_skipped/i.test(tips.rejected), false);
});
