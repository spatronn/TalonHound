import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildUsomReconciliationHealth,
  decideUsomEnqueue,
  isScheduledRepeatIteration,
  normalizeUsomRunMode
} from './usomReconciliation.js';

test('run mode validation defaults to incremental and rejects unknown modes', () => {
  assert.equal(normalizeUsomRunMode(), 'incremental');
  assert.equal(normalizeUsomRunMode('full_reconciliation'), 'full_reconciliation');
  assert.equal(normalizeUsomRunMode('full'), null);
});

test('coalescing gives full reconciliation precedence', () => {
  assert.equal(
    decideUsomEnqueue('incremental', [{ job_id: 'full-1', triggered_by: 'scheduler:full_reconciliation' }]).action,
    'suppress'
  );
  assert.equal(
    decideUsomEnqueue('full_reconciliation', [{ job_id: 'full-1', triggered_by: 'manual-ui-one:full_reconciliation' }]).action,
    'coalesce'
  );
  assert.deepEqual(
    decideUsomEnqueue('full_reconciliation', [{ job_id: 'inc-1', triggered_by: 'scheduler:incremental' }]),
    { action: 'enqueue', reason: 'retain_after_incremental' }
  );
});

test('recognizes delayed scheduler iterations without hiding manual delayed jobs', () => {
  assert.equal(isScheduledRepeatIteration({ id: 'repeat:abc:123' }), true);
  assert.equal(isScheduledRepeatIteration({ id: 'job-1', repeatJobKey: 'integration-schedule:usom-trcert::incremental' }), true);
  assert.equal(isScheduledRepeatIteration({ id: 'job-2', opts: { repeat: { pattern: '0 * * * *' } } }), true);
  assert.equal(isScheduledRepeatIteration({ id: 'manual-1', opts: { delay: 5000 } }), false);
});

test('full reconciliation health warns after 8 days and degrades after 14', () => {
  const now = new Date('2026-07-18T12:00:00.000Z');
  const healthy = buildUsomReconciliationHealth({
    latestFullRun: { status: 'success', finished_at: '2026-07-12T12:00:00.000Z' },
    lastSuccessfulFullRun: { status: 'success', finished_at: '2026-07-12T12:00:00.000Z' },
    now
  });
  assert.equal(healthy.state, 'healthy');

  const warning = buildUsomReconciliationHealth({
    latestFullRun: { status: 'success', finished_at: '2026-07-09T12:00:00.000Z' },
    lastSuccessfulFullRun: { status: 'success', finished_at: '2026-07-09T12:00:00.000Z' },
    now
  });
  assert.equal(warning.state, 'warning');

  const degraded = buildUsomReconciliationHealth({
    latestFullRun: { status: 'success', finished_at: '2026-07-03T12:00:00.000Z' },
    lastSuccessfulFullRun: { status: 'success', finished_at: '2026-07-03T12:00:00.000Z' },
    now
  });
  assert.equal(degraded.state, 'degraded');

  const failed = buildUsomReconciliationHealth({
    latestFullRun: { status: 'failed', finished_at: '2026-07-18T11:00:00.000Z' },
    lastSuccessfulFullRun: { status: 'success', finished_at: '2026-07-17T12:00:00.000Z' },
    now
  });
  assert.equal(failed.state, 'degraded');
});

test('full-reconciliation health is a separate, explicitly labeled signal', () => {
  const now = new Date('2026-08-01T22:30:00.000Z');

  // Latest full reconciliation failed, even though a fresh successful full exists just before it.
  const failed = buildUsomReconciliationHealth({
    latestFullRun: { status: 'failed', finished_at: '2026-08-01T21:16:00.000Z' },
    lastSuccessfulFullRun: { status: 'success', finished_at: '2026-08-01T20:46:00.000Z' },
    now
  });
  assert.equal(failed.state, 'degraded');
  assert.equal(failed.warning, 'Latest full reconciliation failed.');
  assert.equal(failed.latest_status, 'failed');

  // Successful full reconciliation clears the degraded reconciliation signal.
  const healthy = buildUsomReconciliationHealth({
    latestFullRun: { status: 'success', finished_at: '2026-08-01T20:46:00.000Z' },
    lastSuccessfulFullRun: { status: 'success', finished_at: '2026-08-01T20:46:00.000Z' },
    now
  });
  assert.equal(healthy.state, 'healthy');
  assert.equal(healthy.warning, null);

  // A successful incremental does not feed this signal — it is derived only from full runs.
  const noFullEver = buildUsomReconciliationHealth({
    latestFullRun: null,
    lastSuccessfulFullRun: null,
    now
  });
  assert.equal(noFullEver.state, 'degraded');
  assert.equal(noFullEver.warning, 'No successful full reconciliation has been recorded.');
});
