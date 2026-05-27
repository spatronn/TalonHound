import test from 'node:test';
import assert from 'node:assert/strict';
import { computeQueueHealth, buildQueuedJobHint } from './integrationQueueHealth.js';

test('computeQueueHealth blocked when stale active with terminal db', () => {
  const health = computeQueueHealth({
    bullCounts: { waiting: 3, active: 1, stalled: 1 },
    dbCounts: { waiting: 3, active: 0 },
    staleActiveJobs: [{
      job_id: '8',
      bullmq_state: 'active',
      db: { job_id: '8', status: 'failed', integration_key: 'threatfox-abusech' }
    }],
    workerConsuming: true
  });
  assert.equal(health.queue_health, 'Blocked');
  assert.match(health.warnings.join(' '), /Stale active job/);
});

test('computeQueueHealth waiting with no active shows degradation warning', () => {
  const health = computeQueueHealth({
    bullCounts: { waiting: 2, active: 0 },
    dbCounts: { waiting: 2, active: 0 },
    workerConsuming: true
  });
  assert.equal(health.queue_health, 'Degraded');
  assert.ok(health.warnings.some((w) => /waiting but no worker/i.test(w)));
});

test('buildQueuedJobHint explains source lock', () => {
  const hint = buildQueuedJobHint({
    jobId: '17',
    integrationKey: 'usom-trcert',
    dbRunningBySource: new Map([['usom-trcert', { job_id: '14' }]]),
    queueHealth: { recovery_needed: false, worker_status: 'Running' }
  });
  assert.match(hint, /source lock/i);
  assert.match(hint, /14/);
});
