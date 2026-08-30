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

test('computeQueueHealth stays Healthy for a 5+ min running job with no real stall', () => {
  // Long healthy job: BullMQ active=1, truly-stalled count 0, DB running=1,
  // recovery not needed. Must NOT go Degraded just because the job is long-lived.
  const health = computeQueueHealth({
    bullCounts: { waiting: 0, active: 1, stalled: 0 },
    dbCounts: { waiting: 0, active: 1 },
    dbRunningCount: 1,
    workerConsuming: true,
    recoveryNeeded: false
  });
  assert.equal(health.queue_health, 'Healthy');
  assert.equal(health.bullmq_stalled, 0);
  assert.equal(health.bullmq_active, 1);
  assert.equal(health.db_running, 1);
  assert.equal(health.recovery_needed, false);
  assert.deepEqual(health.warnings, []);
});

test('computeQueueHealth goes Degraded on a real BullMQ stalled job', () => {
  const health = computeQueueHealth({
    bullCounts: { waiting: 0, active: 1, stalled: 1 },
    dbCounts: { waiting: 0, active: 1 },
    dbRunningCount: 1,
    workerConsuming: true,
    recoveryNeeded: false
  });
  assert.equal(health.queue_health, 'Degraded');
  assert.equal(health.bullmq_stalled, 1);
});

test('computeQueueHealth is Healthy when DB running matches BullMQ active with no stall', () => {
  const health = computeQueueHealth({
    bullCounts: { waiting: 0, active: 1, stalled: 0 },
    dbCounts: { waiting: 0, active: 1 },
    dbRunningCount: 1,
    workerConsuming: true
  });
  assert.equal(health.queue_health, 'Healthy');
});

test('computeQueueHealth: recovery_needed=no long run does not turn Degraded (50s-boundary guard)', () => {
  // Simulates the corrected snapshot at the ~stalledInterval boundary: the long
  // job is active with a held lock so the truly-stalled count is 0.
  const health = computeQueueHealth({
    bullCounts: { waiting: 0, active: 1, stalled: 0 },
    dbCounts: { waiting: 0, active: 1 },
    dbRunningCount: 1,
    staleActiveJobs: [],
    staleStalledJobs: [],
    workerConsuming: true,
    recoveryNeeded: false
  });
  assert.equal(health.queue_health, 'Healthy');
  assert.equal(health.recovery_needed, false);
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
