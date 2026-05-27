import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyRunningJobForRecovery,
  getJobLastSeenMs,
  isSourceActivelyRunning
} from './integrationQueueRecovery.js';
import { FAILURE_TYPES, QUEUE_HARDENING } from './integrationQueueConfig.js';

const NOW = Date.parse('2026-05-27T12:00:00.000Z');
const config = {
  jobTimeoutMs: 600_000,
  staleAfterMs: 900_000
};

describe('classifyRunningJobForRecovery', () => {
  it('returns null for non-running jobs', () => {
    assert.equal(classifyRunningJobForRecovery({ status: 'queued' }, NOW, config), null);
  });

  it('marks stale when heartbeat is older than stale threshold', () => {
    const job = {
      status: 'running',
      started_at: '2026-05-27T11:55:00.000Z',
      heartbeat_at: '2026-05-27T11:40:00.000Z'
    };
    const result = classifyRunningJobForRecovery(job, NOW, config);
    assert.equal(result?.failureType, FAILURE_TYPES.STALE);
    assert.ok(result.ageMs >= 900_000);
  });

  it('keeps fresh running jobs', () => {
    const job = {
      status: 'running',
      started_at: '2026-05-27T11:50:00.000Z',
      heartbeat_at: '2026-05-27T11:59:00.000Z'
    };
    assert.equal(classifyRunningJobForRecovery(job, NOW, config), null);
  });

  it('marks timeout when started_at exceeds job timeout even with fresh heartbeat', () => {
    const job = {
      status: 'running',
      started_at: '2026-05-27T10:50:00.000Z',
      heartbeat_at: '2026-05-27T11:59:00.000Z'
    };
    const result = classifyRunningJobForRecovery(job, NOW, config);
    assert.equal(result?.failureType, FAILURE_TYPES.TIMEOUT);
  });

  it('falls back to started_at when heartbeat is missing', () => {
    const job = {
      status: 'running',
      started_at: '2026-05-27T10:50:00.000Z',
      updated_at: '2026-05-27T10:50:00.000Z'
    };
    const result = classifyRunningJobForRecovery(job, NOW, config);
    assert.equal(result?.failureType, FAILURE_TYPES.TIMEOUT);
  });
});

describe('isSourceActivelyRunning', () => {
  it('detects another fresh running job for same source', () => {
    const rows = [
      { job_id: 'a', integration_key: 'usom-trcert', status: 'running', started_at: '2026-05-27T11:55:00.000Z', heartbeat_at: '2026-05-27T11:59:00.000Z' },
      { job_id: 'b', integration_key: 'usom-trcert', status: 'running', started_at: '2026-05-27T11:58:00.000Z', heartbeat_at: '2026-05-27T11:59:30.000Z' }
    ];
    const blocking = isSourceActivelyRunning(rows, 'usom-trcert', 'b', NOW, config);
    assert.equal(blocking?.job_id, 'a');
  });

  it('ignores stale running rows when checking source lock', () => {
    const rows = [
      { job_id: 'a', integration_key: 'usom-trcert', status: 'running', started_at: '2026-05-27T09:00:00.000Z', heartbeat_at: '2026-05-27T09:05:00.000Z' }
    ];
    assert.equal(isSourceActivelyRunning(rows, 'usom-trcert', 'b', NOW, config), null);
  });
});

describe('getJobLastSeenMs', () => {
  it('prefers heartbeat_at over updated_at', () => {
    const ms = getJobLastSeenMs({
      heartbeat_at: '2026-05-27T11:59:00.000Z',
      updated_at: '2026-05-27T11:00:00.000Z',
      started_at: '2026-05-27T10:00:00.000Z'
    });
    assert.equal(ms, Date.parse('2026-05-27T11:59:00.000Z'));
  });
});

describe('QUEUE_HARDENING defaults', () => {
  it('has expected default timeout and stale windows', () => {
    assert.equal(QUEUE_HARDENING.jobTimeoutMs, 600_000);
    assert.equal(QUEUE_HARDENING.staleAfterMs, 900_000);
    assert.equal(QUEUE_HARDENING.heartbeatIntervalMs, 30_000);
  });
});
