import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isDbTerminalStatus,
  isBullmqReconcilableState,
  isBlockingBullmqEntry,
  moveBullJobToFailed
} from './integrationQueueBullmqReconciliation.js';

test('isDbTerminalStatus recognizes terminal rows', () => {
  assert.equal(isDbTerminalStatus('failed'), true);
  assert.equal(isDbTerminalStatus('success'), true);
  assert.equal(isDbTerminalStatus('running'), false);
  assert.equal(isDbTerminalStatus('queued'), false);
});

test('isBullmqReconcilableState only active and stalled', () => {
  assert.equal(isBullmqReconcilableState('active'), true);
  assert.equal(isBullmqReconcilableState('stalled'), true);
  assert.equal(isBullmqReconcilableState('waiting'), false);
});

test('moveBullJobToFailed dry-run does not mutate', async () => {
  const calls = [];
  const fakeJob = {
    id: '8',
    getState: async () => 'active',
    moveToFailed: async (...args) => { calls.push(args); }
  };
  const res = await moveBullJobToFailed(fakeJob, 'test', { dryRun: true });
  assert.equal(res.dryRun, true);
  assert.equal(calls.length, 0);
});

test('isBlockingBullmqEntry detects terminal db mismatch', () => {
  assert.equal(isBlockingBullmqEntry({ status: 'failed' }, 'active'), true);
  assert.equal(isBlockingBullmqEntry({ status: 'running', started_at: new Date(), heartbeat_at: new Date() }, 'active'), false);
  assert.equal(isBlockingBullmqEntry(null, 'stalled'), true);
});

test('moveBullJobToFailed skips completed jobs', async () => {
  const fakeJob = {
    id: '8',
    getState: async () => 'completed',
    moveToFailed: async () => { throw new Error('should not run'); }
  };
  const res = await moveBullJobToFailed(fakeJob, 'test', { dryRun: false });
  assert.equal(res.skipped, true);
});
