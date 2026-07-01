import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isDbTerminalStatus,
  isBullmqReconcilableState,
  isBlockingBullmqEntry,
  moveBullJobToFailed,
  classifyOrphanSourceLock,
  orphanSourceLockGraceMs
} from './integrationQueueBullmqReconciliation.js';
import { QUEUE_HARDENING } from './integrationQueueConfig.js';

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

test('isBlockingBullmqEntry detects terminal db mismatch', async () => {
  assert.equal(await isBlockingBullmqEntry({ status: 'failed' }, 'active'), true);
  assert.equal(await isBlockingBullmqEntry({ status: 'running', started_at: new Date(), heartbeat_at: new Date() }, 'active'), false);
  assert.equal(await isBlockingBullmqEntry(null, 'stalled'), true);
  assert.equal(await isBlockingBullmqEntry(null, 'active', Date.now(), { job: { isActive: async () => true } }), false);
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

// --- classifyOrphanSourceLock: orphan source-lock reclaim decision ---
// Regression guard for the false-positive that force-failed a LIVE OTX run-now
// job with reason=reconciled during a worker restart (fresh job not yet visible
// in the new worker's BullMQ active snapshot).

const NOW = Date.parse('2026-07-01T20:00:00Z');
const secsAgo = (s) => new Date(NOW - s * 1000).toISOString();

test('classifyOrphanSourceLock does NOT release a fresh live job missing from BullMQ (the bug)', () => {
  // Job started 2 min ago, heartbeat 20s ago (well within staleAfterMs), not in BullMQ snapshot.
  const row = { status: 'running', started_at: secsAgo(120), heartbeat_at: secsAgo(20) };
  const d = classifyOrphanSourceLock(row, { inLiveBullmq: false, nowMs: NOW });
  assert.equal(d.release, false);
  assert.equal(d.reason, 'live_fresh_heartbeat');
});

test('classifyOrphanSourceLock does NOT release a fresh live job present in BullMQ', () => {
  const row = { status: 'running', started_at: secsAgo(30), heartbeat_at: secsAgo(5) };
  const d = classifyOrphanSourceLock(row, { inLiveBullmq: true, nowMs: NOW });
  assert.equal(d.release, false);
  assert.equal(d.reason, 'live_in_bullmq');
});

test('classifyOrphanSourceLock releases a heartbeat-stale job as stale (not reconciled)', () => {
  // Custom config where staleAfterMs < jobTimeoutMs so the heartbeat-stale branch
  // is reachable in isolation: started 5m ago (< 10m timeout), heartbeat quiet 3m (> 2m stale).
  const config = { jobTimeoutMs: 600_000, staleAfterMs: 120_000, heartbeatIntervalMs: 30_000 };
  const row = { status: 'running', started_at: secsAgo(300), heartbeat_at: secsAgo(180) };
  const d = classifyOrphanSourceLock(row, { inLiveBullmq: false, nowMs: NOW, config });
  assert.equal(d.release, true);
  assert.equal(d.failureType, 'stale');
  assert.equal(d.reason, 'stale');
  assert.equal(d.message.includes('reconciled'), false);
});

test('classifyOrphanSourceLock never uses reconciled reason for a long-quiet job (releases as timeout)', () => {
  // Default config: quiet 16m => age > jobTimeoutMs(10m) => timeout (accurate, not reconciled).
  const quietSecs = Math.ceil(QUEUE_HARDENING.staleAfterMs / 1000) + 60;
  const row = { status: 'running', started_at: secsAgo(quietSecs + 60), heartbeat_at: secsAgo(quietSecs) };
  const d = classifyOrphanSourceLock(row, { inLiveBullmq: false, nowMs: NOW });
  assert.equal(d.release, true);
  assert.notEqual(d.failureType, 'reconciled');
  assert.equal(d.message.includes('Reconciled stale BullMQ'), false);
});

test('classifyOrphanSourceLock releases a timed-out job as timeout', () => {
  const timeoutSecs = Math.ceil(QUEUE_HARDENING.jobTimeoutMs / 1000) + 60;
  // Fresh heartbeat but started beyond jobTimeoutMs => timeout classification.
  const row = { status: 'running', started_at: secsAgo(timeoutSecs), heartbeat_at: secsAgo(5) };
  const d = classifyOrphanSourceLock(row, { inLiveBullmq: true, nowMs: NOW });
  assert.equal(d.release, true);
  assert.equal(d.failureType, 'timeout');
});

test('classifyOrphanSourceLock releases a not-in-bullmq job whose heartbeat is quiet beyond grace', () => {
  // Heartbeat quiet beyond orphan grace (but below staleAfterMs) AND absent from BullMQ => orphan.
  const graceMs = orphanSourceLockGraceMs();
  const quietSecs = Math.ceil(graceMs / 1000) + 30;
  const row = { status: 'running', started_at: secsAgo(quietSecs + 30), heartbeat_at: secsAgo(quietSecs) };
  const d = classifyOrphanSourceLock(row, { inLiveBullmq: false, nowMs: NOW });
  assert.equal(d.release, true);
  assert.equal(d.failureType, 'stale');
  assert.equal(d.reason, 'orphan_absent_bullmq');
});

test('classifyOrphanSourceLock ignores non-running rows', () => {
  assert.equal(classifyOrphanSourceLock({ status: 'success' }, { inLiveBullmq: false, nowMs: NOW }).release, false);
  assert.equal(classifyOrphanSourceLock({ status: 'failed' }, { inLiveBullmq: false, nowMs: NOW }).release, false);
});

test('orphanSourceLockGraceMs stays above one heartbeat interval', () => {
  assert.ok(orphanSourceLockGraceMs() >= QUEUE_HARDENING.heartbeatIntervalMs * 2);
  assert.ok(orphanSourceLockGraceMs() >= 90_000);
});
