import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeRetroStateHealth,
  retroPendingWhereSql,
  secondsBetween,
  RETRO_CURSOR_LAG_WARNING_SECONDS,
  RETRO_RUN_STALE_SECONDS
} from './retroStatus.js';

test('retroPendingWhereSql uses worker confidence filter and cursor tie-break', () => {
  const sql = retroPendingWhereSql('2026-05-27 16:51:11.156', '123');
  assert.match(sql, /confidence > 0/);
  assert.match(sql, /16:51:11\.156/);
  assert.match(sql, /cityHash64\(concat/);
});

test('computeRetroStateHealth OK when synced and no backlog', () => {
  const now = Date.now();
  assert.equal(computeRetroStateHealth({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 16:51:11.156',
    chMaxLookupUpdatedAtMs: now - 1000,
    chPendingIocCount: 0,
    chCursorLagSeconds: 0,
    pgUnsyncedIocCount: 0,
    pgToChSyncLagSeconds: 0,
    lastRunAtMs: now - 5000,
    chunkActive: 0,
    nowMs: now
  }), 'OK');
});

test('computeRetroStateHealth WARNING for PG unsynced with zero CH pending', () => {
  const now = Date.now();
  assert.equal(computeRetroStateHealth({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 16:51:11.156',
    chPendingIocCount: 0,
    pgUnsyncedIocCount: 44,
    pgToChSyncLagSeconds: 600,
    lastRunAtMs: now - 5000,
    nowMs: now
  }), 'WARNING');
});

test('computeRetroStateHealth STALE when last run too old', () => {
  const now = Date.now();
  assert.equal(computeRetroStateHealth({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 16:51:11.156',
    chPendingIocCount: 0,
    lastRunAtMs: now - (RETRO_RUN_STALE_SECONDS + 10) * 1000,
    nowMs: now
  }), 'STALE');
});

test('computeRetroStateHealth ERROR when CH unavailable', () => {
  assert.equal(computeRetroStateHealth({ chOk: false, pgOk: true }), 'ERROR');
});

test('secondsBetween is non-negative', () => {
  assert.equal(secondsBetween(2000, 1000), 1);
  assert.equal(secondsBetween(1000, 2000), 0);
});
