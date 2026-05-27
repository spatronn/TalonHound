import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildRetroHealthPayload,
  computeRetroWorkerHealth,
  computeRetroCursorHealth,
  computeCorrelationSyncHealth,
  computeRetroStateHealth,
  retroPendingWhereSql,
  secondsBetween,
  RETRO_RUN_WARNING_SECONDS,
  RETRO_RUN_STALE_SECONDS
} from './retroStatus.js';

test('retroPendingWhereSql uses worker confidence filter and cursor tie-break', () => {
  const sql = retroPendingWhereSql('2026-05-27 16:51:11.156', '123');
  assert.match(sql, /confidence > 0/);
  assert.match(sql, /16:51:11\.156/);
  assert.match(sql, /cityHash64\(concat/);
});

test('scenario A: normal hourly run, zero backlog, PG sync lag under warning', () => {
  const now = Date.now();
  const bundle = buildRetroHealthPayload({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 20:02:01.000',
    chMaxLookupUpdatedAtMs: now - 1000,
    chPendingIocCount: 0,
    chCursorLagSeconds: 0,
    pgUnsyncedIocCount: 95,
    pgToChSyncLagSeconds: 38 * 60 + 51,
    lastRunAtMs: now - (42 * 60 * 1000),
    nowMs: now
  });
  assert.equal(bundle.retro_worker_health, 'OK');
  assert.equal(bundle.retro_cursor_health, 'OK');
  assert.equal(bundle.correlation_sync_health, 'OK');
  assert.equal(bundle.overall_health, 'OK');
});

test('scenario B: last run delayed → worker warning', () => {
  const now = Date.now();
  const bundle = buildRetroHealthPayload({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 16:51:11.156',
    chPendingIocCount: 0,
    lastRunAtMs: now - (70 * 60 * 1000),
    nowMs: now
  });
  assert.equal(bundle.retro_worker_health, 'WARNING');
  assert.equal(bundle.overall_health, 'WARNING');
});

test('scenario C: last run very delayed → worker stale', () => {
  const now = Date.now();
  const bundle = buildRetroHealthPayload({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 16:51:11.156',
    chPendingIocCount: 0,
    lastRunAtMs: now - (95 * 60 * 1000),
    nowMs: now
  });
  assert.equal(bundle.retro_worker_health, 'STALE');
  assert.equal(bundle.overall_health, 'STALE');
});

test('scenario D: cursor backlog with stale worker run', () => {
  const now = Date.now();
  const bundle = buildRetroHealthPayload({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 10:00:00.000',
    chPendingIocCount: 12,
    chCursorLagSeconds: 70 * 60,
    lastRunAtMs: now - (95 * 60 * 1000),
    nowMs: now
  });
  assert.equal(bundle.retro_cursor_health, 'STALE');
});

test('scenario E: PG sync lag stale does not force worker stale', () => {
  const now = Date.now();
  const bundle = buildRetroHealthPayload({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 20:02:01.000',
    chPendingIocCount: 0,
    chCursorLagSeconds: 0,
    pgUnsyncedIocCount: 200,
    pgToChSyncLagSeconds: 95 * 60,
    lastRunAtMs: now - (40 * 60 * 1000),
    nowMs: now
  });
  assert.equal(bundle.retro_worker_health, 'OK');
  assert.equal(bundle.correlation_sync_health, 'STALE');
  assert.equal(bundle.overall_health, 'STALE');
});

test('computeRetroStateHealth backward compatible with overall', () => {
  const now = Date.now();
  assert.equal(computeRetroStateHealth({
    chOk: true,
    pgOk: true,
    cursorTs: '2026-05-27 16:51:11.156',
    chPendingIocCount: 0,
    pgUnsyncedIocCount: 44,
    pgToChSyncLagSeconds: 600,
    lastRunAtMs: now - (40 * 60 * 1000),
    nowMs: now
  }), 'OK');
});

test('threshold defaults: warning 65m stale 90m', () => {
  assert.equal(RETRO_RUN_WARNING_SECONDS, 65 * 60);
  assert.equal(RETRO_RUN_STALE_SECONDS, 90 * 60);
});

test('secondsBetween is non-negative', () => {
  assert.equal(secondsBetween(2000, 1000), 1);
  assert.equal(secondsBetween(1000, 2000), 0);
});

test('computeRetroWorkerHealth isolated', () => {
  assert.equal(computeRetroWorkerHealth({ lastRunAgeSeconds: 40 * 60 }), 'OK');
  assert.equal(computeRetroWorkerHealth({ lastRunAgeSeconds: 70 * 60 }), 'WARNING');
  assert.equal(computeRetroWorkerHealth({ lastRunAgeSeconds: 95 * 60 }), 'STALE');
});

test('computeCorrelationSyncHealth isolated', () => {
  assert.equal(computeCorrelationSyncHealth({ pgUnsyncedIocCount: 0 }), 'OK');
  assert.equal(computeCorrelationSyncHealth({ pgUnsyncedIocCount: 10, pgToChSyncLagSeconds: 38 * 60 }), 'OK');
  assert.equal(computeCorrelationSyncHealth({ pgUnsyncedIocCount: 10, pgToChSyncLagSeconds: 70 * 60 }), 'WARNING');
});

test('computeRetroCursorHealth OK when no backlog and no lag', () => {
  assert.equal(computeRetroCursorHealth({ chPendingIocCount: 0, chCursorLagSeconds: 0 }), 'OK');
});
