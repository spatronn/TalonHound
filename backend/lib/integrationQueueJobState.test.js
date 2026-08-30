import test from 'node:test';
import assert from 'node:assert/strict';
import { coerceQueuedAt, markJobRunning } from './integrationQueueJobState.js';

test('coerceQueuedAt accepts Date, epoch ms, and ISO strings', () => {
  assert.equal(coerceQueuedAt(new Date('2026-08-23T00:00:00.000Z')), '2026-08-23T00:00:00.000Z');
  assert.equal(coerceQueuedAt(Date.parse('2026-08-23T00:00:05.000Z')), '2026-08-23T00:00:05.000Z');
  assert.equal(coerceQueuedAt('2026-08-23T00:00:05.000Z'), '2026-08-23T00:00:05.000Z');
  assert.equal(coerceQueuedAt(null), null);
  assert.equal(coerceQueuedAt('not-a-date'), null);
});

test('markJobRunning persists BullMQ job.timestamp as queued_at', async () => {
  const seen = [];
  const pool = {
    async query(sql, params) {
      seen.push({ sql, params });
    }
  };
  const queuedAt = Date.parse('2026-08-22T21:00:00.000Z');
  await markJobRunning(pool, {
    jobId: 'repeat:abc:1787432400000',
    integrationKey: 'ctf-1',
    jobName: 'custom-threat-feed-sync',
    triggeredBy: 'scheduler',
    workerId: 'w1',
    workerHostname: 'h1',
    queuedAt
  });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].params[6], '2026-08-22T21:00:00.000Z');
  assert.match(seen[0].sql, /COALESCE\(\$7::timestamptz, NOW\(\)\)/);
});
