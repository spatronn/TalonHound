import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeJobDurationMs,
  formatJobDuration,
  formatJobDurationForRow,
} from './integrationJobDuration.js';

test('completed job duration is finished_at - started_at', () => {
  const job = {
    started_at: '2026-07-25T10:00:00.000Z',
    finished_at: '2026-07-25T10:02:14.000Z',
  };
  assert.equal(computeJobDurationMs(job), 134000);
  assert.equal(formatJobDurationForRow(job), '2m 14s');
});

test('running job duration is now - started_at', () => {
  const now = Date.parse('2026-07-25T10:00:06.000Z');
  const job = { started_at: '2026-07-25T10:00:00.000Z', finished_at: null };
  assert.equal(computeJobDurationMs(job, now), 6000);
  assert.equal(formatJobDurationForRow(job, now), '6s');
});

test('not-started job has no duration and renders "-"', () => {
  assert.equal(computeJobDurationMs({ started_at: null, finished_at: null }), null);
  assert.equal(computeJobDurationMs({}), null);
  assert.equal(formatJobDurationForRow({ started_at: null }), '-');
});

test('formatJobDuration renders each magnitude band', () => {
  assert.equal(formatJobDuration(850), '850ms');
  assert.equal(formatJobDuration(6000), '6s');
  assert.equal(formatJobDuration(134000), '2m 14s');
  assert.equal(formatJobDuration(3 * 3600 * 1000 + 3 * 60 * 1000 + 5000), '3h 3m');
});

test('formatJobDuration hides seconds once hours are shown', () => {
  // 1h 3m 5s -> "1h 3m" (seconds dropped at the hour scale)
  assert.equal(formatJobDuration(3600 * 1000 + 3 * 60 * 1000 + 5000), '1h 3m');
});

test('formatJobDuration guards against null / negative / non-finite input', () => {
  assert.equal(formatJobDuration(null), '-');
  assert.equal(formatJobDuration(undefined), '-');
  assert.equal(formatJobDuration(-1), '-');
  assert.equal(formatJobDuration(NaN), '-');
  assert.equal(formatJobDuration(Infinity), '-');
});

test('negative interval (finished before started) is clamped to 0ms', () => {
  const job = {
    started_at: '2026-07-25T10:02:00.000Z',
    finished_at: '2026-07-25T10:00:00.000Z',
  };
  assert.equal(computeJobDurationMs(job), 0);
  assert.equal(formatJobDurationForRow(job), '0ms');
});
