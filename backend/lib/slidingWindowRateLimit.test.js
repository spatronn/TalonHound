import test from 'node:test';
import assert from 'node:assert/strict';
import { createSlidingWindowRateLimit } from './slidingWindowRateLimit.js';

test('check allows up to limit then rejects within window', () => {
  let now = 1_000;
  const rl = createSlidingWindowRateLimit({
    windowMs: 60_000,
    maxBuckets: 100,
    sweepIntervalMs: 60_000,
    now: () => now,
    setIntervalFn: () => ({ unref() {} }),
    clearIntervalFn: () => {}
  });
  assert.equal(rl.check('a', 2), true);
  assert.equal(rl.check('a', 2), true);
  assert.equal(rl.check('a', 2), false);
  rl.stop();
});

test('opportunistic delete when window expires', () => {
  let now = 1_000;
  const rl = createSlidingWindowRateLimit({
    windowMs: 1_000,
    maxBuckets: 100,
    sweepIntervalMs: 60_000,
    now: () => now,
    setIntervalFn: () => ({ unref() {} }),
    clearIntervalFn: () => {}
  });
  assert.equal(rl.check('stale', 1), true);
  assert.equal(rl.size(), 1);
  now = 3_000;
  assert.equal(rl.check('fresh', 1), true);
  // Rolling a new window for a different key opportunistically prunes expired.
  assert.equal(rl._buckets.has('stale'), false);
  rl.stop();
});

test('prune enforces max bucket size', () => {
  let now = 1_000;
  const rl = createSlidingWindowRateLimit({
    windowMs: 60_000,
    maxBuckets: 2,
    sweepIntervalMs: 60_000,
    now: () => now,
    setIntervalFn: () => ({ unref() {} }),
    clearIntervalFn: () => {}
  });
  rl.check('k1', 10);
  rl.check('k2', 10);
  rl.check('k3', 10);
  assert.ok(rl.size() <= 2);
  assert.equal(rl.prune(), rl.size());
  rl.stop();
});

test('periodic sweep removes expired buckets', () => {
  let now = 1_000;
  let sweepCb = null;
  const rl = createSlidingWindowRateLimit({
    windowMs: 500,
    maxBuckets: 100,
    sweepIntervalMs: 1_000,
    now: () => now,
    setIntervalFn: (cb) => {
      sweepCb = cb;
      return { unref() {} };
    },
    clearIntervalFn: () => {}
  });
  rl.check('old', 5);
  now = 2_000;
  sweepCb();
  assert.equal(rl.size(), 0);
  rl.stop();
});
