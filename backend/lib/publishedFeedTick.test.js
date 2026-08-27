import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  runPublishedFeedSchedulerTick,
  getPublishedFeedTickState,
  resetPublishedFeedTickStateForTests,
  resolvePublishedFeedTickTimeoutMs,
  PUBLISHED_FEED_TICK_TIMEOUT_MS_DEFAULT
} from './publishedFeedTick.js';

beforeEach(() => {
  resetPublishedFeedTickStateForTests();
});

test('resolvePublishedFeedTickTimeoutMs defaults and clamps', () => {
  assert.equal(resolvePublishedFeedTickTimeoutMs(undefined), PUBLISHED_FEED_TICK_TIMEOUT_MS_DEFAULT);
  assert.equal(resolvePublishedFeedTickTimeoutMs(''), PUBLISHED_FEED_TICK_TIMEOUT_MS_DEFAULT);
  assert.equal(resolvePublishedFeedTickTimeoutMs('bogus'), PUBLISHED_FEED_TICK_TIMEOUT_MS_DEFAULT);
  assert.equal(resolvePublishedFeedTickTimeoutMs('3600000'), 3_600_000);
});

test('overlapping tick skipped while in progress', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let entered;
  const enteredGate = new Promise((resolve) => { entered = resolve; });
  const regenerate = async () => {
    entered();
    await gate;
    return { due: 0 };
  };

  const first = runPublishedFeedSchedulerTick({}, {
    regenerateAllEnabledFeeds: regenerate,
    skipCleanup: true,
    timeoutMs: 5_000
  });

  await enteredGate;
  assert.equal(getPublishedFeedTickState().inProgress, true);

  const second = await runPublishedFeedSchedulerTick({}, {
    regenerateAllEnabledFeeds: async () => ({ due: 99 }),
    skipCleanup: true
  });
  assert.deepEqual(second, { skipped: true, reason: 'in_progress' });

  release();
  const firstResult = await first;
  assert.equal(firstResult.ok, true);
  assert.equal(getPublishedFeedTickState().inProgress, false);
});

test('flag cleared after error', async () => {
  const result = await runPublishedFeedSchedulerTick({}, {
    regenerateAllEnabledFeeds: async () => {
      throw new Error('boom');
    },
    skipCleanup: true,
    timeoutMs: 5_000
  });
  assert.equal(result.ok, false);
  assert.match(result.error, /boom/);
  assert.equal(getPublishedFeedTickState().inProgress, false);
  assert.ok(getPublishedFeedTickState().lastTickCompletedAt);
});

test('flag cleared after timeout (mocked stuck regenerate)', async () => {
  const result = await runPublishedFeedSchedulerTick({}, {
    regenerateAllEnabledFeeds: () => new Promise(() => { /* never settles */ }),
    skipCleanup: true,
    timeoutMs: 30
  });
  assert.equal(result.ok, false);
  assert.equal(result.timedOut, true);
  assert.equal(getPublishedFeedTickState().inProgress, false);
  assert.ok(getPublishedFeedTickState().lastTickCompletedAt);
});

test('subsequent tick can run after timeout', async () => {
  const stuck = await runPublishedFeedSchedulerTick({}, {
    regenerateAllEnabledFeeds: () => new Promise(() => {}),
    skipCleanup: true,
    timeoutMs: 20
  });
  assert.equal(stuck.timedOut, true);

  let ran = false;
  const next = await runPublishedFeedSchedulerTick({}, {
    regenerateAllEnabledFeeds: async () => {
      ran = true;
      return { due: 1 };
    },
    skipCleanup: true,
    timeoutMs: 5_000
  });
  assert.equal(next.ok, true);
  assert.equal(ran, true);
  assert.equal(getPublishedFeedTickState().inProgress, false);
});
