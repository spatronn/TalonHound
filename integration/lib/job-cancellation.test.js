import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IntegrationJobAbortedError,
  throwIfAborted,
  isJobAbortedError,
  resolveJobFailureType
} from './job-cancellation.js';
import { FAILURE_TYPES } from './integrationQueueConfig.js';

test('throwIfAborted throws when signal is aborted', () => {
  const controller = new AbortController();
  controller.abort(FAILURE_TYPES.TIMEOUT);
  assert.throws(() => throwIfAborted(controller.signal), IntegrationJobAbortedError);
});

test('resolveJobFailureType maps timeout abort reason', () => {
  const controller = new AbortController();
  controller.abort(FAILURE_TYPES.TIMEOUT);
  try {
    throwIfAborted(controller.signal);
  } catch (err) {
    assert.equal(resolveJobFailureType(err), FAILURE_TYPES.TIMEOUT);
    assert.equal(isJobAbortedError(err), true);
  }
});

test('throwIfAborted is no-op for active signal', () => {
  const controller = new AbortController();
  assert.doesNotThrow(() => throwIfAborted(controller.signal));
});
