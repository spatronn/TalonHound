import test from 'node:test';
import assert from 'node:assert/strict';
import {
  IntegrationJobAbortedError,
  throwIfAborted,
  isJobAbortedError,
  resolveJobFailureType,
  resolveWorkerJobFailureType
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

// resolveWorkerJobFailureType: the worker 'failed' handler helper.
// Regression guard for the missing-import ReferenceError that crashed the worker
// on every failed integration job (commit 38832d6) and surfaced as spurious
// "Reconciled stale BullMQ state" logs after OTX runs (502/504).

test('resolveWorkerJobFailureType is a defined function (import regression guard)', () => {
  assert.equal(typeof resolveWorkerJobFailureType, 'function');
});

test('resolveWorkerJobFailureType passes through explicit failureType', () => {
  assert.equal(resolveWorkerJobFailureType({ failureType: FAILURE_TYPES.TIMEOUT }), FAILURE_TYPES.TIMEOUT);
});

test('resolveWorkerJobFailureType classifies aborted errors', () => {
  const err = new IntegrationJobAbortedError();
  assert.equal(resolveWorkerJobFailureType(err), FAILURE_TYPES.ABORTED);
});

test('resolveWorkerJobFailureType infers fetch error from network/timeout message', () => {
  assert.equal(
    resolveWorkerJobFailureType(new Error('network timeout while fetching')),
    FAILURE_TYPES.FETCH_ERROR
  );
  assert.equal(
    resolveWorkerJobFailureType(new Error('fetch failed: ECONNRESET')),
    FAILURE_TYPES.FETCH_ERROR
  );
});

test('resolveWorkerJobFailureType returns null (still marks failed) for OTX HTTP 5xx message', () => {
  // "AlienVault OTX API request failed (HTTP 504)" has no fetch/network/timeout
  // keyword, so it is unclassified — the job is still finalized as failed with the
  // real error message; failure_type is just untyped. The key regression: no crash.
  assert.equal(
    resolveWorkerJobFailureType(new Error('AlienVault OTX API request failed (HTTP 504)')),
    null
  );
});

test('resolveWorkerJobFailureType infers parse error from message', () => {
  assert.equal(
    resolveWorkerJobFailureType(new Error('failed to parse CSV row')),
    FAILURE_TYPES.PARSE_ERROR
  );
});

test('resolveWorkerJobFailureType returns null for unclassifiable errors', () => {
  assert.equal(resolveWorkerJobFailureType(new Error('something unexpected')), null);
});

test('resolveWorkerJobFailureType never throws on odd inputs', () => {
  assert.doesNotThrow(() => resolveWorkerJobFailureType(null));
  assert.doesNotThrow(() => resolveWorkerJobFailureType(undefined));
  assert.doesNotThrow(() => resolveWorkerJobFailureType('string error'));
});
