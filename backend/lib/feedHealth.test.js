import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveFeedHealthState,
  resolveFeedRuntimeState,
  pickHealthStatus
} from './feedHealth.js';

test('successful sync with new=0 is healthy', () => {
  assert.equal(resolveFeedHealthState(true, 'success', 0, []), 'success');
});

test('successful sync with processed=0 is healthy', () => {
  assert.equal(resolveFeedHealthState(true, 'success', 0, ['no_delta']), 'success');
});

test('skipped_unchanged (URLHaus etag noop) is healthy', () => {
  assert.equal(resolveFeedHealthState(true, 'skipped_unchanged', 0, []), 'success');
});

test('queue skipped status is healthy when intentional noop', () => {
  assert.equal(resolveFeedHealthState(true, 'skipped', 0, []), 'success');
});

test('AlienVault-style empty success is healthy', () => {
  assert.equal(resolveFeedHealthState(true, 'success', 0, []), 'success');
});

test('never run is never (not warning)', () => {
  assert.equal(resolveFeedHealthState(true, 'never', 0, []), 'never');
  assert.equal(resolveFeedHealthState(true, '', 0, []), 'never');
});

test('failed status is failed', () => {
  assert.equal(resolveFeedHealthState(true, 'failed', 0, []), 'failed');
  assert.equal(resolveFeedHealthState(true, 'fail', 0, []), 'failed');
});

test('high_failed hint yields warning', () => {
  assert.equal(resolveFeedHealthState(true, 'success', 0, ['high_failed']), 'warning');
});

test('partial_fetch hint yields warning', () => {
  assert.equal(resolveFeedHealthState(true, 'success', 0, ['partial_fetch']), 'warning');
});

test('truncated run_details yields warning', () => {
  assert.equal(
    resolveFeedHealthState(true, 'success', 0, [], { runDetails: { truncated: true } }),
    'warning'
  );
});

test('consecutive failures yield warning', () => {
  assert.equal(resolveFeedHealthState(true, 'success', 2, []), 'warning');
});

test('running/queued are not health warnings when no failures', () => {
  assert.equal(resolveFeedHealthState(true, 'running', 0, []), 'success');
  assert.equal(resolveFeedHealthState(true, 'queued', 0, []), 'success');
  assert.equal(resolveFeedRuntimeState('running'), 'running');
  assert.equal(resolveFeedRuntimeState('queued'), 'queued');
  assert.equal(resolveFeedRuntimeState('success'), null);
});

test('running with consecutive failures stays warning', () => {
  assert.equal(resolveFeedHealthState(true, 'running', 1, []), 'warning');
});

test('disabled feed is disabled', () => {
  assert.equal(resolveFeedHealthState(false, 'failed', 5, ['high_failed']), 'disabled');
});

test('no_delta / high_skipped hints alone do not create warning', () => {
  assert.equal(resolveFeedHealthState(true, 'success', 0, ['no_delta']), 'success');
  assert.equal(resolveFeedHealthState(true, 'success', 0, ['high_skipped']), 'success');
});

test('pickHealthStatus prefers terminal success while runtime in flight', () => {
  assert.equal(
    pickHealthStatus({ status: 'running' }, { status: 'success' }),
    'success'
  );
  assert.equal(
    pickHealthStatus({ status: 'running' }, null),
    'never'
  );
  assert.equal(
    pickHealthStatus({ status: 'skipped_unchanged' }, null),
    'skipped_unchanged'
  );
});
