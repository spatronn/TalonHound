import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildJobResultSnapshot,
  formatJobResultSummary,
  mapQueueJobResult,
  resolveSkipResultCode,
  sanitizeResultDetails,
  RESULT_CODES
} from './jobResultSnapshot.js';

test('completed with changes snapshot', () => {
  const snap = buildJobResultSnapshot({
    status: 'success',
    triggeredBy: 'scheduler',
    runMode: 'incremental',
    metrics: {
      records_processed: 12540,
      records_inserted: 46,
      records_updated: 250,
      records_unchanged: 12214,
      records_skipped: 30,
      records_failed: 0,
      records_removed: 8
    }
  });
  assert.equal(snap.result_code, RESULT_CODES.COMPLETED_WITH_CHANGES);
  assert.equal(snap.result_summary, '46 new · 250 updated');
  assert.equal(snap.result_details.new, 46);
  assert.equal(snap.result_details.updated, 250);
  assert.equal(snap.result_details.expired, 8);
  assert.equal(snap.result_details.trigger, 'scheduled');
  assert.equal(snap.run_mode, 'incremental');
});

test('no changes vs no new data', () => {
  const noChanges = buildJobResultSnapshot({
    status: 'success',
    metrics: {
      records_processed: 100,
      records_inserted: 0,
      records_updated: 0,
      records_unchanged: 100
    }
  });
  assert.equal(noChanges.result_code, RESULT_CODES.COMPLETED_NO_CHANGES);
  assert.equal(noChanges.result_summary, 'No changes');

  const noData = buildJobResultSnapshot({
    status: 'success',
    metrics: {
      records_processed: 0,
      records_inserted: 0,
      records_updated: 0
    }
  });
  assert.equal(noData.result_code, RESULT_CODES.COMPLETED_NO_NEW_DATA);
  assert.equal(noData.result_summary, 'No new data');
});

test('skipped unchanged and locked', () => {
  assert.equal(resolveSkipResultCode('unchanged'), RESULT_CODES.SKIPPED_UNCHANGED);
  assert.equal(resolveSkipResultCode('same_hash'), RESULT_CODES.SKIPPED_UNCHANGED);
  assert.equal(resolveSkipResultCode('lock_not_acquired'), RESULT_CODES.SKIPPED_LOCKED);

  const skipped = buildJobResultSnapshot({
    status: 'skipped',
    skipReason: 'unchanged',
    triggeredBy: 'manual-ui-one',
    metrics: { records_processed: 0 }
  });
  assert.equal(skipped.result_code, RESULT_CODES.SKIPPED_UNCHANGED);
  assert.equal(skipped.result_details.trigger, 'manual');
});

test('failed snapshot', () => {
  const failed = buildJobResultSnapshot({
    status: 'failed',
    errorMessage: 'source unavailable',
    metrics: {}
  });
  assert.equal(failed.result_code, RESULT_CODES.FAILED);
  assert.equal(failed.result_summary, 'Failed');
});

test('legacy null snapshot maps safely', () => {
  const mapped = mapQueueJobResult({
    job_id: '1',
    status: 'success',
    result_code: null,
    result_summary: null,
    result_details: null
  });
  assert.equal(mapped.available, false);
  assert.equal(mapped.result_summary, null);
});

test('sanitizeResultDetails whitelists keys', () => {
  const clean = sanitizeResultDetails({
    schema_version: 1,
    new: 1,
    secret_token: 'nope',
    stack: 'boom'
  });
  assert.equal(clean.new, 1);
  assert.equal(clean.secret_token, undefined);
  assert.equal(clean.stack, undefined);
});

test('formatJobResultSummary omits Completed prefix', () => {
  assert.equal(
    formatJobResultSummary({
      result_code: RESULT_CODES.COMPLETED_WITH_CHANGES,
      new: 11,
      updated: 0
    }),
    '11 new'
  );
});

test('manual USOM trigger normalizes to manual', () => {
  const snap = buildJobResultSnapshot({
    status: 'success',
    triggeredBy: 'manual-ui-one:full_reconciliation',
    runMode: 'full_reconciliation',
    metrics: { records_processed: 10, records_inserted: 2, records_updated: 0 }
  });
  assert.equal(snap.result_details.trigger, 'manual');
  assert.equal(snap.run_mode, 'full_reconciliation');
});
