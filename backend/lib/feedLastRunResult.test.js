import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeLastRunResult, splitSkippedSemantics } from './feedLastRunResult.js';

test('successful empty sync → completed / no_new_data', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 0,
      records_inserted: 0,
      records_updated: 0,
      records_unchanged: 0,
      records_skipped: 0,
      records_failed: 0
    },
    { status: 'success' }
  );
  assert.equal(result.status, 'completed');
  assert.equal(result.outcome, 'no_new_data');
  assert.equal(result.message, 'No new data');
  assert.equal(result.checked, 0);
  assert.equal(result.new, 0);
});

test('successful no-change run → completed / no_changes', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 25682,
      records_inserted: 0,
      records_updated: 0,
      records_unchanged: 25682,
      records_skipped: 0,
      records_failed: 0
    },
    { status: 'success' }
  );
  assert.equal(result.status, 'completed');
  assert.equal(result.outcome, 'no_changes');
  assert.equal(result.unchanged, 25682);
  assert.equal(result.checked, 25682);
});

test('legacy skipped-as-unchanged remaps for non-USOM success', () => {
  const split = splitSkippedSemantics(
    { skipped: 100, unchanged: 0, failed: 0, inserted: 0, updated: 0 },
    'success',
    'alienvault_otx_import'
  );
  assert.equal(split.unchanged, 100);
  assert.equal(split.filtered, 0);
  assert.equal(split.rejected, 0);
});

test('USOM skipped stays rejected', () => {
  const split = splitSkippedSemantics(
    { skipped: 5, unchanged: 0, failed: 0, inserted: 0, updated: 0 },
    'success',
    'usom_import'
  );
  assert.equal(split.unchanged, 0);
  assert.equal(split.filtered, 0);
  assert.equal(split.rejected, 5);
});

test('USOM skipped stays rejected counter but does not force warning status', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 2196,
      records_inserted: 10,
      records_updated: 0,
      records_unchanged: 2174,
      records_skipped: 12,
      records_failed: 0
    },
    { status: 'success', jobType: 'usom_import' }
  );
  assert.equal(result.status, 'completed');
  assert.equal(result.outcome, 'changes');
  assert.equal(result.rejected, 12);
  assert.equal(result.filtered, 0);
  assert.equal(result.new, 10);
});

test('high legacy skipped/rejected ratio stays completed', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 14877,
      records_inserted: 69,
      records_updated: 46,
      records_unchanged: 0,
      records_skipped: 14716,
      records_failed: 0
    },
    { status: 'success', jobType: 'urlhaus_import' }
  );
  assert.equal(result.status, 'completed');
  assert.equal(result.outcome, 'changes');
  assert.equal(result.new, 69);
  assert.equal(result.updated, 46);
  assert.equal(result.unchanged, 14716);
  assert.equal(result.filtered, 0);
  assert.equal(result.rejected, 0);
  assert.equal(result.failed, 0);
});

test('modern parse/map skipped maps to filtered not rejected', () => {
  const split = splitSkippedSemantics(
    { skipped: 3, unchanged: 90, failed: 0, inserted: 5, updated: 2, processed: 100 },
    'success',
    'urlhaus_import'
  );
  assert.equal(split.unchanged, 90);
  assert.equal(split.filtered, 3);
  assert.equal(split.rejected, 0);
  assert.equal(split.failed, 0);
});

test('records_failed maps to rejected/failed; filtered alone is not a warning', () => {
  const filteredOnly = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 100,
      records_inserted: 5,
      records_updated: 0,
      records_unchanged: 90,
      records_skipped: 5,
      records_failed: 0
    },
    { status: 'success', jobType: 'threatfox_import' }
  );
  assert.equal(filteredOnly.status, 'completed');
  assert.equal(filteredOnly.filtered, 5);
  assert.equal(filteredOnly.rejected, 0);
  assert.equal(filteredOnly.failed, 0);

  const withFailed = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 100,
      records_inserted: 50,
      records_updated: 0,
      records_unchanged: 30,
      records_skipped: 0,
      records_failed: 20
    },
    { status: 'success' }
  );
  assert.equal(withFailed.status, 'completed_with_warnings');
  assert.equal(withFailed.failed, 20);
  assert.equal(withFailed.rejected, 20);
  assert.equal(withFailed.filtered, 0);
});

test('legacy malwarebazaar skipped remaps to unchanged', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 917,
      records_inserted: 70,
      records_updated: 60,
      records_unchanged: 0,
      records_skipped: 787,
      records_failed: 0
    },
    { status: 'success', jobType: 'malwarebazaar_import' }
  );
  assert.equal(result.status, 'completed');
  assert.equal(result.unchanged, 787);
  assert.equal(result.filtered, 0);
  assert.equal(result.rejected, 0);
});

test('truncated partial fetch → completed_with_warnings', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 100,
      records_inserted: 5,
      records_updated: 0,
      records_unchanged: 95,
      records_skipped: 0,
      records_failed: 0,
      run_details: { truncated: true }
    },
    { status: 'success', runDetails: { truncated: true } }
  );
  assert.equal(result.status, 'completed_with_warnings');
  assert.equal(result.message, 'Partial fetch');
});

test('significant records_failed share → completed_with_warnings', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 100,
      records_inserted: 50,
      records_updated: 0,
      records_unchanged: 30,
      records_skipped: 0,
      records_failed: 20
    },
    { status: 'success' }
  );
  assert.equal(result.status, 'completed_with_warnings');
  assert.equal(result.message, 'Partial result');
});

test('auth/network failure → failed with message', () => {
  const result = normalizeLastRunResult(
    { status: 'failed', records_processed: 0 },
    { status: 'failed', errorMessage: 'Authentication rejected' }
  );
  assert.equal(result.status, 'failed');
  assert.equal(result.message, 'Authentication rejected');
});

test('never run → never', () => {
  const result = normalizeLastRunResult(null, { status: 'never' });
  assert.equal(result.status, 'never');
  assert.equal(result.message, 'No successful run');
});

test('changes run exposes new/updated', () => {
  const result = normalizeLastRunResult(
    {
      status: 'success',
      records_processed: 14806,
      records_inserted: 10,
      records_updated: 6,
      records_unchanged: 14746,
      records_skipped: 0,
      records_failed: 0
    },
    { status: 'success' }
  );
  assert.equal(result.status, 'completed');
  assert.equal(result.outcome, 'changes');
  assert.equal(result.new, 10);
  assert.equal(result.updated, 6);
  assert.equal(result.unchanged, 14746);
});

test('running status is not remapped to completed', () => {
  const result = normalizeLastRunResult(
    { status: 'running', records_processed: 0 },
    { status: 'running' }
  );
  assert.equal(result.status, 'running');
});

test('safe defaults — no NaN/undefined counters', () => {
  const result = normalizeLastRunResult({}, { status: 'success' });
  for (const key of ['checked', 'new', 'updated', 'unchanged', 'filtered', 'rejected', 'failed', 'expired']) {
    assert.equal(typeof result[key], 'number');
    assert.equal(Number.isNaN(result[key]), false);
  }
});
