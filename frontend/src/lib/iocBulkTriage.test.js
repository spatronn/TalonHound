import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BULK_TRIAGE_MAX,
  parseIocRowId,
  toggleSelectedId,
  selectPageIds,
  deselectPageIds,
  pageSelectionState,
  formatBulkTriageSummary,
  remainingSelectedAfterBulk,
  bulkConfirmDisabled
} from './iocBulkTriage.js';

test('parseIocRowId accepts positive integers only', () => {
  assert.equal(parseIocRowId({ id: 12 }), 12);
  assert.equal(parseIocRowId({ id: '7' }), 7);
  assert.equal(parseIocRowId({ id: 0 }), null);
  assert.equal(parseIocRowId({ id: -1 }), null);
  assert.equal(parseIocRowId({ public_id: 'abc' }), null);
});

test('toggleSelectedId caps at 100 and never selects by query', () => {
  const selected = new Set();
  for (let i = 1; i <= BULK_TRIAGE_MAX; i += 1) {
    const r = toggleSelectedId(selected, i);
    assert.equal(r.capped, false);
    selected.clear();
    for (const id of r.selected) selected.add(id);
  }
  const over = toggleSelectedId(selected, 101);
  assert.equal(over.capped, true);
  assert.equal(over.selected.size, 100);
  assert.equal(over.selected.has(101), false);
});

test('toggleSelectedId deselects an already selected id', () => {
  const r = toggleSelectedId(new Set([3, 5]), 3);
  assert.equal(r.capped, false);
  assert.deepEqual([...r.selected], [5]);
});

test('selectPageIds adds only explicit page ids up to the cap', () => {
  const existing = new Set([1, 2]);
  const r = selectPageIds(existing, [2, 3, 4]);
  assert.equal(r.capped, false);
  assert.deepEqual([...r.selected].sort((a, b) => a - b), [1, 2, 3, 4]);
});

test('selectPageIds reports capped when page would exceed max', () => {
  const selected = new Set(Array.from({ length: 99 }, (_, i) => i + 1));
  const r = selectPageIds(selected, [200, 201]);
  assert.equal(r.capped, true);
  assert.equal(r.selected.size, 100);
  assert.equal(r.selected.has(200), true);
  assert.equal(r.selected.has(201), false);
});

test('deselectPageIds removes only the current page', () => {
  const next = deselectPageIds(new Set([1, 2, 9]), [1, 2]);
  assert.deepEqual([...next], [9]);
});

test('pageSelectionState distinguishes all / some / none', () => {
  assert.deepEqual(pageSelectionState(new Set([1, 2]), [1, 2]), { all: true, some: false });
  assert.deepEqual(pageSelectionState(new Set([1]), [1, 2]), { all: false, some: true });
  assert.deepEqual(pageSelectionState(new Set(), [1, 2]), { all: false, some: false });
});

test('formatBulkTriageSummary includes skipped and failed when present', () => {
  assert.equal(
    formatBulkTriageSummary({ requested: 4, succeeded: 2, skipped: 1, failed: 1 }),
    '4 selected · 2 succeeded, 1 skipped, 1 failed'
  );
  assert.equal(
    formatBulkTriageSummary({ requested: 2, succeeded: 2, skipped: 0, failed: 0 }),
    '2 selected · 2 succeeded'
  );
});

test('remainingSelectedAfterBulk keeps only failed ids', () => {
  const next = remainingSelectedAfterBulk([
    { id: 1, status: 'ok' },
    { id: 2, status: 'skipped' },
    { id: 3, status: 'error', message: 'IOC not found' }
  ]);
  assert.deepEqual([...next], [3]);
});

test('bulkConfirmDisabled requires reason and picker choice when asked', () => {
  assert.equal(bulkConfirmDisabled({ requireReason: true, reason: 'ab' }), true);
  assert.equal(bulkConfirmDisabled({ requireReason: true, reason: 'ok reason' }), false);
  assert.equal(bulkConfirmDisabled({ requireChoice: true, choice: '' }), true);
  assert.equal(bulkConfirmDisabled({ requireChoice: true, choice: 'malware' }), false);
  assert.equal(bulkConfirmDisabled({}), false);
});
