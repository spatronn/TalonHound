import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BULK_TRIAGE_MAX,
  IOC_LIST_BROWSE_CONTEXT,
  parseIocRowId,
  toggleSelectedId,
  selectPageIds,
  deselectPageIds,
  pageSelectionState,
  formatBulkTriageSummary,
  remainingSelectedAfterBulk,
  bulkConfirmDisabled,
  iocListResultContextKey,
  selectedIdsForResultContext,
  applyIocSelectionContext,
  bulkIocIdsForContext
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

function browseContext() {
  return iocListResultContextKey({ dslActive: false });
}

function searchContext(query) {
  return iocListResultContextKey({ dslActive: true, executedQuery: query });
}

function selectIds(state, ids) {
  let selected = state.selectedIds;
  for (const id of ids) {
    selected = toggleSelectedId(selected, id).selected;
  }
  return { contextKey: state.contextKey, selectedIds: selected };
}

test('iocListResultContextKey ignores page, cursor, page size, and unexecuted input', () => {
  assert.equal(browseContext(), IOC_LIST_BROWSE_CONTEXT);
  assert.equal(
    searchContext('tag contains "mirai"'),
    searchContext('  tag contains "mirai"  ')
  );
  assert.equal(
    iocListResultContextKey({ dslActive: true, executedQuery: 'tag contains "mirai"', page: 2, cursor: 'abc', pageSize: 50 }),
    searchContext('tag contains "mirai"')
  );
  assert.equal(
    iocListResultContextKey({ deepSearchId: 'ds-1', dslActive: false }),
    'deep:ds-1'
  );
});

test('browse selection is cleared when a search is executed and cannot leak into the bulk payload', () => {
  let state = { contextKey: browseContext(), selectedIds: new Set() };
  state = selectIds(state, [11, 12, 13]);
  assert.equal(state.selectedIds.size, 3);

  const search = searchContext('tag contains "mirai"');
  state = applyIocSelectionContext(state, search);
  assert.equal(state.selectedIds.size, 0);
  assert.deepEqual(bulkIocIdsForContext(state, search), []);
  assert.equal(bulkIocIdsForContext(state, search).includes(11), false);
  assert.equal(bulkIocIdsForContext(state, search).includes(12), false);
  assert.equal(bulkIocIdsForContext(state, search).includes(13), false);
});

test('search A selection is cleared when search B is executed', () => {
  let state = { contextKey: searchContext('tag contains "mirai"'), selectedIds: new Set() };
  state = selectIds(state, [21, 22]);
  state = applyIocSelectionContext(state, searchContext('tag contains "emotet"'));
  assert.equal(state.selectedIds.size, 0);
});

test('search selection is cleared when returning to default browse', () => {
  let state = { contextKey: searchContext('tag contains "mirai"'), selectedIds: new Set() };
  state = selectIds(state, [31]);
  state = applyIocSelectionContext(state, browseContext());
  assert.equal(state.selectedIds.size, 0);
});

test('search A selection is cleared when a different saved search query is executed', () => {
  let state = { contextKey: searchContext('type equals "ip"'), selectedIds: new Set() };
  state = selectIds(state, [41]);
  const savedB = searchContext('source contains "usom"');
  state = applyIocSelectionContext(state, savedB);
  assert.equal(state.selectedIds.size, 0);
  assert.deepEqual(bulkIocIdsForContext(state, savedB), []);
});

test('search A selection is cleared when Advanced Search applies a different executed query', () => {
  let state = { contextKey: searchContext('ioc contains "a"'), selectedIds: new Set() };
  state = selectIds(state, [51]);
  state = applyIocSelectionContext(state, searchContext('ioc contains "a" AND type equals "domain"'));
  assert.equal(state.selectedIds.size, 0);
});

test('same-search pagination preserves selection', () => {
  const query = 'tag contains "mirai"';
  let state = { contextKey: searchContext(query), selectedIds: new Set() };
  state = selectIds(state, [61, 62]);
  const page2 = iocListResultContextKey({
    dslActive: true,
    executedQuery: query,
    cursor: 'page-2',
    page: 2
  });
  state = applyIocSelectionContext(state, page2);
  assert.deepEqual([...state.selectedIds].sort((a, b) => a - b), [61, 62]);
});

test('same default-browse pagination preserves selection', () => {
  let state = { contextKey: browseContext(), selectedIds: new Set() };
  state = selectIds(state, [71, 72, 73]);
  const page2 = iocListResultContextKey({ dslActive: false, page: 2, pageSize: 25 });
  state = applyIocSelectionContext(state, page2);
  assert.equal(state.selectedIds.size, 3);
});

test('header checkbox / indeterminate state resets after result context change', () => {
  const browse = browseContext();
  const search = searchContext('tag contains "mirai"');
  const selected = new Set([1, 2, 3]);
  const newPageIds = [1, 10, 11];
  assert.deepEqual(pageSelectionState(selected, newPageIds), { all: false, some: true });

  const after = applyIocSelectionContext({ contextKey: browse, selectedIds: selected }, search);
  assert.deepEqual(pageSelectionState(after.selectedIds, newPageIds), { all: false, some: false });
  assert.equal(selectedIdsForResultContext(selected, browse, search).size, 0);
});

test('bulk action after context change cannot include stale IDs from previous context', () => {
  const browse = browseContext();
  const search = searchContext('tag contains "mirai"');
  const stale = { contextKey: browse, selectedIds: new Set([101, 102, 103]) };
  const payload = bulkIocIdsForContext(stale, search);
  assert.deepEqual(payload, []);
  assert.equal(payload.some((id) => [101, 102, 103].includes(id)), false);
});

test('page-size change on the same executed query preserves selection', () => {
  const query = 'tag contains "mirai"';
  let state = { contextKey: searchContext(query), selectedIds: new Set() };
  state = selectIds(state, [81]);
  state = applyIocSelectionContext(
    state,
    iocListResultContextKey({ dslActive: true, executedQuery: query, pageSize: 100 })
  );
  assert.deepEqual([...state.selectedIds], [81]);
});

test('unexecuted search-box text does not change the result context', () => {
  const browse = iocListResultContextKey({ dslActive: false, searchInput: 'tag contains "mirai"' });
  assert.equal(browse, IOC_LIST_BROWSE_CONTEXT);
});
