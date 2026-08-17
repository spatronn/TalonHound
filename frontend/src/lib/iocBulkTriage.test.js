import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BULK_TRIAGE_MAX,
  IOC_LIST_BROWSE_CONTEXT,
  IOC_LIST_DEFAULT_PAGE_SIZE,
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
  bulkIocIdsForContext,
  bulkIocIdsForVisiblePage,
  formatPageSelectionLabel
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

function browseContext({ page = 1, pageSize = IOC_LIST_DEFAULT_PAGE_SIZE } = {}) {
  return iocListResultContextKey({ dslActive: false, page, pageSize });
}

function searchContext(query, { cursor = '', pageSize = IOC_LIST_DEFAULT_PAGE_SIZE } = {}) {
  return iocListResultContextKey({ dslActive: true, executedQuery: query, cursor, pageSize });
}

function selectIds(state, ids) {
  let selected = state.selectedIds;
  for (const id of ids) {
    selected = toggleSelectedId(selected, id).selected;
  }
  return { contextKey: state.contextKey, selectedIds: selected };
}

test('iocListResultContextKey includes visible page identity and ignores unexecuted input', () => {
  assert.equal(browseContext(), IOC_LIST_BROWSE_CONTEXT);
  assert.equal(
    searchContext('tag contains "mirai"'),
    searchContext('  tag contains "mirai"  ')
  );
  assert.notEqual(
    browseContext({ page: 1 }),
    browseContext({ page: 2 })
  );
  assert.notEqual(
    searchContext('tag contains "mirai"'),
    searchContext('tag contains "mirai"', { cursor: 'page-2' })
  );
  assert.notEqual(
    searchContext('tag contains "mirai"', { pageSize: 25 }),
    searchContext('tag contains "mirai"', { pageSize: 50 })
  );
  assert.equal(
    iocListResultContextKey({ dslActive: false, searchInput: 'tag contains "mirai"' }),
    IOC_LIST_BROWSE_CONTEXT
  );
  assert.equal(
    iocListResultContextKey({ deepSearchId: 'ds-1', pageSize: 25, cursor: '' }),
    'deep:ds-1:s25:c'
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

test('browse page 1 selection is cleared when going to page 2', () => {
  let state = { contextKey: browseContext({ page: 1 }), selectedIds: new Set() };
  state = selectIds(state, [71, 72, 73]);
  const page2 = browseContext({ page: 2 });
  state = applyIocSelectionContext(state, page2);
  assert.equal(state.selectedIds.size, 0);
  assert.deepEqual(bulkIocIdsForVisiblePage(state, page2, [81, 82, 83]), []);
});

test('search page 1 selection is cleared when going to the next cursor', () => {
  const query = 'tag contains "mirai"';
  let state = { contextKey: searchContext(query), selectedIds: new Set() };
  state = selectIds(state, [61, 62, 63, 64, 65]);
  const page2 = searchContext(query, { cursor: 'page-2' });
  state = applyIocSelectionContext(state, page2);
  assert.equal(state.selectedIds.size, 0);
});

test('header select-all is current-page only and resets after pagination', () => {
  const page1Ids = [1, 2, 3, 4, 5];
  const selected = selectPageIds(new Set(), page1Ids).selected;
  assert.equal(selected.size, 5);
  assert.deepEqual(pageSelectionState(selected, page1Ids), { all: true, some: false });

  const after = applyIocSelectionContext(
    { contextKey: browseContext({ page: 1 }), selectedIds: selected },
    browseContext({ page: 2 })
  );
  assert.equal(after.selectedIds.size, 0);
  assert.deepEqual(pageSelectionState(after.selectedIds, [6, 7, 8]), { all: false, some: false });
});

test('manual partial selection is indeterminate and resets on page change', () => {
  const pageIds = [1, 2, 3];
  const selected = new Set([1]);
  assert.deepEqual(pageSelectionState(selected, pageIds), { all: false, some: true });
  const after = applyIocSelectionContext(
    { contextKey: browseContext({ page: 1 }), selectedIds: selected },
    browseContext({ page: 2 })
  );
  assert.deepEqual(pageSelectionState(after.selectedIds, [4, 5, 6]), { all: false, some: false });
});

test('page-size change clears selection', () => {
  let state = { contextKey: browseContext({ pageSize: 25 }), selectedIds: new Set() };
  state = selectIds(state, [81, 82]);
  state = applyIocSelectionContext(state, browseContext({ pageSize: 50 }));
  assert.equal(state.selectedIds.size, 0);
});

test('null row ids do not affect header select-all math', () => {
  const pageIds = [1, null, 2];
  assert.deepEqual(pageSelectionState(new Set([1, 2]), pageIds), { all: true, some: false });
  assert.deepEqual(pageSelectionState(new Set([1]), pageIds), { all: false, some: true });
});

test('same-page row toggle still selects and deselects', () => {
  const ctx = browseContext({ page: 1 });
  let state = { contextKey: ctx, selectedIds: new Set() };
  state = selectIds(state, [91]);
  assert.deepEqual([...state.selectedIds], [91]);
  state = selectIds(state, [91]);
  assert.equal(state.selectedIds.size, 0);
});

test('bulk payload after page change cannot include prior-page IDs', () => {
  const page1 = browseContext({ page: 1 });
  const page2 = browseContext({ page: 2 });
  const stale = { contextKey: page1, selectedIds: new Set([101, 102, 103]) };
  assert.deepEqual(bulkIocIdsForVisiblePage(stale, page2, [201, 202]), []);
  const page2State = applyIocSelectionContext(stale, page2);
  const selectedPage2 = selectIds(page2State, [201]);
  assert.deepEqual(bulkIocIdsForVisiblePage(selectedPage2, page2, [201, 202]), [201]);
  assert.equal(bulkIocIdsForVisiblePage(selectedPage2, page2, [201, 202]).includes(101), false);
});

test('header checkbox / indeterminate state resets after search-context change', () => {
  const browse = browseContext();
  const search = searchContext('tag contains "mirai"');
  const selected = new Set([1, 2, 3]);
  const newPageIds = [1, 10, 11];
  assert.deepEqual(pageSelectionState(selected, newPageIds), { all: false, some: true });
  const after = applyIocSelectionContext({ contextKey: browse, selectedIds: selected }, search);
  assert.deepEqual(pageSelectionState(after.selectedIds, newPageIds), { all: false, some: false });
  assert.equal(selectedIdsForResultContext(selected, browse, search).size, 0);
});

test('unexecuted search-box text does not change the result context', () => {
  const browse = iocListResultContextKey({ dslActive: false, searchInput: 'tag contains "mirai"', page: 1, pageSize: 25 });
  assert.equal(browse, IOC_LIST_BROWSE_CONTEXT);
});

test('re-running the same search on the same visible page preserves selection', () => {
  const query = 'tag contains "mirai"';
  let state = { contextKey: searchContext(query), selectedIds: new Set() };
  state = selectIds(state, [11]);
  state = applyIocSelectionContext(state, searchContext(query, { cursor: '' }));
  assert.deepEqual([...state.selectedIds], [11]);
});

test('re-running the same search after resetting to the first page clears page-2 selection', () => {
  const query = 'tag contains "mirai"';
  let state = { contextKey: searchContext(query, { cursor: 'page-2' }), selectedIds: new Set() };
  state = selectIds(state, [12]);
  state = applyIocSelectionContext(state, searchContext(query, { cursor: '' }));
  assert.equal(state.selectedIds.size, 0);
});

test('formatPageSelectionLabel is page-scoped copy', () => {
  assert.equal(formatPageSelectionLabel(1), '1 selected on this page');
  assert.equal(formatPageSelectionLabel(25), '25 selected on this page');
});
