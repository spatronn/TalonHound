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
  formatPageSelectionLabel,
  SELECTION_MODE_NONE,
  SELECTION_MODE_PAGE,
  SELECTION_MODE_ALL_MATCHING,
  iocListQueryContextKey,
  shouldOfferSelectAllMatching,
  formatSelectAllMatchingActionLabel,
  formatAllMatchingSelectionLabel,
  applySelectionForContexts,
  queryWideBulkPath,
  buildQueryWideBulkPayload,
  formatQueryWideConfirmTitle,
  formatQueryWideConfirmDescription,
  formatQueryWideConfirmButton,
  QUERY_WIDE_PREVIEW_LOADING,
  QUERY_WIDE_PREVIEW_READY,
  QUERY_WIDE_PREVIEW_ERROR,
  QUERY_WIDE_PREVIEW_UNSUPPORTED,
  isFiniteExactMatchCount,
  searchHasMoreMatchesThanPage,
  bindQueryWidePreview,
  previewCountForExecutedQuery,
  resolvedExactMatchCount,
  buildQueryWidePreviewPayload,
  formatQueryWidePreviewLoadingLabel,
  queryWidePreviewFromSuccess,
  queryWidePreviewFromFailure,
  shouldRequestQueryWidePreview
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

const GMAIL_OFFER = {
  canWrite: true,
  dslActive: true,
  executedQuery: 'tag contains "mirai"',
  pageSelectionAll: true,
  pageSelectableCount: 25,
  exactMatchCount: 2143
};

test('header select-all on a 2,143-match search offers query-wide select with page copy', () => {
  assert.equal(formatPageSelectionLabel(25), '25 selected on this page');
  assert.equal(shouldOfferSelectAllMatching(GMAIL_OFFER), true);
  assert.equal(
    formatSelectAllMatchingActionLabel(2143),
    'Select all 2,143 matching IOCs'
  );
});

test('clicking select-all-matching switches to all_matching copy', () => {
  assert.equal(
    formatAllMatchingSelectionLabel(2143),
    'All 2,143 matching IOCs selected'
  );
});

test('query-wide Add tag payload is the query contract, not 2,143 client IDs', () => {
  const body = buildQueryWideBulkPayload({
    query: 'tag contains "mirai"',
    action: 'tag',
    tagId: 9
  });
  assert.equal(body.selection_mode, SELECTION_MODE_ALL_MATCHING);
  assert.equal(body.query, 'tag contains "mirai"');
  assert.equal(body.tag_id, 9);
  assert.equal(Object.prototype.hasOwnProperty.call(body, 'ioc_ids'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(body, 'match_count'), false);
  assert.equal(queryWideBulkPath('tag'), '/iocs/bulk/query/tags');
  assert.equal(formatQueryWideConfirmTitle('tag', 2143), 'Add tag to 2,143 matching IOCs');
  assert.match(
    formatQueryWideConfirmDescription('tag', 25),
    /ALL IOCs matching the current search, not only the 25 IOCs visible on this page/
  );
  assert.equal(formatQueryWideConfirmButton('tag', 2143), 'Add tag to 2,143 IOCs');
});

test('query-wide Add classification uses the same safety contract', () => {
  const body = buildQueryWideBulkPayload({
    query: 'tag contains "mirai"',
    action: 'classification',
    classificationSlug: 'malware'
  });
  assert.equal(body.selection_mode, 'all_matching');
  assert.equal(body.classification_slug, 'malware');
  assert.equal(Object.prototype.hasOwnProperty.call(body, 'ioc_ids'), false);
  assert.equal(queryWideBulkPath('classification'), '/iocs/bulk/query/classifications');
  assert.equal(
    formatQueryWideConfirmTitle('classification', 2143),
    'Add classification to 2,143 matching IOCs'
  );
  assert.equal(formatQueryWideConfirmButton('classification', 2143), 'Add classification to 2,143 IOCs');
});

test('query-wide Suppress confirmation shows exact query, count, and required reason', () => {
  const body = buildQueryWideBulkPayload({
    query: 'tag contains "mirai"',
    action: 'suppress',
    reason: 'test cleanup'
  });
  assert.equal(body.selection_mode, 'all_matching');
  assert.equal(body.query, 'tag contains "mirai"');
  assert.equal(body.reason, 'test cleanup');
  assert.equal(Object.prototype.hasOwnProperty.call(body, 'ioc_ids'), false);
  assert.equal(formatQueryWideConfirmTitle('suppress', 2143), 'Suppress 2,143 matching IOCs');
  assert.match(formatQueryWideConfirmDescription('suppress', 25), /A reason is required/);
  assert.equal(formatQueryWideConfirmButton('suppress', 2143), 'Suppress 2,143 IOCs');
  assert.equal(queryWideBulkPath('suppress'), '/iocs/bulk/query/suppress');
});

test('query-wide Expire uses the same safety checks as Suppress', () => {
  const body = buildQueryWideBulkPayload({
    query: 'tag contains "mirai"',
    action: 'expire',
    reason: 'stale test iocs'
  });
  assert.equal(body.query, 'tag contains "mirai"');
  assert.equal(body.reason, 'stale test iocs');
  assert.equal(formatQueryWideConfirmTitle('expire', 2143), 'Expire 2,143 matching IOCs');
  assert.equal(formatQueryWideConfirmButton('expire', 2143), 'Expire 2,143 IOCs');
  assert.equal(queryWideBulkPath('expire'), '/iocs/bulk/query/expire');
});

test('query-wide confirm buttons are never a generic Confirm', () => {
  for (const action of ['tag', 'classification', 'suppress', 'expire']) {
    assert.notEqual(formatQueryWideConfirmButton(action, 2143), 'Confirm');
  }
});

test('executed query change clears all_matching', () => {
  const next = applySelectionForContexts({
    selectionMode: SELECTION_MODE_ALL_MATCHING,
    allMatchingQueryContext: iocListQueryContextKey({
      dslActive: true,
      executedQuery: 'tag contains "mirai"'
    }),
    queryContextKey: iocListQueryContextKey({
      dslActive: true,
      executedQuery: 'tag contains "emotet"'
    }),
    pageContextKey: searchContext('tag contains "emotet"'),
    selectionContextKey: searchContext('tag contains "mirai"')
  });
  assert.equal(next.selectionMode, SELECTION_MODE_NONE);
  assert.equal(next.keepAllMatching, false);
  assert.equal(next.clearPageSelection, true);
});

test('Saved Search query change clears all_matching', () => {
  const next = applySelectionForContexts({
    selectionMode: SELECTION_MODE_ALL_MATCHING,
    allMatchingQueryContext: iocListQueryContextKey({
      dslActive: true,
      executedQuery: 'type equals "ip"'
    }),
    queryContextKey: iocListQueryContextKey({
      dslActive: true,
      executedQuery: 'source contains "usom"'
    }),
    pageContextKey: searchContext('source contains "usom"'),
    selectionContextKey: searchContext('type equals "ip"')
  });
  assert.equal(next.keepAllMatching, false);
  assert.equal(next.selectionMode, SELECTION_MODE_NONE);
});

test('Clear / return to browse clears all_matching', () => {
  const next = applySelectionForContexts({
    selectionMode: SELECTION_MODE_ALL_MATCHING,
    allMatchingQueryContext: iocListQueryContextKey({
      dslActive: true,
      executedQuery: 'tag contains "mirai"'
    }),
    queryContextKey: iocListQueryContextKey({ dslActive: false }),
    pageContextKey: browseContext(),
    selectionContextKey: searchContext('tag contains "mirai"')
  });
  assert.equal(next.selectionMode, SELECTION_MODE_NONE);
  assert.equal(next.clearPageSelection, true);
});

test('pagination while all_matching stays active because the query is unchanged', () => {
  const query = 'tag contains "mirai"';
  const queryKey = iocListQueryContextKey({ dslActive: true, executedQuery: query });
  const next = applySelectionForContexts({
    selectionMode: SELECTION_MODE_ALL_MATCHING,
    allMatchingQueryContext: queryKey,
    queryContextKey: queryKey,
    pageContextKey: searchContext(query, { cursor: 'page-2' }),
    selectionContextKey: searchContext(query)
  });
  assert.equal(next.selectionMode, SELECTION_MODE_ALL_MATCHING);
  assert.equal(next.keepAllMatching, true);
  assert.equal(next.clearPageSelection, false);
});

test('page mode pagination still clears selection', () => {
  const next = applySelectionForContexts({
    selectionMode: SELECTION_MODE_PAGE,
    queryContextKey: iocListQueryContextKey({ dslActive: false }),
    pageContextKey: browseContext({ page: 2 }),
    selectionContextKey: browseContext({ page: 1 })
  });
  assert.equal(next.selectionMode, SELECTION_MODE_NONE);
  assert.equal(next.clearPageSelection, true);
});

test('unfiltered browse never offers query-wide select-all', () => {
  assert.equal(shouldOfferSelectAllMatching({
    canWrite: true,
    dslActive: false,
    executedQuery: '',
    pageSelectionAll: true,
    pageSelectableCount: 25,
    exactMatchCount: 5000
  }), false);
  assert.equal(iocListQueryContextKey({ dslActive: false }), 'browse');
});

test('select-all-matching is hidden without an exact count, when the page holds all matches, and for readonly', () => {
  assert.equal(shouldOfferSelectAllMatching({ ...GMAIL_OFFER, exactMatchCount: null }), false);
  assert.equal(shouldOfferSelectAllMatching({ ...GMAIL_OFFER, exactMatchCount: 25 }), false);
  assert.equal(shouldOfferSelectAllMatching({ ...GMAIL_OFFER, pageSelectionAll: false }), false);
  assert.equal(shouldOfferSelectAllMatching({ ...GMAIL_OFFER, canWrite: false }), false);
  assert.equal(shouldOfferSelectAllMatching({ ...GMAIL_OFFER, deepSearchId: 'ds-1' }), false);
  assert.equal(shouldOfferSelectAllMatching({ ...GMAIL_OFFER, executedQuery: '   ' }), false);
});

const PREVIEW_GATES = {
  canWrite: true,
  dslActive: true,
  executedQuery: 'tag contains "mirai"',
  pageSelectionAll: true,
  pageSelectableCount: 25,
  searchExactCount: null,
  hasMoreMatches: true,
  preview: null
};

test('null exact_count from a 2,000+ search is not coerced to 0', () => {
  assert.equal(isFiniteExactMatchCount(null), false);
  assert.equal(isFiniteExactMatchCount(undefined), false);
  assert.equal(isFiniteExactMatchCount(''), false);
  assert.equal(isFiniteExactMatchCount(0), true);
  assert.equal(isFiniteExactMatchCount(2143), true);
});

test('exact search count of 143 offers select-all without a preview request', () => {
  const searchExactCount = 143;
  assert.equal(shouldRequestQueryWidePreview({
    ...PREVIEW_GATES,
    executedQuery: 'tag contains "emotet"',
    searchExactCount,
    hasMoreMatches: true
  }), false);
  assert.equal(resolvedExactMatchCount(searchExactCount, null, 'tag contains "emotet"'), 143);
  assert.equal(shouldOfferSelectAllMatching({
    ...GMAIL_OFFER,
    executedQuery: 'tag contains "emotet"',
    exactMatchCount: 143
  }), true);
  assert.equal(formatSelectAllMatchingActionLabel(143), 'Select all 143 matching IOCs');
});

test('2,000+ page select-all requests preview for the executed query and shows loading then exact offer', () => {
  assert.equal(searchHasMoreMatchesThanPage({
    searchExactCount: null,
    pageSelectableCount: 25,
    hasMore: true,
    countDisplay: '2,000+'
  }), true);
  assert.equal(shouldRequestQueryWidePreview(PREVIEW_GATES), true);
  assert.equal(shouldRequestQueryWidePreview({
    ...PREVIEW_GATES,
    preview: { query: PREVIEW_GATES.executedQuery, status: QUERY_WIDE_PREVIEW_LOADING, count: null }
  }), false);
  assert.equal(formatQueryWidePreviewLoadingLabel(), 'Checking total matches…');
  const payload = buildQueryWidePreviewPayload('tag contains "mirai"');
  assert.equal(payload.query, 'tag contains "mirai"');
  assert.equal(payload.selection_mode, SELECTION_MODE_ALL_MATCHING);
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'ioc_ids'), false);
  const ready = queryWidePreviewFromSuccess({ match_count: 2143 });
  assert.equal(ready.status, QUERY_WIDE_PREVIEW_READY);
  assert.equal(ready.count, 2143);
  const preview = { query: 'tag contains "mirai"', ...ready };
  assert.equal(resolvedExactMatchCount(null, preview, 'tag contains "mirai"'), 2143);
  assert.equal(shouldOfferSelectAllMatching({
    ...GMAIL_OFFER,
    exactMatchCount: 2143
  }), true);
  assert.equal(formatSelectAllMatchingActionLabel(2143), 'Select all 2,143 matching IOCs');
  assert.equal(formatAllMatchingSelectionLabel(2143), 'All 2,143 matching IOCs selected');
});

test('preview payload uses executed query and ignores unexecuted textbox edits', () => {
  const executed = 'tag contains "mirai"';
  const body = buildQueryWidePreviewPayload(executed);
  assert.equal(body.query, executed);
  assert.equal(Object.prototype.hasOwnProperty.call(body, 'ioc_ids'), false);
  assert.equal(
    iocListQueryContextKey({
      dslActive: true,
      executedQuery: executed,
      searchInput: 'tag contains "botnet"'
    }),
    iocListQueryContextKey({ dslActive: true, executedQuery: executed })
  );
  assert.equal(
    previewCountForExecutedQuery(
      { query: executed, status: QUERY_WIDE_PREVIEW_READY, count: 2143 },
      'tag contains "botnet"'
    ),
    null
  );
});

test('stale preview response for a previous query is ignored', () => {
  const stale = {
    query: 'tag contains "mirai"',
    status: QUERY_WIDE_PREVIEW_READY,
    count: 2143
  };
  assert.equal(bindQueryWidePreview(stale, 'tag contains "emotet"'), null);
  assert.equal(previewCountForExecutedQuery(stale, 'tag contains "emotet"'), null);
  assert.equal(resolvedExactMatchCount(null, stale, 'tag contains "emotet"'), null);
  assert.equal(shouldOfferSelectAllMatching({
    ...GMAIL_OFFER,
    executedQuery: 'tag contains "emotet"',
    exactMatchCount: resolvedExactMatchCount(null, stale, 'tag contains "emotet"')
  }), false);
});

test('preview failure keeps page selection usable and does not invent a count', () => {
  const failed = queryWidePreviewFromFailure({ message: 'network down' });
  assert.equal(failed.status, QUERY_WIDE_PREVIEW_ERROR);
  assert.equal(failed.count, null);
  const preview = { query: PREVIEW_GATES.executedQuery, ...failed };
  assert.equal(resolvedExactMatchCount(null, preview, PREVIEW_GATES.executedQuery), null);
  assert.equal(shouldOfferSelectAllMatching({
    ...GMAIL_OFFER,
    exactMatchCount: null
  }), false);
  assert.equal(shouldRequestQueryWidePreview({ ...PREVIEW_GATES, preview }), false);
});

test('QUERY_TOO_EXPENSIVE does not offer all-matching and preserves page selection gates', () => {
  const unsupported = queryWidePreviewFromFailure({
    response: {
      data: {
        code: 'QUERY_TOO_EXPENSIVE',
        message: 'This search is too broad for query-wide bulk. Narrow the query or use Deep Search, then act on a page.'
      }
    }
  });
  assert.equal(unsupported.status, QUERY_WIDE_PREVIEW_UNSUPPORTED);
  assert.equal(unsupported.count, null);
  assert.match(unsupported.error, /too broad for query-wide bulk/);
  const preview = { query: PREVIEW_GATES.executedQuery, ...unsupported };
  assert.equal(shouldOfferSelectAllMatching({
    ...GMAIL_OFFER,
    exactMatchCount: resolvedExactMatchCount(null, preview, PREVIEW_GATES.executedQuery)
  }), false);
  assert.equal(shouldRequestQueryWidePreview({ ...PREVIEW_GATES, preview }), false);
});

test('default browse and partial page selection never request preview', () => {
  assert.equal(shouldRequestQueryWidePreview({
    ...PREVIEW_GATES,
    dslActive: false,
    executedQuery: '',
    searchExactCount: 5000,
    hasMoreMatches: true
  }), false);
  assert.equal(shouldRequestQueryWidePreview({
    ...PREVIEW_GATES,
    pageSelectionAll: false
  }), false);
  assert.equal(shouldOfferSelectAllMatching({
    canWrite: true,
    dslActive: false,
    executedQuery: '',
    pageSelectionAll: true,
    pageSelectableCount: 25,
    exactMatchCount: 5000
  }), false);
});

test('cached exact preview is not requested again for the same executed query', () => {
  const preview = {
    query: 'tag contains "mirai"',
    status: QUERY_WIDE_PREVIEW_READY,
    count: 2143
  };
  assert.equal(shouldRequestQueryWidePreview({ ...PREVIEW_GATES, preview }), false);
});

test('Saved Search and Advanced Search resolve approximate counts from the executed query', () => {
  const saved = 'type equals "ip" AND tag contains "mirai"';
  assert.equal(shouldRequestQueryWidePreview({
    ...PREVIEW_GATES,
    executedQuery: saved,
    searchExactCount: null,
    hasMoreMatches: true
  }), true);
  assert.equal(buildQueryWidePreviewPayload(saved).query, saved);
  const advanced = 'tag contains "mirai" AND type equals "domain"';
  const preview = {
    query: advanced,
    ...queryWidePreviewFromSuccess({ match_count: 2143 })
  };
  assert.equal(resolvedExactMatchCount(null, preview, advanced), 2143);
});

test('Clear / browse drops bound preview count so all-matching cannot linger', () => {
  const preview = {
    query: 'tag contains "mirai"',
    status: QUERY_WIDE_PREVIEW_READY,
    count: 2143
  };
  assert.equal(bindQueryWidePreview(preview, ''), null);
  assert.equal(resolvedExactMatchCount(null, preview, ''), null);
  const next = applySelectionForContexts({
    selectionMode: SELECTION_MODE_ALL_MATCHING,
    allMatchingQueryContext: iocListQueryContextKey({
      dslActive: true,
      executedQuery: 'tag contains "mirai"'
    }),
    queryContextKey: iocListQueryContextKey({ dslActive: false }),
    pageContextKey: browseContext(),
    selectionContextKey: searchContext('tag contains "mirai"')
  });
  assert.equal(next.selectionMode, SELECTION_MODE_NONE);
});

test('query-wide confirmation still uses exact count after preview resolution', () => {
  assert.equal(formatQueryWideConfirmTitle('tag', 2143), 'Add tag to 2,143 matching IOCs');
  assert.equal(formatQueryWideConfirmTitle('suppress', 2143), 'Suppress 2,143 matching IOCs');
  assert.match(formatQueryWideConfirmDescription('suppress', 25), /A reason is required/);
  assert.equal(formatQueryWideConfirmButton('suppress', 2143), 'Suppress 2,143 IOCs');
});

test('2,000+ display is never used as the select-all label', () => {
  assert.notEqual(formatSelectAllMatchingActionLabel(null), 'Select all 2,000+ matching IOCs');
  assert.equal(shouldOfferSelectAllMatching({ ...GMAIL_OFFER, exactMatchCount: null }), false);
  assert.equal(queryWidePreviewFromSuccess({ match_count: '2000+' }).status, QUERY_WIDE_PREVIEW_ERROR);
});

test('unexecuted search-box text does not change the query-wide context', () => {
  const executed = iocListQueryContextKey({
    dslActive: true,
    executedQuery: 'tag contains "mirai"',
    searchInput: 'tag contains "emotet"'
  });
  assert.equal(
    executed,
    iocListQueryContextKey({ dslActive: true, executedQuery: 'tag contains "mirai"' })
  );
});

test('IOC List wires query-wide selection, confirmation copy, and query-bound payload', async () => {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const mainJsx = await fs.readFile(path.join(here, '../main.jsx'), 'utf8');
  assert.match(mainJsx, /shouldOfferSelectAllMatching/);
  assert.match(mainJsx, /formatSelectAllMatchingActionLabel/);
  assert.match(mainJsx, /formatAllMatchingSelectionLabel/);
  assert.match(mainJsx, /buildQueryWideBulkPayload/);
  assert.match(mainJsx, /queryWideBulkPath/);
  assert.match(mainJsx, /formatQueryWideConfirmDescription/);
  assert.match(mainJsx, /formatQueryWideConfirmTitle/);
  assert.match(mainJsx, /Matching IOCs:/);
  assert.match(mainJsx, /shouldRequestQueryWidePreview/);
  assert.match(mainJsx, /buildQueryWidePreviewPayload/);
  assert.match(mainJsx, /formatQueryWidePreviewLoadingLabel/);
  assert.match(mainJsx, /queryWidePreviewFromSuccess/);
  assert.match(mainJsx, /queryWidePreviewFromFailure/);
  assert.match(mainJsx, /bindQueryWidePreview/);
  assert.match(mainJsx, /formatQueryWidePreviewLoadingLabel/);
  assert.match(mainJsx, /\/iocs\/bulk\/query\/preview/);
  assert.match(mainJsx, /SELECTION_MODE_ALL_MATCHING/);
  assert.match(mainJsx, /applySelectionForContexts/);
  assert.match(mainJsx, /buildQueryWideBulkPayload/);
  assert.match(mainJsx, /queryWideBulkPath\(bulkModal\)/);
});
