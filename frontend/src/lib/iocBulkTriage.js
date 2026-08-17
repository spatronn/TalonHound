export const BULK_TRIAGE_MAX = 100;
export const IOC_LIST_DEFAULT_PAGE_SIZE = 25;

const EMPTY_IOC_SELECTION = new Set();

function normalizedPageSize(pageSize) {
  const n = Number(pageSize);
  return Number.isInteger(n) && n > 0 ? n : IOC_LIST_DEFAULT_PAGE_SIZE;
}

function normalizedPage(page) {
  const n = Number(page);
  return Number.isInteger(n) && n > 0 ? n : 1;
}

/**
 * Selection is valid only for the current visible IOC page.
 * Includes executed query/mode plus page number or cursor and page size.
 * Unexecuted search-box text is excluded.
 */
export function iocListResultContextKey({
  dslActive = false,
  executedQuery = '',
  deepSearchId = '',
  page = 1,
  pageSize = IOC_LIST_DEFAULT_PAGE_SIZE,
  cursor = ''
} = {}) {
  const size = normalizedPageSize(pageSize);
  const cursorPart = String(cursor || '').trim();
  const deepId = String(deepSearchId || '').trim();
  if (deepId) return `deep:${deepId}:s${size}:c${cursorPart}`;
  if (dslActive) return `search:${String(executedQuery || '').trim()}:s${size}:c${cursorPart}`;
  return `browse:p${normalizedPage(page)}:s${size}`;
}

export const IOC_LIST_BROWSE_CONTEXT = iocListResultContextKey({
  dslActive: false,
  page: 1,
  pageSize: IOC_LIST_DEFAULT_PAGE_SIZE
});

export function selectedIdsForResultContext(selectedIds, selectedContextKey, currentContextKey) {
  if (String(selectedContextKey || '') !== String(currentContextKey || '')) {
    return EMPTY_IOC_SELECTION;
  }
  return selectedIds instanceof Set ? selectedIds : new Set(selectedIds || []);
}

export function applyIocSelectionContext(state, nextContextKey) {
  const currentKey = String(state?.contextKey || '');
  const nextKey = String(nextContextKey || '');
  const selectedIds = state?.selectedIds instanceof Set
    ? state.selectedIds
    : new Set(state?.selectedIds || []);
  if (currentKey === nextKey) {
    return { contextKey: nextKey, selectedIds };
  }
  return { contextKey: nextKey, selectedIds: new Set() };
}

/** Defensive bulk payload: stale IDs from a previous result context are never sent. */
export function bulkIocIdsForContext(state, currentContextKey) {
  return [...applyIocSelectionContext(state, currentContextKey).selectedIds];
}

/** Bulk payload may only include IDs selected on the current visible page. */
export function bulkIocIdsForVisiblePage(state, currentContextKey, pageIds) {
  const allowed = new Set((pageIds || []).filter((id) => id != null));
  return bulkIocIdsForContext(state, currentContextKey).filter((id) => allowed.has(id));
}

export function formatPageSelectionLabel(count) {
  const n = Number(count) || 0;
  return n === 1 ? '1 selected on this page' : `${n} selected on this page`;
}

export function parseIocRowId(row) {
  const n = Number(row?.id);
  return Number.isInteger(n) && n > 0 ? n : null;
}

export function toggleSelectedId(selected, id, { max = BULK_TRIAGE_MAX } = {}) {
  const next = new Set(selected);
  if (next.has(id)) {
    next.delete(id);
    return { selected: next, capped: false };
  }
  if (next.size >= max) return { selected, capped: true };
  next.add(id);
  return { selected: next, capped: false };
}

export function selectPageIds(selected, pageIds, { max = BULK_TRIAGE_MAX } = {}) {
  const next = new Set(selected);
  let capped = false;
  for (const id of pageIds) {
    if (id == null || next.has(id)) continue;
    if (next.size >= max) {
      capped = true;
      break;
    }
    next.add(id);
  }
  return { selected: next, capped };
}

export function deselectPageIds(selected, pageIds) {
  const drop = new Set(pageIds);
  const next = new Set();
  for (const id of selected) {
    if (!drop.has(id)) next.add(id);
  }
  return next;
}

export function pageSelectionState(selected, pageIds) {
  const selectable = (pageIds || []).filter((id) => id != null);
  const selectedOnPage = selectable.filter((id) => selected.has(id));
  return {
    all: selectable.length > 0 && selectedOnPage.length === selectable.length,
    some: selectedOnPage.length > 0 && selectedOnPage.length < selectable.length
  };
}

export function formatBulkTriageSummary({
  succeeded = 0,
  skipped = 0,
  failed = 0,
  requested = 0
} = {}) {
  const parts = [`${succeeded} succeeded`];
  if (skipped) parts.push(`${skipped} skipped`);
  if (failed) parts.push(`${failed} failed`);
  return `${requested} selected · ${parts.join(', ')}`;
}

export function remainingSelectedAfterBulk(results = []) {
  const next = new Set();
  for (const row of results) {
    if (row?.status === 'error' && Number.isInteger(Number(row.id)) && Number(row.id) > 0) {
      next.add(Number(row.id));
    }
  }
  return next;
}

export function bulkConfirmDisabled({
  requireReason = false,
  reason = '',
  requireChoice = false,
  choice = ''
} = {}) {
  if (requireReason && String(reason || '').trim().length < 3) return true;
  if (requireChoice && !String(choice || '').trim()) return true;
  return false;
}
