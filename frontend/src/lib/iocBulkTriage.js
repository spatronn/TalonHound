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

export const SELECTION_MODE_NONE = 'none';
export const SELECTION_MODE_PAGE = 'page';
export const SELECTION_MODE_ALL_MATCHING = 'all_matching';

/**
 * Executed query/mode identity only — no page, cursor, or page size.
 * Used to bind query-wide selection and to clear it when the result set changes.
 */
export function iocListQueryContextKey({
  dslActive = false,
  executedQuery = '',
  deepSearchId = ''
} = {}) {
  const deepId = String(deepSearchId || '').trim();
  if (deepId) return `deep:${deepId}`;
  if (dslActive) return `search:${String(executedQuery || '').trim()}`;
  return 'browse';
}

/**
 * Gmail-like second-stage offer. Requires an executed non-empty search, a full
 * current-page selection, a finite exact match count greater than the page, and write access.
 * Unfiltered browse, Deep Search snapshots, and `2,000+` (null exact count) never qualify.
 */
export function shouldOfferSelectAllMatching({
  canWrite = false,
  dslActive = false,
  executedQuery = '',
  deepSearchId = '',
  pageSelectionAll = false,
  pageSelectableCount = 0,
  exactMatchCount = null
} = {}) {
  if (!canWrite) return false;
  if (String(deepSearchId || '').trim()) return false;
  if (!dslActive) return false;
  if (!String(executedQuery || '').trim()) return false;
  if (!pageSelectionAll) return false;
  const pageN = Number(pageSelectableCount) || 0;
  if (pageN <= 0) return false;
  const total = Number(exactMatchCount);
  if (!Number.isFinite(total) || total <= pageN) return false;
  return true;
}

export function formatSelectAllMatchingActionLabel(count) {
  const n = Number(count) || 0;
  return `Select all ${n.toLocaleString('en-US')} matching IOCs`;
}

export function formatAllMatchingSelectionLabel(count) {
  const n = Number(count) || 0;
  return `All ${n.toLocaleString('en-US')} matching IOCs selected`;
}

/**
 * PAGE selection is bound to the visible page. ALL_MATCHING is bound to the executed query.
 * Pagination must not clear ALL_MATCHING; any query/mode change must.
 */
export function applySelectionForContexts({
  selectionMode = SELECTION_MODE_NONE,
  allMatchingQueryContext = '',
  queryContextKey = '',
  pageContextKey = '',
  selectionContextKey = ''
} = {}) {
  if (selectionMode === SELECTION_MODE_ALL_MATCHING) {
    if (String(allMatchingQueryContext || '') !== String(queryContextKey || '')) {
      return {
        selectionMode: SELECTION_MODE_NONE,
        clearPageSelection: true,
        keepAllMatching: false
      };
    }
    return {
      selectionMode: SELECTION_MODE_ALL_MATCHING,
      clearPageSelection: false,
      keepAllMatching: true
    };
  }
  if (String(selectionContextKey || '') !== String(pageContextKey || '')) {
    return {
      selectionMode: SELECTION_MODE_NONE,
      clearPageSelection: true,
      keepAllMatching: false
    };
  }
  return {
    selectionMode: selectionMode || SELECTION_MODE_NONE,
    clearPageSelection: false,
    keepAllMatching: false
  };
}

export function queryWideBulkPath(action) {
  if (action === 'tag') return '/iocs/bulk/query/tags';
  if (action === 'classification') return '/iocs/bulk/query/classifications';
  if (action === 'suppress') return '/iocs/bulk/query/suppress';
  if (action === 'expire') return '/iocs/bulk/query/expire';
  return '';
}

/** Query-wide HTTP body. Never includes ioc_ids or a client-supplied match count. */
export function buildQueryWideBulkPayload({
  query,
  action,
  tagId,
  classificationSlug,
  reason
} = {}) {
  const body = {
    selection_mode: SELECTION_MODE_ALL_MATCHING,
    query: String(query || '')
  };
  if (action === 'tag' && tagId != null && tagId !== '') body.tag_id = Number(tagId);
  if (action === 'classification' && classificationSlug) {
    body.classification_slug = String(classificationSlug);
  }
  if ((action === 'suppress' || action === 'expire') && reason != null) {
    body.reason = String(reason);
  }
  return body;
}

export function formatQueryWideConfirmTitle(action, count) {
  const formatted = (Number(count) || 0).toLocaleString('en-US');
  if (action === 'tag') return `Add tag to ${formatted} matching IOCs`;
  if (action === 'classification') return `Add classification to ${formatted} matching IOCs`;
  if (action === 'suppress') return `Suppress ${formatted} matching IOCs`;
  if (action === 'expire') return `Expire ${formatted} matching IOCs`;
  return 'Bulk action';
}

export function formatQueryWideConfirmDescription(action, pageSelectableCount) {
  const pageN = Number(pageSelectableCount) || 0;
  const pageBit = pageN > 0
    ? `the ${pageN.toLocaleString('en-US')} IOCs visible on this page`
    : 'the IOCs visible on this page';
  const scope = `This action applies to ALL IOCs matching the current search, not only ${pageBit}.`;
  if (action === 'suppress' || action === 'expire') {
    return `${scope} A reason is required and will be written to the audit log.`;
  }
  return scope;
}

export function formatQueryWideConfirmButton(action, count) {
  const formatted = (Number(count) || 0).toLocaleString('en-US');
  if (action === 'tag') return `Add tag to ${formatted} IOCs`;
  if (action === 'classification') return `Add classification to ${formatted} IOCs`;
  if (action === 'suppress') return `Suppress ${formatted} IOCs`;
  if (action === 'expire') return `Expire ${formatted} IOCs`;
  return 'Confirm';
}

export function formatQueryWideAsyncToast(action, count) {
  const formatted = (Number(count) || 0).toLocaleString('en-US');
  const verb = action === 'tag'
    ? 'Add tag'
    : action === 'classification'
      ? 'Add classification'
      : action === 'suppress'
        ? 'Suppress'
        : 'Expire';
  return `${verb} queued for ${formatted} matching IOCs. Track progress in Action Center.`;
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
