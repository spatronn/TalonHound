export const BULK_TRIAGE_MAX = 100;

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
