// Pure state/helpers for the Audit Logs investigation view.
//
// The page is time-bounded and keyset-paginated. Presets resolve to absolute
// {from,to} instants frozen at query time so cursor navigation stays stable
// (a relative "now" must not drift while paging). Custom ranges reuse the
// System Timezone conversion done by the caller.

export const AUDIT_DEFAULT_RANGE = '24h';

export const AUDIT_RANGE_OPTIONS = [
  { value: '1h', label: 'Last 1 hour', ms: 60 * 60 * 1000 },
  { value: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60 * 1000 },
  { value: '7d', label: 'Last 7 days', ms: 7 * 24 * 60 * 60 * 1000 },
  { value: '30d', label: 'Last 30 days', ms: 30 * 24 * 60 * 60 * 1000 },
  { value: 'custom', label: 'Custom', ms: null }
];

export const AUDIT_PAGE_SIZE_OPTIONS = [25, 50, 100];
export const AUDIT_DEFAULT_PAGE_SIZE = 50;

export const AUDIT_EMPTY_STATE = 'No audit events found for the selected time range and filters.';

export function auditRangeLabel(value) {
  const opt = AUDIT_RANGE_OPTIONS.find((o) => o.value === value);
  return opt ? opt.label : 'Custom';
}

/**
 * Resolve a preset key to absolute ISO instants frozen at `now`.
 * Returns null for the `custom` key (caller supplies from/to explicitly).
 */
export function resolvePresetRange(rangeKey, now = new Date()) {
  const opt = AUDIT_RANGE_OPTIONS.find((o) => o.value === rangeKey);
  if (!opt || !opt.ms) return null;
  const to = now instanceof Date ? now : new Date(now);
  const from = new Date(to.getTime() - opt.ms);
  return { from: from.toISOString(), to: to.toISOString() };
}

/**
 * Validate a custom range. `fromIso`/`toIso` are already-normalized UTC ISO
 * strings (System Timezone conversion happens before this).
 * @returns {{ ok: true, from: string, to: string } | { ok: false, error: string }}
 */
export function validateCustomRange(fromIso, toIso) {
  if (!fromIso || !toIso) return { ok: false, error: 'Enter both From and To.' };
  const f = new Date(fromIso);
  const t = new Date(toIso);
  if (Number.isNaN(f.getTime()) || Number.isNaN(t.getTime())) {
    return { ok: false, error: 'Enter a valid date and time.' };
  }
  if (f.getTime() >= t.getTime()) {
    return { ok: false, error: '"From" must be before "To".' };
  }
  return { ok: true, from: fromIso, to: toIso };
}

/**
 * Footer text. Exact matching totals are intentionally omitted for performance,
 * so we report the position of the current page, never "page X / thousands".
 */
export function auditFooterText({ pageIndex = 0, limit = AUDIT_DEFAULT_PAGE_SIZE, count = 0, rangeLabel = '' } = {}) {
  const suffix = rangeLabel ? ` · ${rangeLabel}` : '';
  if (!count) return `No events${suffix}`;
  const start = pageIndex * limit + 1;
  const end = start + count - 1;
  return `Showing ${start}–${end}${suffix}`;
}

// --- Keyset cursor stack (frontend-maintained, forward cursors only) --------
// stack[i] is the cursor used to fetch page i; stack[0] is always null.

export function initialCursorStack() {
  return { stack: [null], pageIndex: 0 };
}

export function currentCursor(state) {
  return state.stack[state.pageIndex] ?? null;
}

export function canGoPrevious(state) {
  return state.pageIndex > 0;
}

/** Advance one page using the next_cursor from the current response. */
export function goNext(state, nextCursor) {
  if (!nextCursor) return state;
  const trimmed = state.stack.slice(0, state.pageIndex + 1);
  return { stack: [...trimmed, nextCursor], pageIndex: state.pageIndex + 1 };
}

/** Return to the previous page (exact cursor kept on the stack). */
export function goPrevious(state) {
  if (state.pageIndex <= 0) return state;
  return { stack: state.stack, pageIndex: state.pageIndex - 1 };
}
