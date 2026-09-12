// Single source of truth for the IOC List pagination controls.
//
// The IOC List can display results in more than one navigation model:
//   - normal browse / simple search: offset paging (page / page_count)
//   - Deep Search result browsing:   keyset cursor paging (cursor stack + has_more)
//
// Two pagination areas render for the SAME result set — a compact control next to the
// results summary (top) and a control at the very bottom of the table. Historically each
// area read its own state, so the bottom control kept reading the normal offset model even
// while Deep Search result browsing was active (which sets the offset model aside). The
// result: the top Deep Search control enabled Next correctly while the bottom control
// showed Previous/Next both disabled.
//
// This helper derives ONE effective model for whichever mode is currently displayed so both
// areas consume identical enabled/disabled state AND identical navigation handlers. It is a
// pure function (handlers are injected) so the exact button semantics stay unit-testable.

export const IOC_LIST_PAGINATION_MODE_NORMAL = 'normal';
export const IOC_LIST_PAGINATION_MODE_DEEP_SEARCH = 'deep_search';

const noop = () => {};
const asFn = (fn) => (typeof fn === 'function' ? fn : noop);

/**
 * @param {object} args
 * @param {boolean} args.deepSearchReady  True when a completed Deep Search result set is
 *   being browsed (Deep Search cursor paging owns the controls).
 * @param {object} [args.deep]    Deep Search paging inputs:
 *   { hasPrevious, hasNext, loading, goPrevious, goNext }
 * @param {object} [args.normal]  Normal offset paging inputs:
 *   { page, pageCount, goPrevious, goNext }
 * @returns {{ mode, canGoPrevious, canGoNext, goPrevious, goNext }}
 */
export function buildIocListEffectivePagination({
  deepSearchReady = false,
  deep = {},
  normal = {}
} = {}) {
  if (deepSearchReady) {
    const loading = Boolean(deep.loading);
    return {
      mode: IOC_LIST_PAGINATION_MODE_DEEP_SEARCH,
      canGoPrevious: Boolean(deep.hasPrevious) && !loading,
      canGoNext: Boolean(deep.hasNext) && !loading,
      goPrevious: asFn(deep.goPrevious),
      goNext: asFn(deep.goNext)
    };
  }

  const page = Number(normal.page) || 1;
  const pageCount = Math.max(1, Number(normal.pageCount) || 1);
  return {
    mode: IOC_LIST_PAGINATION_MODE_NORMAL,
    canGoPrevious: page > 1,
    canGoNext: page < pageCount,
    goPrevious: asFn(normal.goPrevious),
    goNext: asFn(normal.goNext)
  };
}
