/**
 * Pure view-state helpers for the Watchlist page. No React/DOM.
 */

export const WATCHLIST_EMPTY = Object.freeze({
  title: 'No IOCs in your watchlist',
  description: 'Star an IOC to save it here for quick access.',
  ctaLabel: 'Browse IOCs'
});

/**
 * Which section the page should render.
 * @param {{ loading?: boolean, error?: unknown, itemCount?: number }} state
 * @returns {'loading'|'error'|'empty'|'list'}
 */
export function watchlistViewMode({ loading = false, error = null, itemCount = 0 } = {}) {
  if (loading) return 'loading';
  if (error) return 'error';
  if (!Number(itemCount)) return 'empty';
  return 'list';
}

/**
 * After removing an IOC from the current page, decide whether we should step back
 * a page (removed the last row of a non-first page) so the user never lands on an
 * empty page that actually has earlier results.
 * @param {{ page: number, remainingOnPage: number }} state
 */
export function watchlistPageAfterRemoval({ page = 1, remainingOnPage = 0 } = {}) {
  if (remainingOnPage <= 0 && page > 1) return page - 1;
  return page;
}
