/**
 * Pure presentation/behaviour logic for the Watchlist star toggle.
 * No React, no DOM — safe to unit test with `node --test`.
 *
 *   ☆  Not in my watchlist  → "Add to Watchlist"
 *   ★  In my watchlist      → "Remove from Watchlist"
 */

export const STAR_FILLED = '★';
export const STAR_HOLLOW = '☆';

/** @param {boolean} watchlisted */
export function watchlistStarLabel(watchlisted) {
  return watchlisted ? 'Remove from Watchlist' : 'Add to Watchlist';
}

/** @param {boolean} watchlisted */
export function watchlistStarGlyph(watchlisted) {
  return watchlisted ? STAR_FILLED : STAR_HOLLOW;
}

/**
 * View model for the star button.
 * @param {{ watchlisted?: boolean, pending?: boolean }} state
 */
export function buildWatchlistStarModel({ watchlisted = false, pending = false } = {}) {
  const on = Boolean(watchlisted);
  const label = watchlistStarLabel(on);
  return {
    glyph: watchlistStarGlyph(on),
    label,
    title: label,
    ariaLabel: label,
    ariaPressed: on,
    active: on,
    // Disabled while a mutation is in flight — prevents accidental request spam
    // from rapid clicking / double-submits.
    disabled: Boolean(pending),
    busy: Boolean(pending)
  };
}

/**
 * Plan the optimistic toggle for a click.
 * @param {boolean} watchlisted current membership
 * @returns {{ method: 'PUT'|'DELETE', optimistic: boolean }}
 */
export function planWatchlistToggle(watchlisted) {
  const on = Boolean(watchlisted);
  return {
    method: on ? 'DELETE' : 'PUT',
    optimistic: !on
  };
}

/**
 * Toast message when a toggle fails and the optimistic state is rolled back.
 * `attempted` is the state we tried to reach.
 * @param {boolean} attempted
 */
export function watchlistToggleErrorMessage(attempted) {
  return attempted
    ? 'Failed to add IOC to your watchlist.'
    : 'Failed to remove IOC from your watchlist.';
}
