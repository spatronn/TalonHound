import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildWatchlistStarModel,
  planWatchlistToggle,
  watchlistStarGlyph,
  watchlistStarLabel,
  watchlistToggleErrorMessage,
  STAR_FILLED,
  STAR_HOLLOW
} from './watchlistStar.js';

test('hollow star + "Add" when not watchlisted', () => {
  const m = buildWatchlistStarModel({ watchlisted: false });
  assert.equal(m.glyph, STAR_HOLLOW);
  assert.equal(m.label, 'Add to Watchlist');
  assert.equal(m.ariaLabel, 'Add to Watchlist');
  assert.equal(m.title, 'Add to Watchlist');
  assert.equal(m.ariaPressed, false);
  assert.equal(m.active, false);
  assert.equal(m.disabled, false);
});

test('filled star + "Remove" when watchlisted', () => {
  const m = buildWatchlistStarModel({ watchlisted: true });
  assert.equal(m.glyph, STAR_FILLED);
  assert.equal(m.label, 'Remove from Watchlist');
  assert.equal(m.ariaPressed, true);
  assert.equal(m.active, true);
});

test('pending disables the button (spam prevention) and marks busy', () => {
  const m = buildWatchlistStarModel({ watchlisted: false, pending: true });
  assert.equal(m.disabled, true);
  assert.equal(m.busy, true);
});

test('glyph/label helpers', () => {
  assert.equal(watchlistStarGlyph(true), STAR_FILLED);
  assert.equal(watchlistStarGlyph(false), STAR_HOLLOW);
  assert.equal(watchlistStarLabel(true), 'Remove from Watchlist');
  assert.equal(watchlistStarLabel(false), 'Add to Watchlist');
});

test('planWatchlistToggle: empty star → PUT (optimistic on)', () => {
  assert.deepEqual(planWatchlistToggle(false), { method: 'PUT', optimistic: true });
});

test('planWatchlistToggle: filled star → DELETE (optimistic off)', () => {
  assert.deepEqual(planWatchlistToggle(true), { method: 'DELETE', optimistic: false });
});

test('rollback toast text matches the attempted direction', () => {
  assert.match(watchlistToggleErrorMessage(true), /add/i);
  assert.match(watchlistToggleErrorMessage(false), /remove/i);
});
