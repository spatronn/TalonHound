import test from 'node:test';
import assert from 'node:assert/strict';
import { watchlistViewMode, watchlistPageAfterRemoval, WATCHLIST_EMPTY } from './watchlistPageView.js';

test('view mode: loading beats everything', () => {
  assert.equal(watchlistViewMode({ loading: true, error: new Error('x'), itemCount: 3 }), 'loading');
});

test('view mode: error when not loading', () => {
  assert.equal(watchlistViewMode({ error: new Error('boom'), itemCount: 3 }), 'error');
});

test('view mode: empty when no items', () => {
  assert.equal(watchlistViewMode({ itemCount: 0 }), 'empty');
  assert.equal(watchlistViewMode({}), 'empty');
});

test('view mode: list when items present', () => {
  assert.equal(watchlistViewMode({ itemCount: 5 }), 'list');
});

test('empty-state copy is present and not marketing-length', () => {
  assert.equal(WATCHLIST_EMPTY.title, 'No IOCs in your watchlist');
  assert.match(WATCHLIST_EMPTY.description, /Star an IOC/);
  assert.ok(WATCHLIST_EMPTY.description.length < 80);
});

test('removing last row of a later page steps back a page', () => {
  assert.equal(watchlistPageAfterRemoval({ page: 3, remainingOnPage: 0 }), 2);
  assert.equal(watchlistPageAfterRemoval({ page: 1, remainingOnPage: 0 }), 1);
  assert.equal(watchlistPageAfterRemoval({ page: 2, remainingOnPage: 4 }), 2);
});
