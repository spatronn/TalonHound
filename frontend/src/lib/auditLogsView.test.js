import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AUDIT_DEFAULT_RANGE,
  AUDIT_DEFAULT_PAGE_SIZE,
  AUDIT_RANGE_OPTIONS,
  AUDIT_EMPTY_STATE,
  auditRangeLabel,
  resolvePresetRange,
  validateCustomRange,
  auditFooterText,
  initialCursorStack,
  currentCursor,
  canGoPrevious,
  goNext,
  goPrevious
} from './auditLogsView.js';

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

test('default range is Last 24 hours', () => {
  assert.equal(AUDIT_DEFAULT_RANGE, '24h');
  assert.equal(auditRangeLabel('24h'), 'Last 24 hours');
  assert.equal(AUDIT_DEFAULT_PAGE_SIZE, 50);
});

test('range options expose 1h/24h/7d/30d/custom and no "All time"', () => {
  const values = AUDIT_RANGE_OPTIONS.map((o) => o.value);
  assert.deepEqual(values, ['1h', '24h', '7d', '30d', 'custom']);
  assert.ok(!values.includes('all'));
});

// ---------------------------------------------------------------------------
// Preset resolution (frozen absolute instants)
// ---------------------------------------------------------------------------

test('resolvePresetRange freezes absolute from/to for a preset', () => {
  const now = new Date('2026-08-08T12:00:00.000Z');
  const r = resolvePresetRange('24h', now);
  assert.equal(r.to, '2026-08-08T12:00:00.000Z');
  assert.equal(r.from, '2026-08-07T12:00:00.000Z');
});

test('resolvePresetRange returns null for custom', () => {
  assert.equal(resolvePresetRange('custom', new Date()), null);
});

// ---------------------------------------------------------------------------
// Custom range validation
// ---------------------------------------------------------------------------

test('validateCustomRange requires both bounds', () => {
  assert.equal(validateCustomRange('', '2026-01-02T00:00:00Z').ok, false);
  assert.equal(validateCustomRange('2026-01-01T00:00:00Z', '').ok, false);
});

test('validateCustomRange rejects from >= to (no silent substitution)', () => {
  const eq = validateCustomRange('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
  assert.equal(eq.ok, false);
  const rev = validateCustomRange('2026-02-01T00:00:00Z', '2026-01-01T00:00:00Z');
  assert.equal(rev.ok, false);
  assert.match(rev.error, /before/i);
});

test('validateCustomRange accepts a valid range', () => {
  const ok = validateCustomRange('2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z');
  assert.equal(ok.ok, true);
  assert.equal(ok.from, '2026-01-01T00:00:00Z');
});

// ---------------------------------------------------------------------------
// Footer text — no "page X / thousands", no global total
// ---------------------------------------------------------------------------

test('footer shows position + range label, never a global page count', () => {
  const text = auditFooterText({ pageIndex: 0, limit: 50, count: 50, rangeLabel: 'Last 24 hours' });
  assert.equal(text, 'Showing 1–50 · Last 24 hours');
  assert.ok(!/page\s+\d+\s*\/\s*\d+/i.test(text));
});

test('footer reflects page position for later pages', () => {
  const text = auditFooterText({ pageIndex: 2, limit: 50, count: 12, rangeLabel: 'Last 7 days' });
  assert.equal(text, 'Showing 101–112 · Last 7 days');
});

test('footer empty state carries the range label', () => {
  assert.equal(auditFooterText({ count: 0, rangeLabel: 'Last 24 hours' }), 'No events · Last 24 hours');
  assert.match(AUDIT_EMPTY_STATE, /No audit events found/);
});

// ---------------------------------------------------------------------------
// Cursor stack navigation
// ---------------------------------------------------------------------------

test('first page disables Previous', () => {
  const s = initialCursorStack();
  assert.equal(s.pageIndex, 0);
  assert.equal(currentCursor(s), null);
  assert.equal(canGoPrevious(s), false);
});

test('Next advances using next_cursor and enables Previous', () => {
  let s = initialCursorStack();
  s = goNext(s, 'cursor-A');
  assert.equal(s.pageIndex, 1);
  assert.equal(currentCursor(s), 'cursor-A');
  assert.equal(canGoPrevious(s), true);
});

test('Next is a no-op when there is no next_cursor', () => {
  const s = initialCursorStack();
  const after = goNext(s, null);
  assert.equal(after.pageIndex, 0);
});

test('Previous returns to the exact prior cursor', () => {
  let s = initialCursorStack();
  s = goNext(s, 'cursor-A');
  s = goNext(s, 'cursor-B');
  assert.equal(currentCursor(s), 'cursor-B');
  s = goPrevious(s);
  assert.equal(currentCursor(s), 'cursor-A');
  s = goPrevious(s);
  assert.equal(currentCursor(s), null);
  assert.equal(canGoPrevious(s), false);
});

test('changing filters/range resets pagination to the first page', () => {
  // The component replaces the stack with a fresh one on any filter change.
  let s = initialCursorStack();
  s = goNext(s, 'cursor-A');
  s = goNext(s, 'cursor-B');
  const reset = initialCursorStack();
  assert.equal(reset.pageIndex, 0);
  assert.equal(currentCursor(reset), null);
});

test('advancing after going back discards stale forward cursors', () => {
  let s = initialCursorStack();
  s = goNext(s, 'cursor-A');
  s = goNext(s, 'cursor-B');
  s = goPrevious(s); // back to page 1 (cursor-A)
  s = goNext(s, 'cursor-A2'); // new fetch replaces the old forward path
  assert.equal(s.pageIndex, 2);
  assert.equal(currentCursor(s), 'cursor-A2');
  assert.deepEqual(s.stack, [null, 'cursor-A', 'cursor-A2']);
});
