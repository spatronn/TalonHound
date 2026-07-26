import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFeedMetricsHints } from './feedMetricsHints.js';

test('no_delta does not fire on empty successful sync', () => {
  assert.deepEqual(
    buildFeedMetricsHints({ available: true, processed: 0, inserted: 0, updated: 0, unchanged: 0, skipped: 0, failed: 0 }),
    []
  );
});

test('no_delta for unchanged-heavy success', () => {
  const hints = buildFeedMetricsHints({
    available: true,
    processed: 100,
    inserted: 0,
    updated: 0,
    unchanged: 100,
    skipped: 0,
    failed: 0
  });
  assert.ok(hints.includes('no_delta'));
  assert.equal(hints.includes('high_failed'), false);
});

test('high_failed when ≥10% failed', () => {
  const hints = buildFeedMetricsHints({
    available: true,
    processed: 100,
    inserted: 50,
    updated: 0,
    unchanged: 30,
    skipped: 0,
    failed: 20
  });
  assert.ok(hints.includes('high_failed'));
});

test('partial_fetch from truncated run_details', () => {
  const hints = buildFeedMetricsHints(
    { available: true, processed: 0, inserted: 0, updated: 0, skipped: 0, failed: 0 },
    { runDetails: { truncated: true } }
  );
  assert.ok(hints.includes('partial_fetch'));
});

test('legacy_metrics short-circuits', () => {
  assert.deepEqual(
    buildFeedMetricsHints({ available: false, processed: 50 }),
    ['legacy_metrics']
  );
});
