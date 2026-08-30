import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RUN_COUNTER_COLUMNS,
  resolveRunCounters,
  resolveUnchangedCount
} from './integrationRunCounters.js';

test('unchanged resolves via records_unchanged ?? records_duplicate ?? 0', () => {
  // Migrated importer: canonical field wins even when both are present.
  assert.equal(resolveUnchangedCount({ records_unchanged: 7, records_duplicate: 7 }), 7);
  // Legacy row written before migration 121: fall back to the deprecated column.
  assert.equal(resolveUnchangedCount({ records_duplicate: 5 }), 5);
  // Neither present.
  assert.equal(resolveUnchangedCount({}), 0);
  assert.equal(resolveUnchangedCount(null), 0);
});

test('zero is respected and does not fall through to the deprecated column', () => {
  // A migrated run that genuinely saw 0 unchanged rows must report 0, not inherit a
  // stale records_duplicate value.
  assert.equal(resolveUnchangedCount({ records_unchanged: 0, records_duplicate: 99 }), 0);
});

test('duplicate is emitted as an exact alias of unchanged', () => {
  const migrated = resolveRunCounters({ records_unchanged: 4, records_duplicate: 4 });
  assert.equal(migrated.unchanged, 4);
  assert.equal(migrated.duplicate, migrated.unchanged);

  // Even for a legacy row the two agree, so no client can observe a contradiction.
  const legacy = resolveRunCounters({ records_duplicate: 6 });
  assert.equal(legacy.unchanged, 6);
  assert.equal(legacy.duplicate, 6);

  // And a disagreeing row is normalized rather than passed through.
  const inconsistent = resolveRunCounters({ records_unchanged: 2, records_duplicate: 99 });
  assert.equal(inconsistent.unchanged, 2);
  assert.equal(inconsistent.duplicate, 2, 'alias must never contradict the canonical field');
});

test('all counters are non-negative integers', () => {
  const counters = resolveRunCounters({
    records_processed: '12',
    records_inserted: -3,
    records_updated: null,
    records_unchanged: 4.7,
    records_reactivated: undefined,
    records_removed: 'nope'
  });
  assert.equal(counters.processed, 12, 'numeric strings are coerced');
  assert.equal(counters.inserted, 0, 'negatives clamp to 0');
  assert.equal(counters.updated, 0);
  assert.equal(counters.unchanged, 4, 'fractions floor');
  assert.equal(counters.reactivated, 0);
  assert.equal(counters.removed, 0, 'non-numeric clamps to 0');
});

test('new lifecycle counters are exposed', () => {
  const counters = resolveRunCounters({
    records_unchanged: 1,
    records_reactivated: 2,
    records_removed: 3
  });
  assert.equal(counters.reactivated, 2);
  assert.equal(counters.removed, 3);
});

test('column list covers every field resolveRunCounters reads', () => {
  // Guards against a new counter being added to one query but forgotten in another.
  for (const column of [
    'records_processed', 'records_inserted', 'records_updated',
    'records_unchanged', 'records_reactivated', 'records_removed',
    'records_duplicate', 'records_skipped', 'records_suppressed', 'records_failed'
  ]) {
    assert.ok(RUN_COUNTER_COLUMNS.includes(column), `missing projection column: ${column}`);
  }
});
