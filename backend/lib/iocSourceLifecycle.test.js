import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveIocSourceState, isIocSourceSelectable } from './iocSourceLifecycle.js';
import { serializeIocSourceRow } from './iocSourceValidation.js';
import { summarizeMovePreview, normalizeScope } from './iocSourceMove.js';

test('resolveIocSourceState distinguishes active, disabled, archived', () => {
  assert.equal(resolveIocSourceState({ active: true, archived_at: null }), 'active');
  assert.equal(resolveIocSourceState({ active: false, archived_at: null }), 'disabled');
  assert.equal(resolveIocSourceState({ active: true, archived_at: '2026-01-01T00:00:00.000Z' }), 'archived');
});

test('isIocSourceSelectable only allows active non-archived sources', () => {
  assert.equal(isIocSourceSelectable({ active: true, archived_at: null }), true);
  assert.equal(isIocSourceSelectable({ active: false, archived_at: null }), false);
  assert.equal(isIocSourceSelectable({ active: true, archived_at: '2026-01-01T00:00:00.000Z' }), false);
});

test('serializeIocSourceRow exposes state and usage_count', () => {
  const row = serializeIocSourceRow({
    id: 1,
    name: 'manual-cobalt-strike',
    active: false,
    archived_at: '2026-06-01T00:00:00.000Z',
    usage_count: 12,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-06-01T00:00:00.000Z'
  });
  assert.equal(row.state, 'archived');
  assert.equal(row.active, false);
  assert.equal(row.usage_count, 12);
});

test('normalizeScope defaults to active_only', () => {
  assert.equal(normalizeScope(undefined), 'active_only');
  assert.equal(normalizeScope('all'), 'all');
  assert.equal(normalizeScope('invalid'), 'active_only');
});

test('summarizeMovePreview counts move vs merge candidates', () => {
  const summary = summarizeMovePreview(
    { id: 1, name: 'manual-threathunting' },
    { id: 2, name: 'manual-cobalt-strike' },
    'active_only',
    [
      { status: 'active', target_exists: false },
      { status: 'active', target_exists: true },
      { status: 'expired', target_exists: false }
    ],
    true
  );
  assert.equal(summary.total_memberships_matched, 3);
  assert.equal(summary.active_memberships_matched, 2);
  assert.equal(summary.inactive_memberships_matched, 1);
  assert.equal(summary.will_move, 2);
  assert.equal(summary.will_merge, 1);
  assert.equal(summary.archive_source_after_move, true);
  assert.equal(summary.possible_conflicts.length, 1);
});
