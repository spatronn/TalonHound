import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveIocSourceState,
  isIocSourceSelectable,
  DELETE_BLOCKED_MESSAGE
} from './iocSourceLifecycle.js';
import { serializeIocSourceRow } from './iocSourceValidation.js';
import { summarizeMovePreview, resolveApplyTargetDefaults } from './iocSourceMove.js';

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

test('serializeIocSourceRow exposes state and ioc_count', () => {
  const row = serializeIocSourceRow({
    id: 1,
    name: 'manual-cobalt-strike',
    active: false,
    archived_at: '2026-06-01T00:00:00.000Z',
    ioc_count: 12,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-06-01T00:00:00.000Z'
  });
  assert.equal(row.state, 'archived');
  assert.equal(row.active, false);
  assert.equal(row.ioc_count, 12);
  assert.equal(row.usage_count, 12);
});

test('resolveApplyTargetDefaults defaults to true', () => {
  assert.equal(resolveApplyTargetDefaults({}), true);
  assert.equal(resolveApplyTargetDefaults({ apply_target_defaults: false }), false);
  assert.equal(resolveApplyTargetDefaults({ apply_target_defaults: true }), true);
});

test('summarizeMovePreview counts move vs merge candidates', () => {
  const summary = summarizeMovePreview(
    { id: 1, name: 'manual-threathunting' },
    { id: 2, name: 'manual-cobalt-strike' },
    [
      { target_exists: false },
      { target_exists: true },
      { target_exists: false }
    ]
  );
  assert.equal(summary.ioc_count, 3);
  assert.equal(summary.will_move, 2);
  assert.equal(summary.will_merge, 1);
  assert.equal(summary.source_will_be_empty_after_move, true);
});

test('delete blocked message matches product copy', () => {
  assert.match(DELETE_BLOCKED_MESSAGE, /Move them to another source before deleting/);
});
