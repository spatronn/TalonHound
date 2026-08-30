import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveIocSourceState,
  isIocSourceSelectable,
  DELETE_BLOCKED_MESSAGE,
  DELETE_BLOCKED_PUBLISHED_FEEDS_MESSAGE,
  DELETE_BLOCK_REASON,
  isIocSourceDeleteAllowed,
  buildIocSourceDeletePreview
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
  assert.equal(isIocSourceSelectable({ name: 'API', active: true, archived_at: null }), false);
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

test('isIocSourceDeleteAllowed only allows zero IOC count', () => {
  assert.equal(isIocSourceDeleteAllowed(0), true);
  assert.equal(isIocSourceDeleteAllowed('0'), true);
  assert.equal(isIocSourceDeleteAllowed(1), false);
  assert.equal(isIocSourceDeleteAllowed(null), true);
});

test('buildIocSourceDeletePreview matches list and delete gate logic', () => {
  const empty = buildIocSourceDeletePreview({ id: 3, name: 'manual-test', ioc_count: 0 });
  assert.equal(empty.can_delete, true);
  assert.equal(empty.blocked_reason, null);
  assert.equal(empty.ioc_count, 0);
  assert.equal(empty.usage_count, 0);
  assert.deepEqual(empty.published_feed_dependencies, []);

  const used = buildIocSourceDeletePreview({ id: 4, name: 'manual-used', ioc_count: 7 });
  assert.equal(used.can_delete, false);
  assert.equal(used.blocked_reason, DELETE_BLOCK_REASON.HAS_IOCS);
  assert.equal(used.blocked_message, DELETE_BLOCKED_MESSAGE);
  assert.equal(used.ioc_count, 7);
  assert.equal(used.usage_count, 7);

  const feedBlocked = buildIocSourceDeletePreview(
    { id: 5, name: 'manual-smoke', ioc_count: 0 },
    [{ id: 2, name: 'test_2', key: 'manual:5' }]
  );
  assert.equal(feedBlocked.can_delete, false);
  assert.equal(feedBlocked.blocked_reason, DELETE_BLOCK_REASON.PUBLISHED_FEED_DEPENDENCY);
  assert.equal(feedBlocked.blocked_message, DELETE_BLOCKED_PUBLISHED_FEEDS_MESSAGE);
  assert.equal(feedBlocked.published_feed_dependencies.length, 1);
});

test('archived unused source preview allows delete when no feed dependencies', () => {
  const preview = buildIocSourceDeletePreview({
    id: 5,
    name: 'manual-archived-empty',
    ioc_count: 0,
    archived_at: '2026-06-01T00:00:00.000Z'
  });
  assert.equal(preview.can_delete, true);
});
