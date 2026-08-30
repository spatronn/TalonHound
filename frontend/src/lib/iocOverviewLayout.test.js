import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTIVE_SOURCES_COLUMNS, buildIocSummaryStripItems } from './iocOverviewLayout.js';
import { computeOverflowMenuPosition } from './backupMenuPosition.js';
import { listSourceMembershipActions } from './iocDetailTimestamps.js';

test('Active Sources keeps simplified columns without timestamp bloat', () => {
  assert.deepEqual(ACTIVE_SOURCES_COLUMNS, [
    'Source',
    'Type',
    'Status',
    'Policy expires',
    'Effective expires',
    'Override',
    'Actions'
  ]);
  const blob = ACTIVE_SOURCES_COLUMNS.join('|').toLowerCase();
  assert.equal(blob.includes('first seen'), false);
  assert.equal(blob.includes('inserted into platform'), false);
  assert.equal(blob.includes('last changed'), false);
});

test('summary strip only exposes Type and Sources', () => {
  const items = buildIocSummaryStripItems({
    observable_type: 'sha256',
    active_source_count: 1,
    total_source_membership_count: 1,
    first_seen_at: '2026-07-26T14:30:05.000Z',
    last_seen_at: '2026-07-26T14:30:05.000Z'
  });
  assert.deepEqual(items.map((i) => i.label), ['Type', 'Sources']);
  assert.equal(items[0].value, 'sha256');
  assert.equal(items[1].value, '1 / 1 total');
});

test('source actions menu placement flips above when near viewport bottom', () => {
  const trigger = { top: 700, bottom: 732, left: 900, right: 932, width: 32, height: 32 };
  const pos = computeOverflowMenuPosition({
    trigger,
    menuWidth: 180,
    menuHeight: 168,
    viewportWidth: 1366,
    viewportHeight: 768
  });
  assert.equal(pos.placement, 'top');
  assert.ok(pos.top + 168 <= trigger.top);
});

test('source action enabled/disabled states remain for kebab items', () => {
  const actions = listSourceMembershipActions({
    source_type: 'feed',
    status: 'active',
    actions_enabled: true,
    override_enabled: false
  });
  assert.equal(actions.length, 4);
  assert.equal(actions.find((a) => a.type === 'reactivate_membership')?.enabled, false);
  assert.equal(actions.find((a) => a.type === 'custom_expire_membership')?.enabled, true);
  assert.equal(actions.find((a) => a.type === 'expire_membership')?.enabled, true);
  assert.equal(actions.find((a) => a.type === 'clear_membership_override')?.enabled, false);
});
