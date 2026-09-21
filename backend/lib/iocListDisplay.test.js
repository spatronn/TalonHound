import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeIocLifecycleStatus,
  resolveIocDisplaySource,
  decorateIocListItems,
  resolveIocListStatusScope
} from './iocListDisplay.js';

test('resolveIocListStatusScope uses all statuses when searching', () => {
  assert.equal(resolveIocListStatusScope(true, 'active'), 'all');
  assert.equal(resolveIocListStatusScope(true, 'expired'), 'all');
  assert.equal(resolveIocListStatusScope(false, 'active'), 'active');
  assert.equal(resolveIocListStatusScope(false, undefined), 'active');
});

test('normalizeIocLifecycleStatus maps lifecycle values', () => {
  assert.equal(normalizeIocLifecycleStatus('active'), 'Active');
  assert.equal(normalizeIocLifecycleStatus('expired'), 'Expired');
  assert.equal(normalizeIocLifecycleStatus('suppressed'), 'Suppressed');
  assert.equal(normalizeIocLifecycleStatus('disabled'), 'Inactive');
  assert.equal(normalizeIocLifecycleStatus('inactive'), 'Inactive');
});

test('resolveIocDisplaySource prefers active then historical sources', () => {
  assert.deepEqual(resolveIocDisplaySource({
    source_names: ['Feed A'],
    historical_sources: [{ feed_name: 'Old Feed' }]
  }), { label: 'Feed A', extra: 0, kind: 'active' });

  assert.deepEqual(resolveIocDisplaySource({
    source_names: [],
    historical_sources: [{ feed_name: 'Old Feed' }, { feed_name: 'Old Feed 2' }]
  }), { label: 'Old Feed', extra: 1, kind: 'historical' });

  assert.deepEqual(resolveIocDisplaySource({}), { label: 'No active source', extra: 0, kind: 'none' });
});

test('decorateIocListItems adds lifecycle and display source fields', () => {
  const [item] = decorateIocListItems([{
    status: 'expired',
    source_names: [],
    historical_sources: [{ feed_name: 'Legacy Feed' }]
  }]);
  assert.equal(item.lifecycle_status, 'Expired');
  assert.equal(item.display_source, 'Legacy Feed');
  assert.equal(item.display_source_kind, 'historical');
});

test('decorateIocListItems shows Threat_Library for canonical hash row with active source_names', () => {
  const [item] = decorateIocListItems([{
    id: 3475208,
    observable: '3f5ff48aa4dc2c1af3deeb33a9cc576616dad37156ae9182831b1b2a5ae4ae20',
    observable_type: 'sha256',
    status: 'active',
    source_names: ['Threat_Library'],
    active_source_count: 1
  }]);
  assert.equal(item.observable_type, 'sha256');
  assert.equal(item.display_source, 'Threat_Library');
  assert.equal(item.display_source_kind, 'active');
  assert.notEqual(item.display_source, 'No active source');
});
