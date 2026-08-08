import test from 'node:test';
import assert from 'node:assert/strict';
import {
  actionCenterPollIntervalMs,
  actionCenterStatusBadgeStyle,
  buildActionCenterListParams,
  formatExpiresIn,
  formatFileSize,
  formatActionCenterStatus,
  hasLegacySearchExportsModal,
  truncateQuery,
  taskTypeLabel
} from './actionCenter.js';

test('taskTypeLabel maps IOC search export', () => {
  assert.equal(taskTypeLabel('ioc_search_export'), 'IOC Search Export');
});

test('formatExpiresIn handles remaining time and expired', () => {
  const now = Date.parse('2026-07-25T12:00:00.000Z');
  assert.equal(formatExpiresIn(new Date(now + 90 * 60 * 1000).toISOString(), now), 'Expires in 1h 30m');
  assert.equal(formatExpiresIn(new Date(now - 1000).toISOString(), now), 'Expired');
  assert.equal(formatExpiresIn(null, now), '—');
});

test('formatFileSize and truncateQuery', () => {
  assert.equal(formatFileSize(512), '512 B');
  assert.equal(formatFileSize(2048), '2.0 KB');
  assert.equal(truncateQuery('abcdefghij', 8), 'abcdefg…');
  assert.equal(truncateQuery('short', 8), 'short');
});

test('formatActionCenterStatus includes progress for processing', () => {
  assert.equal(formatActionCenterStatus({ status: 'processing', progress: 42 }), 'Processing 42%');
  assert.equal(formatActionCenterStatus({ status: 'ready' }), 'Ready');
});

test('poll interval is faster when active jobs exist', () => {
  assert.equal(actionCenterPollIntervalMs([{ status: 'queued' }]), 3000);
  assert.equal(actionCenterPollIntervalMs([{ status: 'ready' }]), 15000);
});

test('buildActionCenterListParams omits status=all', () => {
  assert.deepEqual(buildActionCenterListParams({ page: 2, pageSize: 25, status: 'all' }), {
    page: 2,
    page_size: 25
  });
  assert.deepEqual(buildActionCenterListParams({ page: 1, status: 'failed' }), {
    page: 1,
    page_size: 25,
    status: 'failed'
  });
});

test('deep-search task type has a label', () => {
  assert.equal(taskTypeLabel('ioc_deep_search'), 'IOC Deep Search');
});

test('deep-search statuses share export badge/status vocabulary', () => {
  // 'completed'/'running' (deep search) render like 'ready'/'processing' (export).
  assert.deepEqual(actionCenterStatusBadgeStyle('completed'), actionCenterStatusBadgeStyle('ready'));
  assert.deepEqual(actionCenterStatusBadgeStyle('running'), actionCenterStatusBadgeStyle('processing'));
  assert.equal(formatActionCenterStatus({ status: 'running', progress: 0 }), 'Running');
  assert.equal(formatActionCenterStatus({ status: 'running', progress: 40 }), 'Running 40%');
  assert.equal(formatActionCenterStatus({ status: 'completed' }), 'Completed');
});

test('poll interval treats running deep searches as active', () => {
  assert.equal(actionCenterPollIntervalMs([{ status: 'running' }]), 3000);
  assert.equal(actionCenterPollIntervalMs([{ status: 'completed' }]), 15000);
});

test('legacy Search Exports modal detector', () => {
  assert.equal(hasLegacySearchExportsModal('<h3>Search Exports</h3>'), true);
  assert.equal(hasLegacySearchExportsModal('<h3>Action Center</h3>'), false);
});

test('IOC List source no longer contains Search Exports modal heading', async () => {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const mainJsx = await fs.readFile(path.join(here, '../main.jsx'), 'utf8');
  assert.equal(hasLegacySearchExportsModal(mainJsx), false);
  assert.match(mainJsx, /Action Center/);
  assert.match(mainJsx, /path="\/action-center"/);
  assert.match(mainJsx, /Open Action Center/);
  assert.match(mainJsx, /Export task created\. Track its progress in Action Center\./);
});
