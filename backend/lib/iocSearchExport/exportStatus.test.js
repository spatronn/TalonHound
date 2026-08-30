import test from 'node:test';
import assert from 'node:assert/strict';
import {
  effectiveExportStatus,
  publicFailureReason,
  parseListStatusFilter,
  parseListPagination,
  EXPORT_TASK_TYPE
} from './exportStatus.js';

test('effectiveExportStatus flips ready past expires_at to expired', () => {
  const now = new Date('2026-07-25T12:00:00.000Z');
  assert.equal(
    effectiveExportStatus({ status: 'ready', expires_at: '2026-07-25T11:00:00.000Z' }, now),
    'expired'
  );
  assert.equal(
    effectiveExportStatus({ status: 'ready', expires_at: '2026-07-25T13:00:00.000Z' }, now),
    'ready'
  );
  assert.equal(effectiveExportStatus({ status: 'failed' }, now), 'failed');
});

test('publicFailureReason redacts paths and truncates', () => {
  assert.equal(publicFailureReason('/data/ioc-search-exports/abc.csv boom'), '[path] boom');
  assert.equal(publicFailureReason('C:\\Temp\\x.csv fail'), '[path] fail');
  const long = 'x'.repeat(400);
  assert.ok(publicFailureReason(long).endsWith('...'));
  assert.ok(publicFailureReason(long).length <= 280);
});

test('publicFailureReason redacts raw PostgreSQL shared-memory internals (defense in depth)', () => {
  const raw = 'could not resize shared memory segment "/PostgreSQL.1786937221" to 33554432 bytes: No space left on device';
  const out = publicFailureReason(raw);
  // The DSM object name and the "shared memory segment ..." internals must not survive.
  assert.doesNotMatch(out, /PostgreSQL\.\d+/);
  assert.doesNotMatch(out, /shared memory segment/i);
  assert.doesNotMatch(out, /33554432/); // segment size stripped along with the segment clause
});

test('publicFailureReason leaves the classified safe message intact', () => {
  const safe = 'Export failed due to insufficient database shared memory. Check server resources and retry.';
  assert.equal(publicFailureReason(safe), safe);
});

test('parseListStatusFilter validates buckets', () => {
  assert.equal(parseListStatusFilter('all'), null);
  assert.deepEqual(parseListStatusFilter('processing'), ['queued', 'processing']);
  assert.deepEqual(parseListStatusFilter('ready'), ['ready']);
  assert.deepEqual(parseListStatusFilter('failed'), ['failed']);
  assert.equal(parseListStatusFilter('nope'), undefined);
});

test('parseListPagination prefers page/page_size', () => {
  assert.deepEqual(parseListPagination({ page: 2, pageSize: 25 }), {
    limit: 25,
    offset: 25,
    page: 2,
    pageSize: 25
  });
  assert.deepEqual(parseListPagination({ limit: 50, offset: 100 }), {
    limit: 50,
    offset: 100,
    page: 3,
    pageSize: 50
  });
});

test('EXPORT_TASK_TYPE constant', () => {
  assert.equal(EXPORT_TASK_TYPE, 'ioc_search_export');
});
