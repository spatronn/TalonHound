import test from 'node:test';
import assert from 'node:assert/strict';
import {
  queryFingerprint,
  effectiveDeepSearchStatus,
  isBrowsable,
  publicFailureReason,
  parseListStatusFilter,
  serializeDeepSearch,
  DEEP_SEARCH_TASK_TYPE
} from './deepSearchStatus.js';

test('queryFingerprint is stable and query-derived', () => {
  const a = queryFingerprint('source contains "USOM"');
  const b = queryFingerprint('source contains "USOM"');
  const c = queryFingerprint('source contains "Siber"');
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('completed row past expires_at reads as expired', () => {
  const past = new Date(Date.now() - 1000).toISOString();
  const row = { status: 'completed', expires_at: past };
  assert.equal(effectiveDeepSearchStatus(row), 'expired');
  assert.equal(isBrowsable(row), false);
});

test('completed row within retention is browsable', () => {
  const future = new Date(Date.now() + 3600_000).toISOString();
  const row = { status: 'completed', expires_at: future };
  assert.equal(effectiveDeepSearchStatus(row), 'completed');
  assert.equal(isBrowsable(row), true);
});

test('running row is neither expired nor browsable', () => {
  assert.equal(effectiveDeepSearchStatus({ status: 'running' }), 'running');
  assert.equal(isBrowsable({ status: 'running' }), false);
});

test('publicFailureReason strips paths and truncates', () => {
  assert.equal(publicFailureReason(null), null);
  const scrubbed = publicFailureReason('boom at /data/ioc/x.tmp and C:\\Users\\a\\b.txt');
  assert.ok(!scrubbed.includes('/data/ioc'));
  assert.ok(!scrubbed.includes('C:\\Users'));
});

test('parseListStatusFilter maps Action Center buckets to deep-search statuses', () => {
  assert.equal(parseListStatusFilter('all'), null);
  assert.deepEqual(parseListStatusFilter('processing'), ['queued', 'running']);
  assert.deepEqual(parseListStatusFilter('ready'), ['completed']);
  assert.deepEqual(parseListStatusFilter('failed'), ['failed']);
  assert.deepEqual(parseListStatusFilter('running'), ['running']);
  assert.equal(parseListStatusFilter('bogus'), undefined);
});

test('serializeDeepSearch omits SQL/AST internals and exposes safe fields', () => {
  const row = {
    id: 'ds-1',
    original_query: 'source contains "USOM"',
    normalized_query: 'source contains "USOM"',
    normalized_ast: { type: 'condition' },
    query_fingerprint: 'abc',
    classification_reason: 'source_scan',
    origin: 'classified',
    status: 'completed',
    requested_by_email: 'a@example.com',
    match_count: 485031,
    truncated: false,
    duration_ms: 8400,
    progress: 100,
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    failure_reason: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
  const out = serializeDeepSearch(row);
  assert.equal(out.task_type, DEEP_SEARCH_TASK_TYPE);
  assert.equal(out.match_count, 485031);
  assert.equal(out.status, 'completed');
  assert.equal(out.classification_reason, 'source_scan');
  assert.ok(!('normalized_ast' in out));
  assert.ok(!('query_fingerprint' in out));
});
