import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createDeepSearch,
  findActiveDuplicate,
  claimForProcessing,
  markCompleted,
  getResultsPage,
  deleteResultsBatch
} from './deepSearchStore.js';

// A mock pool that records queries and returns a scripted row/rowCount.
function recorder(result = { rows: [], rowCount: 0 }) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      calls.push({ sql: String(sql), params });
      return typeof result === 'function' ? result(String(sql), params) : result;
    }
  };
}

test('createDeepSearch binds AST as jsonb and stores the fingerprint', async () => {
  const db = recorder({ rows: [{ id: 'ds-1' }], rowCount: 1 });
  await createDeepSearch(db, {
    originalQuery: 'source contains "USOM"',
    normalizedQuery: 'source contains "USOM"',
    normalizedAst: { type: 'condition', field: 'source' },
    queryFingerprint: 'fp-1',
    classificationReason: 'source_scan',
    origin: 'classified',
    requestedById: 7,
    requestedByEmail: 'a@example.com'
  });
  const call = db.calls[0];
  assert.match(call.sql, /INSERT INTO ioc_deep_searches/);
  assert.match(call.sql, /\$3::jsonb/);
  // AST is JSON-stringified, not passed as an object.
  assert.equal(typeof call.params[2], 'string');
  assert.equal(call.params[3], 'fp-1');
  assert.equal(call.params[5], 'classified');
});

test('findActiveDuplicate scopes to owner id + fingerprint + active statuses', async () => {
  const db = recorder({ rows: [], rowCount: 0 });
  await findActiveDuplicate(db, { userId: 7, queryFingerprint: 'fp-1' });
  const call = db.calls[0];
  assert.match(call.sql, /requested_by_id = \$1/);
  assert.match(call.sql, /query_fingerprint = \$2/);
  assert.match(call.sql, /status IN \('queued', 'running'\)/);
  assert.deepEqual(call.params, [7, 'fp-1']);
});

test('claimForProcessing only claims a queued row (atomic status flip)', async () => {
  const db = recorder({ rows: [{ id: 'ds-1', status: 'running' }], rowCount: 1 });
  const row = await claimForProcessing(db, 'ds-1', '2026-08-08T00:00:00Z');
  assert.equal(row.status, 'running');
  const call = db.calls[0];
  assert.match(call.sql, /SET status = 'running'/);
  assert.match(call.sql, /WHERE id = \$1 AND status = 'queued'/);
});

test('markCompleted records exact match count + duration and is cancel-guarded', async () => {
  const db = recorder({ rows: [], rowCount: 1 });
  const ok = await markCompleted(db, 'ds-1', { matchCount: 485031, durationMs: 8400, expiresAt: '2026-08-09T00:00:00Z' });
  assert.equal(ok, true);
  const call = db.calls[0];
  assert.match(call.sql, /status = 'completed'/);
  // Completion only fires for a still-running, not-cancelled row — cannot overwrite a cancel.
  assert.match(call.sql, /WHERE id = \$1 AND status = 'running' AND cancel_requested = FALSE/);
  assert.deepEqual(call.params, ['ds-1', 485031, 8400, '2026-08-09T00:00:00Z']);
});

test('markCompleted returns false when the row is no longer running (lost cancel race)', async () => {
  const db = recorder({ rows: [], rowCount: 0 });
  const ok = await markCompleted(db, 'ds-1', { matchCount: 10, durationMs: 5, expiresAt: '2026-08-09T00:00:00Z' });
  assert.equal(ok, false);
});

test('getResultsPage keyset-paginates in canonical order (no OFFSET)', async () => {
  const db = recorder({ rows: [], rowCount: 0 });
  await getResultsPage(db, 'ds-1', { cursor: { t: '2026-08-08T00:00:00Z', id: '42' }, limit: 25 });
  const call = db.calls[0];
  assert.match(call.sql, /ORDER BY created_at DESC, ioc_item_id DESC/);
  assert.match(call.sql, /\(created_at, ioc_item_id\) < \(/);
  assert.ok(!/OFFSET/i.test(call.sql), 'must not use OFFSET');
  assert.equal(call.params[0], 'ds-1');
});

test('deleteResultsBatch deletes a bounded batch by deep_search_id', async () => {
  const db = recorder({ rows: [], rowCount: 10 });
  const n = await deleteResultsBatch(db, 'ds-1', 10_000);
  assert.equal(n, 10);
  const call = db.calls[0];
  assert.match(call.sql, /DELETE FROM ioc_deep_search_results/);
  assert.match(call.sql, /LIMIT \$2/);
  assert.equal(call.params[1], 10_000);
});
