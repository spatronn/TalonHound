import test from 'node:test';
import assert from 'node:assert/strict';
import { hasActiveBulkJobForDeepSearch } from './store.js';
import { ACTIVE_BULK_QUERY_STATUSES } from './status.js';

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

test('hasActiveBulkJobForDeepSearch looks up queued/processing jobs by payload deep_search_id', async () => {
  const db = recorder({ rows: [{ '?column?': 1 }], rowCount: 1 });
  const found = await hasActiveBulkJobForDeepSearch(db, 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
  assert.equal(found, true);
  const call = db.calls[0];
  assert.match(call.sql, /FROM ioc_bulk_query_jobs/);
  assert.match(call.sql, /payload->>'deep_search_id' = \$1/);
  assert.match(call.sql, /status = ANY\(\$2::text\[\]\)/);
  assert.equal(call.params[0], 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
  assert.deepEqual(call.params[1], ['queued', 'processing']);
  assert.deepEqual([...ACTIVE_BULK_QUERY_STATUSES], ['queued', 'processing']);
});

test('hasActiveBulkJobForDeepSearch is false for terminal jobs and empty ids', async () => {
  const db = recorder({ rows: [], rowCount: 0 });
  assert.equal(await hasActiveBulkJobForDeepSearch(db, 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'), false);
  assert.equal(await hasActiveBulkJobForDeepSearch(db, ''), false);
  assert.equal(await hasActiveBulkJobForDeepSearch(db, null), false);
  assert.equal(db.calls.length, 1);
});
