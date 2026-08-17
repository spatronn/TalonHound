import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseQueryWideRequest,
  compileQueryWideTarget,
  decideExecutionMode,
  extraAuditMetadata,
  payloadFromBody,
  mergeOutcomes,
  errorSampleFromResults
} from './iocBulkQueryTriage.js';

test('empty query is rejected for all_matching', () => {
  assert.equal(parseQueryWideRequest({ query: '' }, 'tag').code, 'EMPTY_QUERY');
  assert.equal(parseQueryWideRequest({ query: '   ' }, 'suppress').code, 'EMPTY_QUERY');
  assert.equal(compileQueryWideTarget('').code, 'EMPTY_QUERY');
});

test('malformed query is rejected', () => {
  const r = compileQueryWideTarget('tag contains');
  assert.equal(r.ok, false);
  assert.equal(r.status, 400);
});

test('unfiltered browse cannot compile a query-wide target', () => {
  assert.equal(compileQueryWideTarget(null).code, 'EMPTY_QUERY');
});

test('expensive classifier queries are refused rather than scanned interactively', () => {
  const r = compileQueryWideTarget('source contains "USOM"');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'QUERY_TOO_EXPENSIVE');
  assert.equal(r.status, 409);
});

test('interactive tag query compiles to the current DSL', () => {
  const r = compileQueryWideTarget('tag contains "mirai"');
  assert.equal(r.ok, true);
  assert.match(r.normalizedQuery, /tag contains "mirai"/i);
  assert.ok(r.whereSql);
});

test('invalid action is rejected', () => {
  const r = parseQueryWideRequest({ query: 'tag contains "mirai"' }, 'delete');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_ACTION');
});

test('client match_count is not part of the compiled payload', () => {
  const payload = payloadFromBody('tag', { tag_id: 9, match_count: 1, ioc_ids: [1, 2, 3] });
  assert.deepEqual(payload, { tag_id: 9 });
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'match_count'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'ioc_ids'), false);
});

test('sync vs async follows expiration-batch sized sync max', () => {
  const cfg = { syncMax: 500, hardLimit: 50_000 };
  assert.equal(decideExecutionMode(47, cfg).mode, 'sync');
  assert.equal(decideExecutionMode(500, cfg).mode, 'sync');
  assert.equal(decideExecutionMode(2143, cfg).mode, 'async');
  assert.equal(decideExecutionMode(50_001, cfg).ok, false);
  assert.equal(decideExecutionMode(50_001, cfg).code, 'HARD_LIMIT');
});

test('audit metadata binds the exact normalized query', () => {
  const compiled = compileQueryWideTarget('tag contains "mirai"');
  const meta = extraAuditMetadata(compiled, 'suppress');
  assert.equal(meta.selection_mode, 'all_matching');
  assert.equal(meta.query, compiled.normalizedQuery);
  assert.equal(meta.bulk_action, 'suppress');
});

test('partial failures are retained in the merged outcome sample', () => {
  const merged = mergeOutcomes(
    { requested: 2, succeeded: 1, skipped: 0, failed: 1, results: [{ id: 1, status: 'ok' }, { id: 2, status: 'error', message: 'nope' }] },
    { requested: 1, succeeded: 1, skipped: 0, failed: 0, results: [{ id: 3, status: 'ok' }] }
  );
  assert.equal(merged.requested, 3);
  assert.equal(merged.failed, 1);
  assert.deepEqual(errorSampleFromResults(merged.results), [{ id: 2, message: 'nope' }]);
});
