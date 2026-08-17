import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseQueryWideRequest,
  compileQueryWideTarget,
  resolveQueryWideTarget,
  decideExecutionMode,
  extraAuditMetadata,
  payloadFromBody,
  mergeOutcomes,
  errorSampleFromResults,
  streamDeepSearchIocIds,
  deepSearchAvailableForInFlightBulk,
  expectedCountForInFlightDeepSearchJob
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

test('expensive classifier queries compile when bound to a completed Deep Search', () => {
  const r = compileQueryWideTarget('ioc contains "a"', { allowExpensive: true });
  assert.equal(r.ok, true);
  assert.match(r.normalizedQuery, /ioc contains "a"/i);
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
  assert.equal(decideExecutionMode(2_160_030, cfg, { skipHardLimit: true }).ok, true);
  assert.equal(decideExecutionMode(2_160_030, cfg, { skipHardLimit: true }).mode, 'async');
});

const DS_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const DS_ROW = {
  id: DS_ID,
  original_query: 'ioc contains "a"',
  normalized_query: 'ioc contains "a"',
  status: 'completed',
  match_count: 2160030,
  requested_by_id: 2,
  expires_at: new Date(Date.now() + 3600_000).toISOString()
};

test('audit metadata binds the exact normalized query', () => {
  const compiled = compileQueryWideTarget('tag contains "mirai"');
  const meta = extraAuditMetadata(compiled, 'suppress');
  assert.equal(meta.selection_mode, 'all_matching');
  assert.equal(meta.query, compiled.normalizedQuery);
  assert.equal(meta.bulk_action, 'suppress');
  assert.equal(Object.prototype.hasOwnProperty.call(meta, 'deep_search_id'), false);
});

test('Deep Search audit metadata includes deep_search_id', () => {
  const compiled = compileQueryWideTarget('ioc contains "a"', { allowExpensive: true });
  compiled.deepSearchId = DS_ID;
  const meta = extraAuditMetadata(compiled, 'tag');
  assert.equal(meta.deep_search_id, DS_ID);
  assert.match(meta.query, /ioc contains "a"/i);
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

test('parseQueryWideRequest accepts deep_search_id without a client query', () => {
  const parsed = parseQueryWideRequest({
    selection_mode: 'all_matching',
    deep_search_id: DS_ID,
    query: '',
    match_count: 1,
    ioc_ids: [1, 2, 3]
  }, 'tag');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.deepSearchId, DS_ID);
});

test('invalid deep_search_id is rejected', () => {
  const parsed = parseQueryWideRequest({
    selection_mode: 'all_matching',
    deep_search_id: 'not-a-uuid'
  }, 'tag');
  assert.equal(parsed.ok, false);
  assert.equal(parsed.code, 'INVALID_DEEP_SEARCH_ID');
});

test('resolveQueryWideTarget uses stored Deep Search query and exact count, ignoring client query', async () => {
  const compiled = await resolveQueryWideTarget(
    {},
    { deepSearchId: DS_ID, query: 'tag contains "tampered"' },
    {
      req: { user: { role: 'admin', id: 1 } },
      getDeepSearch: async () => DS_ROW,
      canAccess: () => true
    }
  );
  assert.equal(compiled.ok, true);
  assert.equal(compiled.deepSearchId, DS_ID);
  assert.equal(compiled.matchCount, 2160030);
  assert.match(compiled.normalizedQuery, /ioc contains "a"/i);
  assert.equal(compiled.originalQuery, 'ioc contains "a"');
});

test('resolveQueryWideTarget fails safely for missing, forbidden, expired, and null count', async () => {
  const missing = await resolveQueryWideTarget({}, { deepSearchId: DS_ID }, {
    req: {},
    getDeepSearch: async () => null,
    canAccess: () => true
  });
  assert.equal(missing.code, 'DEEP_SEARCH_NOT_FOUND');

  const forbidden = await resolveQueryWideTarget({}, { deepSearchId: DS_ID }, {
    req: {},
    getDeepSearch: async () => DS_ROW,
    canAccess: () => false
  });
  assert.equal(forbidden.code, 'FORBIDDEN');
  assert.equal(forbidden.status, 403);

  const expired = await resolveQueryWideTarget({}, { deepSearchId: DS_ID }, {
    req: {},
    getDeepSearch: async () => ({ ...DS_ROW, expires_at: '2020-01-01T00:00:00.000Z' }),
    canAccess: () => true
  });
  assert.equal(expired.code, 'DEEP_SEARCH_NOT_READY');

  const noCount = await resolveQueryWideTarget({}, { deepSearchId: DS_ID }, {
    req: {},
    getDeepSearch: async () => ({ ...DS_ROW, match_count: null }),
    canAccess: () => true
  });
  assert.equal(noCount.code, 'COUNT_UNAVAILABLE');
  assert.notEqual(noCount.matchCount, 0);
});

test('streamDeepSearchIocIds pages the full spool and never uses a 2,000 display cap', async () => {
  const pages = [
    { ids: [1, 2], lastPosition: 2 },
    { ids: [3], lastPosition: 3 },
    { ids: [], lastPosition: 3 }
  ];
  let calls = 0;
  const collected = [];
  const streamed = await streamDeepSearchIocIds({}, DS_ID, {
    chunkSize: 100,
    listPage: async (_pool, id, { afterPosition }) => {
      assert.equal(id, DS_ID);
      const page = pages[calls] || { ids: [], lastPosition: afterPosition };
      calls += 1;
      return page;
    },
    onChunk: async (ids) => { collected.push(...ids); }
  });
  assert.equal(streamed.ok, true);
  assert.equal(streamed.matchCount, 3);
  assert.deepEqual(collected, [1, 2, 3]);
  assert.ok(calls >= 2);
});

test('in-flight Deep Search bulk keeps the spool after UI expiry; new jobs still require browsable', async () => {
  const expired = {
    ...DS_ROW,
    status: 'expired',
    match_count: null,
    expires_at: '2020-01-01T00:00:00.000Z'
  };
  assert.equal(deepSearchAvailableForInFlightBulk(expired), true);
  assert.equal(deepSearchAvailableForInFlightBulk(null), false);
  assert.equal(deepSearchAvailableForInFlightBulk({}), false);

  assert.equal(expectedCountForInFlightDeepSearchJob({
    payload: { expected_match_count: 2160030 },
    jobMatchCount: null,
    deepSearchMatchCount: null
  }), 2160030);
  assert.equal(expectedCountForInFlightDeepSearchJob({
    payload: {},
    jobMatchCount: 2160030,
    deepSearchMatchCount: null
  }), 2160030);
  assert.equal(expectedCountForInFlightDeepSearchJob({
    payload: { expected_match_count: 'not-a-number' },
    jobMatchCount: null,
    deepSearchMatchCount: null
  }), null);

  const blocked = await resolveQueryWideTarget({}, { deepSearchId: DS_ID }, {
    req: {},
    getDeepSearch: async () => expired,
    canAccess: () => true
  });
  assert.equal(blocked.code, 'DEEP_SEARCH_NOT_READY');
});
