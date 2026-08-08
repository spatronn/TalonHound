import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSearchQuery } from '../iocSearchDsl/index.js';
import { enqueueDeepSearch } from './enqueueDeepSearch.js';
import { queryFingerprint } from './deepSearchStatus.js';

// Minimal in-memory pool that models the two lookups enqueue performs (active-duplicate,
// active-count) plus the insert + setJobId.
function makePool({ existingDuplicate = null, activeCount = 0 } = {}) {
  const inserted = [];
  return {
    inserted,
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('status IN (\'queued\', \'running\')') && s.includes('ORDER BY created_at DESC')) {
        return { rows: existingDuplicate ? [existingDuplicate] : [], rowCount: existingDuplicate ? 1 : 0 };
      }
      if (s.includes('COUNT(*)::int AS n')) {
        return { rows: [{ n: activeCount }], rowCount: 1 };
      }
      if (s.includes('INSERT INTO ioc_deep_searches')) {
        const row = {
          id: `ds-${inserted.length + 1}`,
          original_query: params[0],
          normalized_query: params[1],
          normalized_ast: params[2],
          query_fingerprint: params[3],
          classification_reason: params[4],
          origin: params[5],
          status: 'queued'
        };
        inserted.push(row);
        return { rows: [row], rowCount: 1 };
      }
      if (s.includes('SET job_id')) return { rows: [], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    }
  };
}

function makeQueue() {
  const added = [];
  return { added, async add(name, data, opts) { added.push({ name, data, opts }); return { id: `job-${added.length}` }; } };
}

const parsed = parseSearchQuery('source contains "USOM"');

test('enqueue creates a job and preserves the normalized query + AST', async () => {
  const pool = makePool();
  const queue = makeQueue();
  const { row, deduped } = await enqueueDeepSearch(pool, queue, {
    originalQuery: 'source contains "USOM"',
    normalizedQuery: parsed.normalizedQuery,
    normalizedAst: parsed.ast,
    classificationReason: 'source_scan',
    origin: 'classified',
    requestedById: 1,
    requestedByEmail: 'a@example.com'
  });
  assert.equal(deduped, false);
  assert.equal(queue.added.length, 1);
  assert.equal(queue.added[0].data.deepSearchId, row.id);
  assert.equal(row.normalized_query, parsed.normalizedQuery);
  assert.equal(row.query_fingerprint, queryFingerprint(parsed.normalizedQuery));
});

test('enqueue dedupes an identical in-flight search (at most once)', async () => {
  const existing = { id: 'ds-existing', normalized_query: parsed.normalizedQuery, status: 'running' };
  const pool = makePool({ existingDuplicate: existing });
  const queue = makeQueue();
  const { row, deduped } = await enqueueDeepSearch(pool, queue, {
    originalQuery: 'source contains "USOM"',
    normalizedQuery: parsed.normalizedQuery,
    normalizedAst: parsed.ast,
    classificationReason: 'interactive_statement_timeout',
    origin: 'timeout_fallback',
    requestedByEmail: 'a@example.com'
  });
  assert.equal(deduped, true);
  assert.equal(row.id, 'ds-existing');
  assert.equal(queue.added.length, 0, 'no new job enqueued when deduped');
  assert.equal(pool.inserted.length, 0, 'no new row inserted when deduped');
});

test('enqueue rejects over the per-user concurrency limit (429)', async () => {
  const pool = makePool({ activeCount: 99 });
  const queue = makeQueue();
  await assert.rejects(
    () => enqueueDeepSearch(pool, queue, {
      originalQuery: 'source contains "USOM"',
      normalizedQuery: parsed.normalizedQuery,
      normalizedAst: parsed.ast,
      requestedByEmail: 'a@example.com'
    }),
    (err) => err.status === 429
  );
  assert.equal(queue.added.length, 0);
});

test('enqueue requires an actor email (401)', async () => {
  const pool = makePool();
  const queue = makeQueue();
  await assert.rejects(
    () => enqueueDeepSearch(pool, queue, {
      originalQuery: 'x',
      normalizedQuery: parsed.normalizedQuery,
      normalizedAst: parsed.ast,
      requestedByEmail: ''
    }),
    (err) => err.status === 401
  );
});
