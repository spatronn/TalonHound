import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  nextReconciliationProgress,
  reconciliationBatchSize,
  reconciliationSliceCount,
  reconciliationSliceForBucket,
  reconciliationBucketRange,
  RECONCILIATION_BUCKET_COUNT,
  simulateReconciliationCycle,
  buildReconciliationBatchSql,
  useIndexedReconciliationBuckets
} from './publishedFeedReconciliation.js';

describe('publishedFeedReconciliation progress', () => {
  it('paginates within a slice before advancing', () => {
    const rows = Array.from({ length: 1200 }, (_, i) => ({
      identity_key: `o:domain:host${String(i).padStart(5, '0')}.com`,
      id: i + 1,
      observable_type: 'domain'
    }));
    const batchSize = 500;
    let cursor = '';
    let slice = 0;
    let batches = 0;
    while (batches < 10) {
      const batch = rows.filter((r) => r.identity_key > cursor).slice(0, batchSize);
      const progress = nextReconciliationProgress({
        slice,
        sliceCount: 1,
        cursor,
        batchRows: batch,
        batchSize
      });
      batches += 1;
      if (!batch.length) break;
      assert.equal(progress.sliceAdvanced, batch.length < batchSize);
      if (progress.sliceAdvanced) break;
      assert.equal(progress.reconciliation_slice, 0);
      assert.ok(progress.reconciliation_cursor > cursor);
      cursor = progress.reconciliation_cursor;
    }
    assert.equal(batches, 3);
  });

  it('advances slice when exhausted', () => {
    const progress = nextReconciliationProgress({
      slice: 3,
      sliceCount: 64,
      cursor: 'z:last',
      batchRows: []
    });
    assert.equal(progress.reconciliation_slice, 4);
    assert.equal(progress.reconciliation_cursor, '');
    assert.equal(progress.sliceAdvanced, true);
  });
});

describe('publishedFeedReconciliation completeness', () => {
  it('visits every identity in a large synthetic projection (> slices × batch)', () => {
    const sliceCount = 16;
    const batchSize = 500;
    const total = sliceCount * batchSize + 137;
    const identities = Array.from({ length: total }, (_, i) => ({
      identity_key: `o:domain:item${String(i).padStart(6, '0')}.com`,
      partition_identity: `o:domain:item${i}.com`,
      reconciliation_bucket: i % RECONCILIATION_BUCKET_COUNT,
      id: i + 1
    }));
    const { visited, ticks } = simulateReconciliationCycle({
      identities,
      sliceCount,
      batchSize
    });
    assert.equal(visited.size, total);
    assert.ok(ticks >= Math.ceil(total / batchSize));
    assert.ok(ticks < total * 2);
  });

  it('resumes after crash mid-slice without skipping rows', () => {
    const sliceCount = 4;
    const batchSize = 100;
    const identities = Array.from({ length: 450 }, (_, i) => ({
      identity_key: `k${String(i).padStart(5, '0')}`,
      partition_identity: `o:url:item${i}.example`,
      reconciliation_bucket: i % RECONCILIATION_BUCKET_COUNT,
      id: i + 1
    }));

    const bySlice = new Map();
    for (const row of identities) {
      const s = reconciliationSliceForBucket(row.reconciliation_bucket, sliceCount);
      if (!bySlice.has(s)) bySlice.set(s, []);
      bySlice.get(s).push(row);
    }
    for (const list of bySlice.values()) {
      list.sort((a, b) => a.identity_key.localeCompare(b.identity_key));
    }

    let slice = 0;
    let cursor = '';
    const visited = new Set();
    let ticks = 0;
    const stopAfter = 3;

    while (ticks < stopAfter) {
      const list = bySlice.get(slice) || [];
      const batch = list.filter((r) => r.identity_key > cursor).slice(0, batchSize);
      for (const row of batch) visited.add(row.identity_key);
      const progress = nextReconciliationProgress({
        slice, sliceCount, cursor, batchRows: batch, batchSize
      });
      slice = progress.reconciliation_slice;
      cursor = progress.reconciliation_cursor;
      ticks += 1;
    }

    while (visited.size < identities.length && ticks < 10000) {
      const list = bySlice.get(slice) || [];
      const batch = list.filter((r) => r.identity_key > cursor).slice(0, batchSize);
      for (const row of batch) visited.add(row.identity_key);
      const progress = nextReconciliationProgress({
        slice, sliceCount, cursor, batchRows: batch, batchSize
      });
      slice = progress.reconciliation_slice;
      cursor = progress.reconciliation_cursor;
      ticks += 1;
    }

    assert.equal(visited.size, identities.length);
  });
});

describe('publishedFeedReconciliation defaults', () => {
  it('uses configured slice and batch sizes', () => {
    assert.ok(reconciliationSliceCount() >= 1);
    assert.ok(reconciliationBatchSize() >= 50);
  });

});

describe('runReconciliationSlice bucket_range', () => {
  it('returns bucket bounds when indexed reconciliation inspects rows', async () => {
    const prevRecon = process.env.PUBLISHED_FEED_RECONCILIATION_ENABLED;
    const prevSlide = process.env.PUBLISHED_FEED_SLIDING_WINDOW_INCREMENTAL_ENABLED;
    process.env.PUBLISHED_FEED_RECONCILIATION_ENABLED = 'true';
    process.env.PUBLISHED_FEED_SLIDING_WINDOW_INCREMENTAL_ENABLED = 'true';
    try {
      const { runReconciliationSlice } = await import('./publishedFeedReconciliation.js');
      const calls = [];
      const db = {
        query: async (sql, params) => {
          calls.push({ sql, params });
          if (sql.includes('UPDATE published_feeds')) {
            return { rows: [{ projection_item_count: 0 }] };
          }
          if (sql.includes('FROM published_feed_items') && sql.includes('reconciliation_bucket')) {
            return {
              rows: [{
                id: 99,
                identity_key: 'o:sha256:abc',
                observable_type: 'sha256'
              }]
            };
          }
          return { rows: [] };
        }
      };
      const feed = {
        id: 25,
        reconciliation_slice: 0,
        reconciliation_cursor: '',
        projection_cutoff: new Date('2026-01-01T00:00:00Z')
      };
      const result = await runReconciliationSlice(db, feed, ['hash'], {
        cutoff: feed.projection_cutoff,
        candidateCutoff: new Date('2026-01-02T00:00:00Z')
      });
      assert.equal(result.inspected, 1);
      assert.deepEqual(result.bucket_range, { low: 0, high: 4 });
      const batchCall = calls.find((c) => String(c.sql).includes('reconciliation_bucket = ANY'));
      assert.ok(batchCall, 'must use bucket ANY predicate');
      assert.ok(!/reconciliation_bucket IS NULL/.test(batchCall.sql),
        'bucket SQL must not OR-in NULL buckets (blocks index)');
      // feed_id, snapshot_window, bucketList, batchSize — no slice ordinal param
      assert.equal(batchCall.params.length, 4);
    } finally {
      if (prevRecon === undefined) delete process.env.PUBLISHED_FEED_RECONCILIATION_ENABLED;
      else process.env.PUBLISHED_FEED_RECONCILIATION_ENABLED = prevRecon;
      if (prevSlide === undefined) delete process.env.PUBLISHED_FEED_SLIDING_WINDOW_INCREMENTAL_ENABLED;
      else process.env.PUBLISHED_FEED_SLIDING_WINDOW_INCREMENTAL_ENABLED = prevSlide;
    }
  });
});

describe('buildReconciliationBatchSql index shape', () => {
  it('emits bucket-only predicate without NULL OR when useBuckets', () => {
    const sql = buildReconciliationBatchSql({ includeCursor: false, useBuckets: true });
    assert.ok(sql.includes('reconciliation_bucket = ANY($3::smallint[])'));
    assert.ok(!sql.includes('reconciliation_bucket IS NULL'));
    assert.ok(useIndexedReconciliationBuckets());
  });
});
