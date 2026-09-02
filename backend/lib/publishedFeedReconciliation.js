// Rolling bounded reconciliation for Published Feed projections.
//
// Re-evaluates one hash slice of the feed keyspace per run without scanning the
// full IOC dataset every tick. PostgreSQL remains authoritative; Redis is not used.
//
// Each slice maps to a contiguous range of stable reconciliation_bucket values
// (0..255). Pagination uses reconciliation_cursor within the slice.

import {
  BASE_PROJECTION_WINDOW,
  isSlidingWindowIncrementalEnabled
} from './publishedFeedWindowEligibility.js';
import {
  applyIncrementalProjectionUpdate,
  captureCutoffNow
} from './publishedFeedIncremental.js';
import { setFeedProjectionState } from './publishedFeedProjection.js';
import { createServiceLogger } from './appLogger.js';

const log = createServiceLogger('published-feeds');

/** Fixed stable bucket count — independent of configurable slice_count. */
export const RECONCILIATION_BUCKET_COUNT = 256;

export function isPublishedFeedReconciliationEnabled() {
  const v = String(process.env.PUBLISHED_FEED_RECONCILIATION_ENABLED ?? 'true').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

export function reconciliationSliceCount() {
  const raw = Math.max(Number(process.env.PUBLISHED_FEED_RECONCILIATION_SLICES || 64), 1);
  if (RECONCILIATION_BUCKET_COUNT % raw !== 0) {
    return 64;
  }
  return raw;
}

export function reconciliationBatchSize() {
  return Math.max(Number(process.env.PUBLISHED_FEED_RECONCILIATION_BATCH || 500), 50);
}

export function reconciliationBucketsPerSlice(sliceCount = reconciliationSliceCount()) {
  const n = Number(sliceCount);
  if (!Number.isInteger(n) || n <= 0 || RECONCILIATION_BUCKET_COUNT % n !== 0) {
    throw new Error(`reconciliation slice_count must evenly divide ${RECONCILIATION_BUCKET_COUNT}`);
  }
  return RECONCILIATION_BUCKET_COUNT / n;
}

/** Inclusive low, exclusive high bucket range for a logical reconciliation slice. */
export function reconciliationBucketRange(slice, sliceCount = reconciliationSliceCount()) {
  const perSlice = reconciliationBucketsPerSlice(sliceCount);
  const count = Number(sliceCount);
  const s = ((Number(slice) % count) + count) % count;
  return { low: s * perSlice, high: (s + 1) * perSlice };
}

/** Bucket list for SQL = ANY($n::smallint[]) — helps planner use the recon index. */
export function reconciliationBucketList(slice, sliceCount = reconciliationSliceCount()) {
  const { low, high } = reconciliationBucketRange(slice, sliceCount);
  const list = [];
  for (let b = low; b < high; b += 1) list.push(b);
  return list;
}

export function reconciliationSliceForBucket(bucket, sliceCount = reconciliationSliceCount()) {
  const perSlice = reconciliationBucketsPerSlice(sliceCount);
  const b = Number(bucket);
  if (!Number.isFinite(b) || b < 0) return 0;
  return Math.floor(b / perSlice) % Number(sliceCount);
}

/**
 * Simulation helper when reconciliation_bucket is not precomputed.
 * Uses Java hash modulo 256 — NOT identical to PostgreSQL hashtext, but slice
 * grouping in simulateReconciliationCycle uses explicit reconciliation_bucket when set.
 */
export function reconciliationSliceForIdentity(partitionIdentity, sliceCount) {
  if (!partitionIdentity) return 0;
  let hash = 0;
  const s = String(partitionIdentity);
  for (let i = 0; i < s.length; i += 1) {
    hash = ((hash * 31) + s.charCodeAt(i)) | 0;
  }
  const bucket = Math.abs(hash) % RECONCILIATION_BUCKET_COUNT;
  return reconciliationSliceForBucket(bucket, sliceCount);
}

/**
 * Select the next reconciliation batch within the current slice using indexed buckets.
 * Bucket-only predicate (no OR null) so PostgreSQL can use idx_pf_items_feed_recon_bucket.
 */
export function buildReconciliationBatchSql({ includeCursor = true, useBuckets = true } = {}) {
  if (!useBuckets) {
    const cursorClause = includeCursor ? 'AND identity_key > $6' : '';
    return `
    SELECT DISTINCT ioc_item_id AS id, observable_type, identity_key
    FROM published_feed_items
    WHERE feed_id = $1
      AND snapshot_window = $2
      AND (
        (partition_identity IS NOT NULL AND (abs(hashtext(partition_identity)) % $3) = $4)
        OR ($4 = 0 AND partition_identity IS NULL)
      )
      ${cursorClause}
    ORDER BY identity_key
    LIMIT $5`;
  }
  const limitParam = includeCursor ? 5 : 4;
  const cursorParam = 4;
  const cursorClause = includeCursor ? `AND identity_key > $${cursorParam}` : '';
  return `
    SELECT ioc_item_id AS id, observable_type, identity_key
    FROM published_feed_items
    WHERE feed_id = $1
      AND snapshot_window = $2
      AND reconciliation_bucket = ANY($3::smallint[])
      ${cursorClause}
    ORDER BY identity_key
    LIMIT $${limitParam}`;
}

export function useIndexedReconciliationBuckets() {
  const v = String(process.env.PUBLISHED_FEED_RECONCILIATION_USE_BUCKETS ?? 'true').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

/**
 * Compute next durable reconciliation progress after processing a batch.
 */
export function nextReconciliationProgress({
  slice,
  sliceCount,
  cursor,
  batchRows,
  batchSize
}) {
  const count = Math.max(Number(sliceCount) || 1, 1);
  const currentSlice = Number(slice) % count;
  if (!batchRows?.length) {
    return {
      reconciliation_slice: (currentSlice + 1) % count,
      reconciliation_cursor: '',
      sliceAdvanced: true,
      sliceComplete: true
    };
  }
  const lastKey = String(batchRows[batchRows.length - 1].identity_key || '');
  const batchLimit = Math.max(Number(batchSize) || reconciliationBatchSize(), 1);
  if (batchRows.length < batchLimit) {
    return {
      reconciliation_slice: (currentSlice + 1) % count,
      reconciliation_cursor: '',
      sliceAdvanced: true,
      sliceComplete: true
    };
  }
  return {
    reconciliation_slice: currentSlice,
    reconciliation_cursor: lastKey,
    sliceAdvanced: false,
    sliceComplete: false
  };
}

/**
 * Run one reconciliation batch for a feed with a ready base projection.
 */
export async function runReconciliationSlice(db, feed, formatTypes, { cutoff, candidateCutoff } = {}) {
  if (!isPublishedFeedReconciliationEnabled() || !isSlidingWindowIncrementalEnabled()) {
    return { skipped: true, reason: 'disabled' };
  }
  const sliceCount = reconciliationSliceCount();
  const batchSize = reconciliationBatchSize();
  const slice = Number(feed.reconciliation_slice || 0) % sliceCount;
  const cursor = String(feed.reconciliation_cursor || '');
  const W = candidateCutoff || captureCutoffNow();
  const prevCutoff = cutoff || (feed.projection_cutoff ? new Date(feed.projection_cutoff) : null);
  const indexed = useIndexedReconciliationBuckets();
  const bucketList = reconciliationBucketList(slice, sliceCount);

  const sql = buildReconciliationBatchSql({ includeCursor: Boolean(cursor), useBuckets: indexed });
  const params = indexed
    ? (cursor
      ? [feed.id, BASE_PROJECTION_WINDOW, bucketList, cursor, batchSize]
      : [feed.id, BASE_PROJECTION_WINDOW, bucketList, batchSize])
    : (cursor
      ? [feed.id, BASE_PROJECTION_WINDOW, sliceCount, slice, batchSize, cursor]
      : [feed.id, BASE_PROJECTION_WINDOW, sliceCount, slice, batchSize]);

  const { rows } = await db.query(sql, params);
  const progress = nextReconciliationProgress({
    slice,
    sliceCount,
    cursor,
    batchRows: rows,
    batchSize
  });

  await setFeedProjectionState(db, feed.id, {
    reconciliation_slice: progress.reconciliation_slice,
    reconciliation_cursor: progress.reconciliation_cursor
  });

  if (!rows.length) {
    return {
      skipped: false,
      slice,
      inspected: 0,
      repaired: 0,
      sliceAdvanced: progress.sliceAdvanced,
      sliceComplete: progress.sliceComplete,
      cursor: progress.reconciliation_cursor,
      bucket_range: indexed ? { buckets: bucketList } : null
    };
  }

  if (indexed && rows.length > batchSize * 2) {
    log.warn('published feed reconciliation batch unexpectedly large', {
      feed_id: feed.id,
      slice,
      inspected: rows.length,
      batch_size: batchSize
    });
  }

  const dirty = {
    ids: rows.map((r) => Number(r.id)).filter(Number.isFinite),
    deletes: [],
    truncated: false,
    sources: { reconciliation: rows.length },
    forceFull: false,
    typeById: Object.fromEntries(
      rows.filter((r) => r.observable_type != null).map((r) => [Number(r.id), r.observable_type])
    )
  };

  const delta = await applyIncrementalProjectionUpdate(
    db,
    feed,
    BASE_PROJECTION_WINDOW,
    formatTypes,
    dirty
  );

  const repaired = (delta.entered || 0) + (delta.updated || 0) + (delta.removed || 0);
  log.info('published feed reconciliation slice', {
    feed_id: feed.id,
    slice,
    slice_count: sliceCount,
    bucket_low: indexed ? bucketList[0] : null,
    bucket_high: indexed ? (bucketList.at(-1) + 1) : null,
    inspected: rows.length,
    repaired,
    entered: delta.entered,
    updated: delta.updated,
    removed: delta.removed,
    cursor: progress.reconciliation_cursor || null,
    slice_advanced: progress.sliceAdvanced,
    slice_complete: progress.sliceComplete,
    indexed_buckets: indexed,
    watermark_to: W.toISOString(),
    watermark_from: prevCutoff ? prevCutoff.toISOString() : null
  });

  return {
    skipped: false,
    slice,
    inspected: rows.length,
    repaired,
    delta,
    sliceAdvanced: progress.sliceAdvanced,
    sliceComplete: progress.sliceComplete,
    cursor: progress.reconciliation_cursor,
    bucket_range: indexed ? { low: bucketList[0], high: bucketList.at(-1) + 1 } : null
  };
}

/**
 * In-memory simulation helper for completeness tests.
 */
export function simulateReconciliationCycle({
  identities,
  sliceCount = 8,
  batchSize = 500
}) {
  const bySlice = new Map();
  for (const row of identities) {
    const bucket = row.reconciliation_bucket != null
      ? Number(row.reconciliation_bucket)
      : (reconciliationSliceForIdentity(row.partition_identity, sliceCount) * reconciliationBucketsPerSlice(sliceCount));
    const s = reconciliationSliceForBucket(bucket, sliceCount);
    if (!bySlice.has(s)) bySlice.set(s, []);
    bySlice.get(s).push(row);
  }
  for (const list of bySlice.values()) {
    list.sort((a, b) => String(a.identity_key).localeCompare(String(b.identity_key)));
  }

  let reconciliation_slice = 0;
  let reconciliation_cursor = '';
  const visited = new Set();
  let ticks = 0;
  const maxTicks = Math.ceil(identities.length / Math.max(batchSize, 1)) * sliceCount * 3 + sliceCount;

  while (visited.size < identities.length && ticks < maxTicks) {
    ticks += 1;
    const slice = reconciliation_slice % sliceCount;
    const list = bySlice.get(slice) || [];
    const batch = list
      .filter((r) => String(r.identity_key) > reconciliation_cursor)
      .slice(0, batchSize);

    for (const row of batch) visited.add(row.identity_key);

    const progress = nextReconciliationProgress({
      slice,
      sliceCount,
      cursor: reconciliation_cursor,
      batchRows: batch,
      batchSize
    });
    reconciliation_slice = progress.reconciliation_slice;
    reconciliation_cursor = progress.reconciliation_cursor;
  }

  return { visited, ticks, reconciliation_slice, reconciliation_cursor };
}
