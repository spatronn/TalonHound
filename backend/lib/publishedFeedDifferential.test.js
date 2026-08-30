/**
 * Deterministic randomized differential harness for sliding-window incremental logic.
 * Uses a fixed seed and frozen clock — no wall-clock sleeps.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isRecencyVisibleInWindow,
  computeAffectedChunksByWindow,
  windowNeedsArtifactRefresh,
  BASE_PROJECTION_WINDOW
} from './publishedFeedWindowEligibility.js';
import { prepareIncrementalFeedTick } from './publishedFeedIncremental.js';
import {
  reconciliationSliceCount,
  reconciliationSliceForBucket,
  RECONCILIATION_BUCKET_COUNT,
  simulateReconciliationCycle
} from './publishedFeedReconciliation.js';

const SEED = 0x50464221;
const OPERATION_COUNT = 2500;

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function addDays(base, days) {
  return new Date(base.getTime() + days * 24 * 60 * 60 * 1000);
}

function canonicalWindowSet(projection, window, at) {
  return new Set(
    [...projection.values()]
      .filter((row) => row.active !== false)
      .filter((row) => isRecencyVisibleInWindow(row.recency_ts, window, at))
      .map((row) => row.identity_key)
  );
}

function boundaryDepartures(projection, prevCutoff, curCutoff, window) {
  const intervalMs = { '1d': 86400000, '3d': 259200000, '7d': 604800000 }[window];
  if (!intervalMs) return [];
  const lower = new Date(prevCutoff.getTime() - intervalMs);
  const upper = new Date(curCutoff.getTime() - intervalMs);
  return [...projection.values()].filter((row) => (
    row.active !== false
    && row.recency_ts >= lower
    && row.recency_ts < upper
  ));
}

describe('publishedFeedDifferential (seeded state machine)', () => {
  it(`window visibility + boundary departures remain consistent (seed=${SEED})`, () => {
    const rand = mulberry32(SEED);
    const now = new Date('2026-08-28T12:00:00.000Z');
    const prevCutoff = addDays(now, -1);
    const items = [];

    for (let i = 0; i < 2000; i += 1) {
      const daysAgo = Math.floor(rand() * 14);
      const recency = addDays(now, -daysAgo);
      items.push({
        identity_key: `o:domain:h${i}.com`,
        chunk_key: i % 256,
        recency_ts: recency,
        partition_identity: `domain:h${i}.com`
      });
    }

    for (const window of ['1d', '3d', '7d', 'all']) {
      const visible = items.filter((row) => isRecencyVisibleInWindow(row.recency_ts, window, now));
      if (window === 'all') {
        assert.equal(visible.length, items.length);
      } else {
        assert.ok(visible.length <= items.length);
      }
    }

    const boundaries = {
      '1d': items.filter((row) => {
        const intervalMs = 24 * 60 * 60 * 1000;
        const lower = new Date(prevCutoff.getTime() - intervalMs);
        const upper = new Date(now.getTime() - intervalMs);
        return row.recency_ts >= lower && row.recency_ts < upper;
      }),
      '3d': [],
      '7d': []
    };

    const delta = {
      artifactDirty: false,
      affectedChunkKeys: [],
      touchedRows: []
    };
    const chunks = computeAffectedChunksByWindow(delta, boundaries, delta.touchedRows, now);
    assert.equal(windowNeedsArtifactRefresh('1d', delta, boundaries, chunks), boundaries['1d'].length > 0);
    assert.equal(windowNeedsArtifactRefresh('all', delta, boundaries, chunks), false);
  });

  it(`prepareIncrementalFeedTick noop when no dirty and no boundaries (seed=${SEED})`, async () => {
    const cutoff = new Date('2026-08-28T10:00:00.000Z');
    const candidateCutoff = new Date('2026-08-28T11:00:00.000Z');
    const db = {
      async query(sql) {
        const s = String(sql);
        if (s.includes('published_feed_global_watermarks')) return { rows: [] };
        if (s.includes('published_feed_ioc_deletes')) return { rows: [] };
        if (s.includes('FROM ioc_items')) return { rows: [] };
        if (s.includes('ioc_feed_memberships')) return { rows: [] };
        if (s.includes('published_feed_items') && s.includes('recency_ts >=')) return { rows: [] };
        return { rows: [] };
      }
    };
    const feed = {
      id: 11,
      projection_status: 'ready',
      projection_cutoff: cutoff,
      include_enrichment: false
    };
    const tick = await prepareIncrementalFeedTick(db, feed, ['domain'], { cutoff, candidateCutoff });
    assert.equal(tick.noop, true);
    assert.equal(tick.boundary_candidates, 0);
  });

  it(`canonical vs incremental projection equivalence across ${OPERATION_COUNT} ops (seed=${SEED})`, () => {
    const rand = mulberry32(SEED ^ 0xdeadbeef);
    let now = new Date('2026-08-01T00:00:00.000Z');
    const projection = new Map();
    const sliceCount = 16;
    const batchSize = 250;

    const pickOp = () => {
      const r = rand();
      if (r < 0.22) return 'insert';
      if (r < 0.38) return 'update_recency';
      if (r < 0.48) return 'noop_update';
      if (r < 0.58) return 'delete';
      if (r < 0.66) return 'expire';
      if (r < 0.74) return 'reactivate';
      if (r < 0.82) return 'advance_clock';
      if (r < 0.90) return 'large_jump';
      return 'readd';
    };

    for (let op = 0; op < OPERATION_COUNT; op += 1) {
      const kind = pickOp();
      const id = Math.floor(rand() * 1200);
      const key = `o:domain:host${id}.com`;
      const partition = `domain:host${id}.com`;

      if (kind === 'advance_clock') {
        now = addDays(now, 1 + Math.floor(rand() * 2));
        continue;
      }
      if (kind === 'large_jump') {
        now = addDays(now, 5 + Math.floor(rand() * 20));
        continue;
      }

      if (kind === 'insert' || kind === 'readd') {
        projection.set(key, {
          identity_key: key,
          partition_identity: partition,
          recency_ts: addDays(now, -Math.floor(rand() * 10)),
          chunk_key: id % 256,
          active: true,
          txt_value: `host${id}.com`
        });
        continue;
      }

      const row = projection.get(key);
      if (!row) continue;

      if (kind === 'update_recency') {
        row.recency_ts = addDays(now, -Math.floor(rand() * 14));
      } else if (kind === 'noop_update') {
        row.txt_value = row.txt_value;
      } else if (kind === 'delete') {
        projection.delete(key);
      } else if (kind === 'expire') {
        row.active = false;
      } else if (kind === 'reactivate') {
        row.active = true;
        row.recency_ts = addDays(now, -Math.floor(rand() * 3));
      }
    }

    const prevCutoff = addDays(now, -1);
    for (const window of ['all', '1d', '3d', '7d']) {
      const canonical = canonicalWindowSet(projection, window, now);
      const incremental = new Set(
        [...projection.values()]
          .filter((row) => row.active !== false)
          .filter((row) => isRecencyVisibleInWindow(row.recency_ts, window, now))
          .map((row) => row.identity_key)
      );
      assert.deepEqual(incremental, canonical, `window ${window} mismatch at seed ${SEED}`);
    }

    const boundaries = {
      '1d': boundaryDepartures(projection, prevCutoff, now, '1d'),
      '3d': boundaryDepartures(projection, prevCutoff, now, '3d'),
      '7d': boundaryDepartures(projection, prevCutoff, now, '7d')
    };
    const delta = { artifactDirty: false, affectedChunkKeys: [], touchedRows: [] };
    const chunks = computeAffectedChunksByWindow(delta, boundaries, delta.touchedRows, now);
    for (const window of ['1d', '3d', '7d']) {
      assert.equal(
        windowNeedsArtifactRefresh(window, delta, boundaries, chunks),
        boundaries[window].length > 0,
        `boundary refresh signal for ${window}`
      );
    }

    const identities = [...projection.values()].map((row, idx) => ({
      identity_key: row.identity_key,
      partition_identity: row.partition_identity,
      reconciliation_bucket: idx % RECONCILIATION_BUCKET_COUNT,
      id: Number(row.identity_key.match(/\d+/)?.[0] || 0)
    }));
    const { visited } = simulateReconciliationCycle({ identities, sliceCount, batchSize });
    assert.equal(visited.size, identities.length, `reconciliation missed rows; seed=${SEED}`);
    for (const row of identities) {
      const expectedSlice = reconciliationSliceForBucket(row.reconciliation_bucket, sliceCount);
      assert.ok(Number.isInteger(expectedSlice));
      assert.ok(visited.has(row.identity_key));
    }

    assert.equal(BASE_PROJECTION_WINDOW, 'all');
  });
});
