import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  BASE_PROJECTION_WINDOW,
  SLIDING_WINDOWS,
  isRecencyVisibleInWindow,
  computeAffectedChunksByWindow,
  windowNeedsArtifactRefresh,
  projectionWindowFilter,
  canReuseUnaffectedChunks,
  countProjectionItemsOutsideChunks,
  sumGenerationChunkItemsOutside
} from './publishedFeedWindowEligibility.js';

describe('publishedFeedWindowEligibility', () => {
  const at = new Date('2026-08-28T12:00:00.000Z');

  it('uses single base projection window', () => {
    assert.equal(BASE_PROJECTION_WINDOW, 'all');
    assert.deepEqual(SLIDING_WINDOWS, ['1d', '3d', '7d']);
  });

  it('matches sliding-window visibility semantics (inclusive lower bound)', () => {
    const recent = new Date('2026-08-27T12:00:00.000Z');
    const outside1d = new Date('2026-08-20T12:00:00.000Z');
    const inside7d = new Date('2026-08-22T12:00:00.000Z');
    assert.equal(isRecencyVisibleInWindow(recent, '1d', at), true);
    assert.equal(isRecencyVisibleInWindow(outside1d, '1d', at), false);
    assert.equal(isRecencyVisibleInWindow(inside7d, '7d', at), true);
    assert.equal(isRecencyVisibleInWindow(recent, 'all', at), true);
  });

  it('builds projection window filter SQL for sliding windows only', () => {
    assert.deepEqual(projectionWindowFilter('all', 3), { sql: '', params: [] });
    const f = projectionWindowFilter('7d', 3);
    assert.match(f.sql, /recency_ts >= NOW\(\) - \$3::interval/);
    assert.deepEqual(f.params, ['7 days']);
  });

  it('freezes sliding-window filter to a generation asOf bound', () => {
    const asOf = new Date('2026-08-28T12:00:00.000Z');
    const f = projectionWindowFilter('1d', 3, asOf);
    assert.match(f.sql, /recency_ts >= \$3::timestamptz - \$4::interval/);
    assert.deepEqual(f.params, ['2026-08-28T12:00:00.000Z', '1 day']);
    assert.deepEqual(projectionWindowFilter('all', 3, asOf), { sql: '', params: [] });
  });

  it('computes per-window dirty chunks from boundaries and touched rows', () => {
    const prev = new Date('2026-08-20T12:00:00.000Z');
    const now = new Date('2026-08-27T12:00:00.000Z');
    const delta = { affectedChunkKeys: [1, 2], artifactDirty: true };
    const boundaries = {
      '1d': [{ chunk_key: 9, recency_ts: prev }],
      '3d': [],
      '7d': []
    };
    const touched = [{
      chunk_key: 4,
      recency_ts: now,
      prev_recency_ts: prev
    }];
    const byWindow = computeAffectedChunksByWindow(delta, boundaries, touched, at);
    assert.deepEqual(byWindow.all, [1, 2]);
    assert.ok(byWindow['1d'].includes(9));
    assert.ok(byWindow['7d'].includes(4));
  });

  it('decides per-window artifact refresh from boundaries vs projection delta', () => {
    const delta = { artifactDirty: false };
    const boundaries = { '1d': [{ chunk_key: 1 }], '3d': [], '7d': [] };
    const chunks = { all: [], '1d': [1], '3d': [], '7d': [] };
    assert.equal(windowNeedsArtifactRefresh('all', delta, boundaries, chunks), false);
    assert.equal(windowNeedsArtifactRefresh('1d', delta, boundaries, chunks), true);
    assert.equal(
      windowNeedsArtifactRefresh('all', { artifactDirty: true }, boundaries, chunks),
      true
    );
  });

  it('rejects chunk reuse when unaffected parent chunks underfill projection', async () => {
    const asOf = new Date('2026-08-28T12:00:00.000Z');
    // Projection has 100 items in reused keys; parent only stored 5 for those keys.
    const db = {
      async query(sql, params = []) {
        if (String(sql).includes('FROM published_feed_items')) {
          assert.deepEqual(params[params.length - 1], [7, 8]);
          return { rows: [{ n: 100 }] };
        }
        if (String(sql).includes('FROM published_feed_generation_chunks')) {
          assert.equal(params[0], 'parent-gen');
          assert.equal(params[1], 'txt');
          assert.deepEqual(params[2], [7, 8]);
          return { rows: [{ n: 5 }] };
        }
        throw new Error(`unexpected sql: ${String(sql).slice(0, 80)}`);
      }
    };
    const reuse = await canReuseUnaffectedChunks(db, {
      feedId: 11,
      artifactWindow: '1d',
      asOf,
      parentGenerationId: 'parent-gen',
      format: 'txt',
      excludeChunkKeys: [7, 8]
    });
    assert.equal(reuse.reusable, false);
    assert.equal(reuse.reason, 'reused_chunk_membership_drift');
    assert.equal(reuse.projection_reused, 100);
    assert.equal(reuse.parent_reused, 5);
  });

  it('allows chunk reuse when unaffected membership matches parent', async () => {
    const db = {
      async query(sql) {
        if (String(sql).includes('FROM published_feed_items')) return { rows: [{ n: 42 }] };
        if (String(sql).includes('FROM published_feed_generation_chunks')) {
          return { rows: [{ n: 42 }] };
        }
        throw new Error('unexpected');
      }
    };
    const reuse = await canReuseUnaffectedChunks(db, {
      feedId: 12,
      artifactWindow: '1d',
      asOf: new Date('2026-08-28T12:00:00.000Z'),
      parentGenerationId: 'ok-parent',
      excludeChunkKeys: [1]
    });
    assert.equal(reuse.reusable, true);
    assert.equal(reuse.reason, null);
  });

  it('countProjectionItemsOutsideChunks binds exclude keys after window filter params', async () => {
    const asOf = new Date('2026-08-28T12:00:00.000Z');
    let seen;
    const db = {
      async query(sql, params) {
        seen = { sql, params };
        return { rows: [{ n: 0 }] };
      }
    };
    await countProjectionItemsOutsideChunks(db, 11, '1d', asOf, [3, 4]);
    assert.match(seen.sql, /NOT \(chunk_key = ANY\(\$5::integer\[\]\)\)/);
    assert.deepEqual(seen.params, [11, 'all', '2026-08-28T12:00:00.000Z', '1 day', [3, 4]]);
  });

  it('sumGenerationChunkItemsOutside excludes dirty keys', async () => {
    let seen;
    const db = {
      async query(sql, params) {
        seen = { sql, params };
        return { rows: [{ n: 9 }] };
      }
    };
    const n = await sumGenerationChunkItemsOutside(db, 'gen-1', 'txt', [1, 2]);
    assert.equal(n, 9);
    assert.deepEqual(seen.params, ['gen-1', 'txt', [1, 2]]);
  });
});
