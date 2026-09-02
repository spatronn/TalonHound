import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveExpectedProjectionItemCount,
  countProjectionItemsInChunks,
  canReuseUnaffectedChunks
} from './publishedFeedWindowEligibility.js';

describe('resolveExpectedProjectionItemCount', () => {
  it('uses durable projection_item_count without COUNT for window=all', async () => {
    let counted = 0;
    const db = {
      async query(sql) {
        if (String(sql).includes('COUNT(*)')) {
          counted += 1;
          return { rows: [{ n: 999 }] };
        }
        return { rows: [] };
      }
    };
    const feed = { id: 11, projection_item_count: 1360924 };
    const n = await resolveExpectedProjectionItemCount(db, feed, 'all', new Date(), { verify: false });
    assert.equal(n, 1360924);
    assert.equal(counted, 0);
  });

  it('recounts and stores when verify=true', async () => {
    const updates = [];
    const db = {
      async query(sql, params) {
        if (String(sql).includes('COUNT(*)')) return { rows: [{ n: '42' }] };
        if (String(sql).includes('UPDATE published_feeds')) {
          updates.push(params);
          return { rows: [] };
        }
        return { rows: [] };
      }
    };
    const feed = { id: 11, projection_item_count: 10 };
    const n = await resolveExpectedProjectionItemCount(db, feed, 'all', null, { verify: true });
    assert.equal(n, 42);
    assert.equal(feed.projection_item_count, 42);
    assert.ok(updates.some((p) => p.includes(42)));
  });
});

describe('canReuseUnaffectedChunks with expectedTotal', () => {
  it('counts only affected chunks then subtracts from expectedTotal', async () => {
    const sqls = [];
    const db = {
      async query(sql) {
        sqls.push(String(sql).replace(/\s+/g, ' '));
        if (String(sql).includes('SUM(c.item_count)')) return { rows: [{ n: 90 }] };
        if (String(sql).includes('COUNT(*)') && String(sql).includes('chunk_key = ANY')) {
          return { rows: [{ n: 10 }] };
        }
        if (String(sql).includes('COUNT(*)')) return { rows: [{ n: 100 }] };
        return { rows: [] };
      }
    };
    const reuse = await canReuseUnaffectedChunks(db, {
      feedId: 11,
      artifactWindow: 'all',
      asOf: new Date(),
      parentGenerationId: 'gen-1',
      format: 'txt',
      excludeChunkKeys: [3, 7],
      expectedTotal: 100
    });
    assert.equal(reuse.reusable, true);
    assert.equal(reuse.projection_reused, 90);
    assert.ok(!sqls.some((s) => s.includes('NOT (chunk_key = ANY')),
      'must not scan the complement of affected chunks');
    assert.equal(await countProjectionItemsInChunks(db, 11, 'all', null, [1]), 10);
  });
});
