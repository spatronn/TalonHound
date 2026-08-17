import test from 'node:test';
import assert from 'node:assert/strict';
import {
  pinPublishedFeedGeneration,
  isPublishedFeedGenerationPinned,
  cleanupPublishedFeedChunkGenerations,
  buildAndActivateChunkGeneration
} from './publishedFeedChunkGeneration.js';

test('in-process generation pins prevent GC of the active stream', () => {
  const id = 'gen-pin-test';
  assert.equal(isPublishedFeedGenerationPinned(id), false);
  const release = pinPublishedFeedGeneration(id);
  assert.equal(isPublishedFeedGenerationPinned(id), true);
  const nested = pinPublishedFeedGeneration(id);
  assert.equal(isPublishedFeedGenerationPinned(id), true);
  nested();
  assert.equal(isPublishedFeedGenerationPinned(id), true);
  release();
  assert.equal(isPublishedFeedGenerationPinned(id), false);
});

test('GC skips pinned generations and can collect unpinned superseded ones', async () => {
  const release = pinPublishedFeedGeneration('pinned');
  const seen = [];
  const pool = {
    async query(sql) {
      seen.push(['pool', String(sql).slice(0, 40)]);
      if (String(sql).includes('FROM published_feed_generations')) {
        return {
          rows: [
            { id: 'pinned', feed_id: 11 },
            { id: 'old', feed_id: 11 }
          ]
        };
      }
      throw new Error(`unexpected pool sql: ${String(sql).slice(0, 80)}`);
    },
    async connect() {
      return {
        async query(sql) {
          seen.push(['client', String(sql).slice(0, 40)]);
          if (String(sql).includes('pg_try_advisory_lock')) return { rows: [{ ok: true }] };
          if (String(sql).includes('pg_advisory_unlock')) return { rows: [] };
          if (String(sql) === 'BEGIN' || String(sql) === 'COMMIT' || String(sql) === 'ROLLBACK') return { rows: [] };
          if (String(sql).includes('SELECT recency_head_path')) return { rows: [] };
          if (String(sql).includes('DELETE FROM published_feed_generations')) {
            return { rows: [{ id: 'old' }], rowCount: 1 };
          }
          if (String(sql).includes('DELETE FROM published_feed_chunks')) {
            return { rows: [], rowCount: 0 };
          }
          throw new Error(`unexpected client sql: ${String(sql).slice(0, 80)}`);
        },
        release() {}
      };
    }
  };
  const result = await cleanupPublishedFeedChunkGenerations(pool, { retentionMinutes: 1 });
  release();
  assert.equal(result.generations, 1);
  assert.equal(result.chunks, 0);
});

function createActivationRecorder({ parent = null } = {}) {
  const statements = [];
  return {
    statements,
    cutoffMoved: false,
    activePointerMoved: false,
    async query(sql, params = []) {
      const text = String(sql);
      statements.push(text.replace(/\s+/g, ' ').trim());
      if (text.includes('FROM published_feed_active_generations')) {
        return parent
          ? {
            rows: [{
              id: parent.id,
              item_count: parent.item_count,
              chunk_count: parent.chunk_count,
              format: 'json'
            }]
          }
          : { rows: [] };
      }
      if (text.includes('INSERT INTO published_feed_chunks')) {
        return { rows: [{ id: 9001 }] };
      }
      if (text.includes('FROM published_feed_generation_chunks gc') && text.includes('JOIN published_feed_chunks')) {
        return {
          rows: [{
            content_hash: 'ab'.repeat(32),
            byte_length: 12,
            item_count: 2
          }]
        };
      }
      if (text.includes('INSERT INTO published_feed_active_generations')) {
        this.activePointerMoved = true;
        return { rows: [] };
      }
      if (text.includes('UPDATE published_feeds') && text.includes('projection_cutoff')) {
        this.cutoffMoved = true;
        return { rows: [] };
      }
      return { rows: [] };
    }
  };
}

const crashFeed = {
  id: 77,
  name: 'Crash Feed',
  slug: 'crash-feed',
  formats: ['json'],
  chunk_count: 64,
  chunk_algo_version: 1,
  chunk_backfill_status: 'ready'
};

async function fakeGenerateChunks() {
  return {
    chunks: [{
      feed_id: 77,
      snapshot_window: 'all',
      chunk_algo_version: 1,
      chunk_count: 64,
      chunk_key: 0,
      format: 'json',
      serializer_version: 1,
      content_hash: 'ab'.repeat(32),
      byte_length: 12,
      item_count: 2,
      storage_path: 'chunks/feed-77/all/v1/json/0-ab.chunk',
      physical_bytes_written: 12
    }],
    rowsRead: 2,
    physicalBytesWritten: 12
  };
}

const activationOpts = {
  window: 'all',
  iocTypeKey: 'domain',
  configHash: 'cfg',
  candidateCutoff: new Date('2026-08-17T12:00:00.000Z'),
  affectedChunkKeys: [0],
  expectedItemCount: 2,
  generateChunks: fakeGenerateChunks
};

for (const stage of [
  'after_generation_insert',
  'after_chunks',
  'after_manifest',
  'before_activation',
  'during_activation'
]) {
  test(`failure ${stage} does not advance the committed publication cutoff`, async () => {
    const db = createActivationRecorder();
    await assert.rejects(
      () => buildAndActivateChunkGeneration(db, crashFeed, { ...activationOpts, failAt: stage }),
      /injected generation failure/
    );
    assert.equal(db.cutoffMoved, false);
    if (stage === 'during_activation') {
      assert.equal(db.activePointerMoved, true);
    } else {
      assert.equal(db.activePointerMoved, false);
    }
  });
}

test('failure after activation leaves the new cutoff and active pointer in place', async () => {
  const db = createActivationRecorder();
  await assert.rejects(
    () => buildAndActivateChunkGeneration(db, crashFeed, { ...activationOpts, failAt: 'after_activation' }),
    /injected generation failure/
  );
  assert.equal(db.cutoffMoved, true);
  assert.equal(db.activePointerMoved, true);
});

