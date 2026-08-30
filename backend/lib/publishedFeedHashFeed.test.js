import test from 'node:test';
import assert from 'node:assert/strict';
import { choosePublishedFeedChunkCount } from './publishedFeedChunks.js';
import { decideRefreshMode, PROJECTION_STATUS } from './publishedFeedIncremental.js';
import { shouldCanonicalizePublishedHashFeed } from './feedPublisherService.js';

const HASH_FEED = {
  id: 25,
  ioc_types: ['hash'],
  time_window: 'all',
  max_items: null,
  projection_status: PROJECTION_STATUS.READY,
  chunk_count: 256,
  chunk_backfill_status: 'ready',
  filter_mode: 'basic'
};

test('hash feed at ~1.12M items chooses 256 chunks (~4.4k rows/chunk)', () => {
  assert.equal(choosePublishedFeedChunkCount(1_121_874), 256);
  assert.equal(Math.ceil(1_121_874 / 256), 4383);
});

test('hash feed with ready projection uses incremental refresh when enabled', () => {
  assert.equal(
    decideRefreshMode(HASH_FEED, {
      incrementalEnabled: true,
      streamingEnabled: true,
      snapshotWindow: 'all'
    }),
    'incremental'
  );
});

test('hash feed without projection bootstraps when incremental enabled', () => {
  assert.equal(
    decideRefreshMode(
      { ...HASH_FEED, projection_status: PROJECTION_STATUS.ABSENT },
      { incrementalEnabled: true, streamingEnabled: true }
    ),
    'bootstrap'
  );
});

test('hash basic feed canonicalizes file artifacts when read is enabled', () => {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = 'true';
  try {
    assert.equal(shouldCanonicalizePublishedHashFeed({ ioc_types: ['hash'], filter_mode: 'basic' }), true);
    assert.equal(shouldCanonicalizePublishedHashFeed({ ioc_types: ['domain'], filter_mode: 'basic' }), false);
  } finally {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  }
});
