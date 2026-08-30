#!/usr/bin/env node
/**
 * Bootstrap published_feed_items projection for a feed (bounded full scan).
 * Usage: node scripts/bootstrap-published-feed-projection.js --feed-id=12
 */
import '../lib/ensure-db-password.js';
import pg from 'pg';
import {
  generateFeedArtifact
} from '../lib/publishedFeedStreamGenerator.js';
import {
  PROJECTION_STATUS,
  setFeedProjectionState,
  clearFeedProjection,
  isIncrementalEnabledForFeed
} from '../lib/publishedFeedProjection.js';
import { captureCutoffNow } from '../lib/publishedFeedIncremental.js';
import { resolveFeedIocTypes } from '../lib/feedPublisherService.js';
import process from 'node:process';

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

function parseFeedId(argv) {
  for (const arg of argv) {
    const m = String(arg).match(/^--feed-id=(\d+)$/);
    if (m) return Number(m[1]);
  }
  const idx = argv.indexOf('--feed-id');
  if (idx >= 0 && argv[idx + 1]) return Number(argv[idx + 1]);
  return null;
}

async function main() {
  const feedId = parseFeedId(process.argv.slice(2));
  if (!feedId) {
    console.error('Usage: bootstrap-published-feed-projection.js --feed-id=<id>');
    process.exit(2);
  }
  const client = await pool.connect();
  try {
    const { rows } = await client.query('SELECT * FROM published_feeds WHERE id = $1', [feedId]);
    if (!rows.length) throw new Error(`Feed ${feedId} not found`);
    const feed = rows[0];
    if (!isIncrementalEnabledForFeed(feedId)) {
      console.warn(`Feed ${feedId} is not in incremental allowlist; bootstrap will still populate projection.`);
    }
    const W = captureCutoffNow();
    await setFeedProjectionState(client, feedId, {
      projection_status: PROJECTION_STATUS.BOOTSTRAPPING,
      projection_pending_cutoff: W
    });
    await clearFeedProjection(client, feedId);
    const formatTypes = resolveFeedIocTypes(feed);
    const art = await generateFeedArtifact(client, feed, 'all', {
      formatTypes,
      populateProjection: true,
      projectionWindow: 'all'
    });
    await setFeedProjectionState(client, feedId, {
      projection_status: PROJECTION_STATUS.READY,
      projection_built_at: new Date(),
      projection_cutoff: W,
      projection_pending_cutoff: null
    });
    console.log(JSON.stringify({
      feed_id: feedId,
      item_count: art.itemCount,
      projection_status: PROJECTION_STATUS.READY
    }, null, 2));
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
