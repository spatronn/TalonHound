import '../lib/ensure-db-password.js';
import pg from 'pg';
import {
  filtersHash,
  normalizeFeedConfig,
  resolveFeedIocTypes
} from '../lib/feedPublisherService.js';
import { feedIocTypesKey } from '../lib/feedFormatter.js';
import { buildAndActivateChunkGeneration } from '../lib/publishedFeedChunkGeneration.js';

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

function arg(name, fallback = null) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

async function main() {
  const feedId = Number(arg('feed-id'));
  const window = String(arg('window', 'all')).toLowerCase();
  if (!Number.isInteger(feedId) || feedId <= 0) throw new Error('--feed-id is required');
  if (window !== 'all') throw new Error('Chunk bootstrap currently supports only the all window');

  const client = await pool.connect();
  let locked = false;
  try {
    const lock = await client.query(
      'SELECT pg_try_advisory_lock($1::int, $2::int) AS ok',
      [874290151, feedId]
    );
    locked = Boolean(lock.rows[0]?.ok);
    if (!locked) {
      const stale = await client.query(
        `SELECT pid, granted, EXTRACT(EPOCH FROM (now() - COALESCE(query_start, backend_start)))::int AS age_s
         FROM pg_locks l
         JOIN pg_stat_activity a ON a.pid = l.pid
         WHERE l.locktype = 'advisory'
           AND l.classid = $1 AND l.objid = $2`,
        [874290151, feedId]
      );
      const details = stale.rows.map((row) =>
        `pid=${row.pid} granted=${row.granted} age_s=${row.age_s}`
      ).join('; ');
      throw new Error(`Published Feed generation lock is already held (${details || 'no lock rows'})`);
    }

    const { rows } = await client.query('SELECT * FROM published_feeds WHERE id = $1', [feedId]);
    if (!rows.length) throw new Error('Feed not found');
    const feed = normalizeFeedConfig(rows[0]);
    if (String(feed.chunk_backfill_status || '') !== 'ready') {
      throw new Error('Chunk backfill must be ready before bootstrap');
    }
    const count = await client.query(
      `SELECT COUNT(*)::bigint AS n
       FROM published_feed_items
       WHERE feed_id = $1 AND snapshot_window = $2`,
      [feedId, window]
    );
    const itemCount = Number(count.rows[0]?.n || 0);
    const iocTypeKey = feedIocTypesKey(resolveFeedIocTypes(feed));
    const cutoff = new Date();

    await client.query('BEGIN');
    try {
      const result = await buildAndActivateChunkGeneration(client, feed, {
        window,
        iocTypeKey,
        configHash: filtersHash(feed, window),
        candidateCutoff: cutoff,
        affectedChunkKeys: null,
        expectedItemCount: itemCount,
        fullRebuildReason: 'operator_bootstrap',
        metrics: { semantic_changes: itemCount }
      });
      await client.query('COMMIT');
      console.log(JSON.stringify({ ok: true, ...result }));
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    }
  } finally {
    if (locked) {
      await client.query(
        'SELECT pg_advisory_unlock($1::int, $2::int)',
        [874290151, feedId]
      ).catch(() => {});
    }
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[published-feed-chunks] bootstrap failed', err?.message || err);
  process.exitCode = 1;
});
