import '../lib/ensure-db-password.js';
import pg from 'pg';
import {
  PUBLISHED_FEED_CHUNK_ALGO_VERSION,
  choosePublishedFeedChunkCount,
  partitionIdentityForProjectionRow,
  publishedFeedChunkKey
} from '../lib/publishedFeedChunks.js';

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

const feedId = Number(arg('feed-id'));
const windowName = String(arg('window', 'all'));
const batchSize = Math.max(100, Math.min(10000, Number(arg('batch-size', 5000)) || 5000));
const indexesOnly = process.argv.includes('--indexes-only');

function quoteIdent(value) {
  const v = String(value || '');
  if (!/^[a-z_][a-z0-9_]*$/i.test(v)) throw new Error(`Unsafe SQL identifier: ${v}`);
  return `"${v.replaceAll('"', '""')}"`;
}

async function createDirtyIndexes(client) {
  const { rows: partitions } = await client.query(
    `SELECT c.relname
     FROM pg_inherits i
     JOIN pg_class p ON p.oid = i.inhparent
     JOIN pg_class c ON c.oid = i.inhrelid
     WHERE p.relname = 'ioc_items'
     ORDER BY c.relname`
  );
  for (const row of partitions) {
    const table = quoteIdent(row.relname);
    const index = quoteIdent(`${row.relname}_pf_updated_at_idx`);
    // eslint-disable-next-line no-await-in-loop
    await client.query(
      `CREATE INDEX CONCURRENTLY IF NOT EXISTS ${index}
       ON ${table} (updated_at, id) WHERE updated_at IS NOT NULL`
    );
  }

  const statements = [
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_feed_memberships_pf_updated_at
       ON ioc_feed_memberships (updated_at, ioc_item_id)`,
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_enrichments_pf_updated_at
       ON ioc_enrichments (updated_at, ioc_value)`,
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_ip_enrichment_pf_updated_at
       ON ioc_ip_enrichment (updated_at, ip)`,
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_abuseipdb_enrichment_pf_updated_at
       ON ioc_abuseipdb_enrichment (updated_at, ip)`,
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_spamhaus_drop_enrichment_pf_updated_at
       ON ioc_spamhaus_drop_enrichment (updated_at, lookup_ip)`,
    `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_file_artifacts_pf_updated_at
       ON file_artifacts (updated_at, id)`
  ];
  for (const sql of statements) {
    // eslint-disable-next-line no-await-in-loop
    await client.query(sql);
  }
}

async function backfill(client) {
  if (!Number.isInteger(feedId) || feedId <= 0) {
    throw new Error('--feed-id is required');
  }
  const countQ = await client.query(
    `SELECT COUNT(*)::bigint AS n
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2`,
    [feedId, windowName]
  );
  const itemCount = Number(countQ.rows[0]?.n || 0);
  const chunkCount = choosePublishedFeedChunkCount(itemCount);
  await client.query(
    `UPDATE published_feeds
     SET chunk_count = $2, chunk_algo_version = $3, chunk_backfill_status = 'backfilling'
     WHERE id = $1`,
    [feedId, chunkCount, PUBLISHED_FEED_CHUNK_ALGO_VERSION]
  );

  let cursor = '';
  let updated = 0;
  try {
    for (;;) {
      // Resolve a stable File Artifact identity when one exists. Output identity remains
      // unchanged; only bucket membership uses the resolved artifact UUID.
      // eslint-disable-next-line no-await-in-loop
      const { rows } = await client.query(
        `SELECT p.identity_key, p.observable, p.observable_type, p.txt_value,
                a.resolved_artifact_id
         FROM published_feed_items p
         LEFT JOIN LATERAL (
           SELECT COALESCE(
                    CASE WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
                      THEN fa.merged_into_artifact_id ELSE fa.id END,
                    fa.id
                  )::text AS resolved_artifact_id
           FROM file_artifact_ioc_links fal
           JOIN file_artifacts fa ON fa.id = fal.artifact_id
           WHERE fal.ioc_item_id = p.ioc_item_id
             AND fal.ioc_observable_type = p.observable_type
             AND p.observable_type IN ('md5','sha1','sha256')
           ORDER BY fal.is_canonical_ioc DESC NULLS LAST, fa.id
           LIMIT 1
         ) a ON TRUE
         WHERE p.feed_id = $1 AND p.snapshot_window = $2
           AND p.identity_key > $3
         ORDER BY p.identity_key
         LIMIT $4`,
        [feedId, windowName, cursor, batchSize]
      );
      if (!rows.length) break;
      const identities = [];
      const partitionIdentities = [];
      const chunkKeys = [];
      for (const row of rows) {
        const partitionIdentity = partitionIdentityForProjectionRow(row);
        identities.push(row.identity_key);
        partitionIdentities.push(partitionIdentity);
        chunkKeys.push(publishedFeedChunkKey(partitionIdentity, chunkCount));
      }
      // eslint-disable-next-line no-await-in-loop
      await client.query('BEGIN');
      try {
        // eslint-disable-next-line no-await-in-loop
        await client.query(
          `UPDATE published_feed_items p
           SET partition_identity = x.partition_identity,
               chunk_key = x.chunk_key
           FROM unnest($1::text[], $2::text[], $3::integer[])
             AS x(identity_key, partition_identity, chunk_key)
           WHERE p.feed_id = $4 AND p.snapshot_window = $5
             AND p.identity_key = x.identity_key`,
          [identities, partitionIdentities, chunkKeys, feedId, windowName]
        );
        // eslint-disable-next-line no-await-in-loop
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      }
      cursor = rows.at(-1).identity_key;
      updated += rows.length;
      console.log(`[published-feed-chunks] feed=${feedId} backfilled=${updated}/${itemCount}`);
    }

    const verify = await client.query(
      `SELECT COUNT(*) FILTER (WHERE partition_identity IS NULL OR chunk_key IS NULL)::bigint AS missing,
              COUNT(*)::bigint AS total
       FROM published_feed_items
       WHERE feed_id = $1 AND snapshot_window = $2`,
      [feedId, windowName]
    );
    if (Number(verify.rows[0]?.missing || 0) !== 0) {
      throw new Error(`Chunk backfill incomplete: ${verify.rows[0].missing} rows missing`);
    }
    await client.query(
      `UPDATE published_feeds SET chunk_backfill_status = 'ready' WHERE id = $1`,
      [feedId]
    );
    return { feedId, itemCount, chunkCount, updated };
  } catch (err) {
    await client.query(
      `UPDATE published_feeds SET chunk_backfill_status = 'failed' WHERE id = $1`,
      [feedId]
    ).catch(() => {});
    throw err;
  }
}

async function main() {
  const client = await pool.connect();
  try {
    await createDirtyIndexes(client);
    await client.query(
      `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pf_items_feed_window_chunk_order
       ON published_feed_items (
         feed_id, snapshot_window, chunk_key,
         recency_ts DESC NULLS LAST, confidence_rank DESC, observable ASC
       )
       WHERE chunk_key IS NOT NULL`
    );
    if (!indexesOnly) {
      const result = await backfill(client);
      console.log(JSON.stringify({ ok: true, ...result }));
    } else {
      console.log(JSON.stringify({ ok: true, indexes_only: true }));
    }
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[published-feed-chunks] backfill failed', err?.message || err);
  process.exitCode = 1;
});
