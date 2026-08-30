import '../lib/ensure-db-password.js';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import {
  filtersHash,
  normalizeFeedConfig,
  resolveFeedIocTypes,
  resolvePublishedFeedFormats
} from '../lib/feedPublisherService.js';
import { feedIocTypesKey } from '../lib/feedFormatter.js';
import {
  buildAndActivateChunkGeneration,
  getActiveChunkGeneration,
  getChunkGenerationFiles,
  streamChunkGeneration
} from '../lib/publishedFeedChunkGeneration.js';
import { getPublishedFeedArtifactConfig } from '../lib/publishedFeedArtifact/store.js';

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

function nowMs() {
  return Number(process.hrtime.bigint() / 1000000n);
}

async function withFeedLock(feedId, fn) {
  const client = await pool.connect();
  let locked = false;
  try {
    const lock = await client.query(
      'SELECT pg_try_advisory_lock($1::int, $2::int) AS ok',
      [874290151, feedId]
    );
    locked = Boolean(lock.rows[0]?.ok);
    if (!locked) throw new Error(`generation lock held for feed ${feedId}`);
    return await fn(client);
  } finally {
    if (locked) {
      await client.query(
        'SELECT pg_advisory_unlock($1::int, $2::int)',
        [874290151, feedId]
      ).catch(() => {});
    }
    client.release();
  }
}

async function loadFeed(client, feedId) {
  const { rows } = await client.query('SELECT * FROM published_feeds WHERE id = $1', [feedId]);
  if (!rows.length) throw new Error(`feed ${feedId} not found`);
  return normalizeFeedConfig(rows[0]);
}

async function projectionCount(client, feedId, window) {
  const { rows } = await client.query(
    `SELECT COUNT(*)::bigint AS n,
            COUNT(*) FILTER (WHERE chunk_key IS NULL)::bigint AS missing
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2`,
    [feedId, window]
  );
  return { n: Number(rows[0].n || 0), missing: Number(rows[0].missing || 0) };
}

async function pickAndMutate(client, feedId, window, n) {
  const { rows } = await client.query(
    `SELECT identity_key, chunk_key, txt_value, item_json
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2 AND chunk_key IS NOT NULL
     ORDER BY identity_key
     LIMIT $3`,
    [feedId, window, n]
  );
  const keys = [...new Set(rows.map((row) => Number(row.chunk_key)))];
  const identities = rows.map((row) => row.identity_key);
  const txt = rows.map((row) => `${row.txt_value}.bench`);
  const json = rows.map((row) => {
    const item = row.item_json && typeof row.item_json === 'object'
      ? row.item_json
      : (typeof row.item_json === 'string' ? JSON.parse(row.item_json) : { value: row.txt_value, type: 'domain' });
    return JSON.stringify({ ...item, value: `${item.value || row.txt_value}.bench` });
  });
  await client.query(
    `UPDATE published_feed_items p
     SET txt_value = x.txt_value,
         item_json = x.item_json::jsonb,
         content_fingerprint = md5(x.txt_value)
     FROM unnest($1::text[], $2::text[], $3::text[]) AS x(identity_key, txt_value, item_json)
     WHERE p.feed_id = $4 AND p.snapshot_window = $5 AND p.identity_key = x.identity_key`,
    [identities, txt, json, feedId, window]
  );
  return { keys, mutated: rows.length };
}

async function rowCountForChunks(client, feedId, window, keys) {
  if (!keys.length) return 0;
  const { rows } = await client.query(
    `SELECT COUNT(*)::bigint AS n
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2 AND chunk_key = ANY($3::integer[])`,
    [feedId, window, keys]
  );
  return Number(rows[0].n || 0);
}

async function runGeneration(client, feed, {
  window,
  affectedChunkKeys,
  expectedItemCount,
  reason
}) {
  const iocTypeKey = feedIocTypesKey(resolveFeedIocTypes(feed));
  const t0 = nowMs();
  await client.query('BEGIN');
  try {
    const result = await buildAndActivateChunkGeneration(client, feed, {
      window,
      iocTypeKey,
      configHash: filtersHash(feed, window),
      candidateCutoff: new Date(),
      affectedChunkKeys,
      expectedItemCount,
      fullRebuildReason: reason,
      metrics: { semantic_changes: affectedChunkKeys?.length || expectedItemCount }
    });
    await client.query('COMMIT');
    return { ...result, duration_ms: nowMs() - t0 };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  }
}

async function serveBench(client, feed, window, format) {
  const iocTypeKey = feedIocTypesKey(resolveFeedIocTypes(feed));
  const generation = await getActiveChunkGeneration(client, feed.id, iocTypeKey, window, format);
  if (!generation) throw new Error(`no active ${format} generation`);
  const chunks = await getChunkGenerationFiles(client, generation.id, format);
  let received = 0;
  const res = {
    destroyed: false,
    write(buf) {
      received += Buffer.byteLength(buf);
      return true;
    },
    end(buf) {
      if (buf) received += Buffer.byteLength(buf);
    },
    once() {},
    off() {}
  };
  const req = { aborted: false, once() {}, off() {} };
  const t0 = nowMs();
  await streamChunkGeneration(res, req, generation, chunks);
  return {
    format,
    generation_id: generation.id,
    logical_bytes: Number(generation.byte_length),
    received_bytes: received,
    etag: generation.strong_etag,
    chunk_count: chunks.length,
    duration_ms: nowMs() - t0,
    content_length_ok: received === Number(generation.byte_length)
  };
}

async function txtSetStats(client, feed, window) {
  const iocTypeKey = feedIocTypesKey(resolveFeedIocTypes(feed));
  const generation = await getActiveChunkGeneration(client, feed.id, iocTypeKey, window, 'txt');
  const chunks = await getChunkGenerationFiles(client, generation.id, 'txt');
  const cfg = getPublishedFeedArtifactConfig();
  const values = new Set();
  let lines = 0;
  let dupes = 0;
  for (const chunk of chunks) {
    const abs = path.resolve(cfg.storageDir, chunk.storage_path);
    const text = fs.readFileSync(abs, 'utf8');
    const chunkLines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : text.split('\n').filter(Boolean);
    for (const line of chunkLines) {
      lines += 1;
      if (values.has(line)) dupes += 1;
      else values.add(line);
    }
  }
  const { rows } = await client.query(
    `SELECT COUNT(*)::bigint AS n, COUNT(DISTINCT txt_value)::bigint AS uniq
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2`,
    [feed.id, window]
  );
  return {
    generation_id: generation.id,
    txt_lines: lines,
    txt_unique: values.size,
    txt_dupes: dupes,
    projection_count: Number(rows[0].n),
    projection_unique: Number(rows[0].uniq)
  };
}

async function main() {
  const feedId = Number(arg('feed-id'));
  const window = String(arg('window', 'all'));
  const deltas = String(arg('deltas', '0,1,10,100,1000,full'))
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
  if (!Number.isInteger(feedId) || feedId <= 0) throw new Error('--feed-id is required');

  const report = { feed_id: feedId, window, cases: [] };
  await withFeedLock(feedId, async (client) => {
    const feed = await loadFeed(client, feedId);
    const counts = await projectionCount(client, feedId, window);
    if (counts.missing) throw new Error(`chunk backfill incomplete: ${counts.missing} rows`);
    report.item_count = counts.n;
    report.chunk_count = Number(feed.chunk_count);
    report.formats = resolvePublishedFeedFormats(feed);

    const iocTypeKey = feedIocTypesKey(resolveFeedIocTypes(feed));
    let active = await getActiveChunkGeneration(client, feedId, iocTypeKey, window, report.formats[0]);
    if (!active) {
      const full = await runGeneration(client, feed, {
        window,
        affectedChunkKeys: null,
        expectedItemCount: counts.n,
        reason: 'bench_full_bootstrap'
      });
      report.cases.push({ delta: 'bootstrap', ...full });
      active = await getActiveChunkGeneration(client, feedId, iocTypeKey, window, report.formats[0]);
    }

    for (const delta of deltas) {
      if (delta === '0') {
        const t0 = nowMs();
        const generation = await getActiveChunkGeneration(client, feedId, iocTypeKey, window, report.formats[0]);
        report.cases.push({
          delta: 0,
          affectedChunks: 0,
          generatedChunks: 0,
          reusedChunks: Number(generation.chunk_count) * report.formats.length,
          rowsRead: 0,
          physicalBytesWritten: 0,
          itemCount: Number(generation.item_count),
          duration_ms: nowMs() - t0,
          note: 'logical no-op; no new generation'
        });
        continue;
      }
      const full = delta === 'full';
      let keys = null;
      let mutated = 0;
      if (!full) {
        const picked = await pickAndMutate(client, feedId, window, Number(delta));
        keys = picked.keys;
        mutated = picked.mutated;
      }
      const rowsReadExpected = full
        ? counts.n
        : await rowCountForChunks(client, feedId, window, keys);
      const result = await runGeneration(client, feed, {
        window,
        affectedChunkKeys: keys,
        expectedItemCount: counts.n,
        reason: full ? 'bench_full' : `bench_delta_${delta}`
      });
      report.cases.push({
        delta: full ? 'full' : Number(delta),
        mutated_identities: mutated,
        requested_chunks: full ? Number(feed.chunk_count) : keys.length,
        rows_read_expected: rowsReadExpected,
        ...result
      });
    }

    report.serving = [];
    for (const format of report.formats) {
      report.serving.push(await serveBench(client, feed, window, format));
    }
    report.txt_set = await txtSetStats(client, feed, window);
  });

  console.log(JSON.stringify(report, null, 2));
}

main().catch((err) => {
  console.error('[published-feed-chunks] bench failed', err?.stack || err?.message || err);
  process.exitCode = 1;
}).finally(() => pool.end());
