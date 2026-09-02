import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import {
  PUBLISHED_FEED_CHUNK_ALGO_VERSION,
  PUBLISHED_FEED_CHUNK_SERIALIZER_VERSION,
  choosePublishedFeedChunkCount,
  logicalRepresentationLength,
  strongRepresentationEtag
} from './publishedFeedChunks.js';
import {
  resolvePublishedFeedFormats,
  resolveJsonIncludeFlags,
  retireLegacyMonolithicSnapshotsForWindow
} from './feedPublisherService.js';
import { indicatorFromPublishedItem } from './publishedFeedStix.js';
import {
  StreamingJsonBodyWriter,
  StreamingStixBodyWriter,
  StreamingTxtWriter,
  buildJsonFeedHeader,
  buildStixFeedHeader,
  JSON_FEED_FOOTER,
  STIX_FEED_FOOTER
} from './publishedFeedArtifact/streamWriter.js';
import {
  commitArtifact,
  commitContentAddressedPart,
  finalizeStream,
  getPublishedFeedArtifactConfig,
  openChunkPartStream,
  removeFileQuiet,
  resolveChunkFinalPath,
  resolveGenerationHeadPath,
  resolveStoredArtifactPath,
  toRelativeChunkPath
} from './publishedFeedArtifact/store.js';
import {
  BASE_PROJECTION_WINDOW,
  projectionWindowFilter,
  isSlidingWindowIncrementalEnabled,
  canReuseUnaffectedChunks
} from './publishedFeedWindowEligibility.js';

const CURSOR_BATCH = Math.max(Number(process.env.PUBLISHED_FEED_CURSOR_BATCH || 5000), 100);
const RECENCY_HEAD_ITEMS = Math.max(Number(process.env.FEED_EXPORT_MAX_LIMIT || 100000), 1);
const activeGenerationPins = new Map();

function envEnabled(name, fallback = false) {
  const value = String(process.env[name] ?? fallback).trim().toLowerCase();
  return ['1', 'true', 'yes', 'on'].includes(value);
}

function allowlisted(feedId) {
  const raw = String(process.env.PUBLISHED_FEED_CHUNKED_FEED_IDS || '').trim();
  if (!raw) return true;
  return new Set(raw.split(/[,\s]+/).map(Number).filter(Number.isFinite)).has(Number(feedId));
}

export function isPublishedFeedChunkedEnabledForFeed(feedId) {
  return envEnabled('PUBLISHED_FEED_CHUNKED_ENABLED') && allowlisted(feedId);
}

export function pinPublishedFeedGeneration(generationId) {
  const id = String(generationId);
  activeGenerationPins.set(id, (activeGenerationPins.get(id) || 0) + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const next = Math.max(0, (activeGenerationPins.get(id) || 1) - 1);
    if (next === 0) activeGenerationPins.delete(id);
    else activeGenerationPins.set(id, next);
  };
}

export function isPublishedFeedGenerationPinned(generationId) {
  return (activeGenerationPins.get(String(generationId)) || 0) > 0;
}

export async function getActiveChunkGeneration(db, feedId, iocTypeKey, window, format = null) {
  const params = [Number(feedId), String(window), String(iocTypeKey)];
  const formatWhere = format ? `AND gf.format = $4` : '';
  if (format) params.push(String(format));
  const { rows } = await db.query(
    `SELECT g.*, gf.format, gf.serializer_version, gf.header_bytes, gf.footer_bytes,
            gf.separator_bytes, gf.item_count AS format_item_count,
            gf.byte_length, gf.strong_etag, gf.recency_head_path,
            gf.recency_head_hash, gf.recency_head_item_count, gf.recency_head_byte_length
     FROM published_feed_active_generations a
     JOIN published_feed_generations g ON g.id = a.generation_id AND g.state = 'active'
     JOIN published_feed_generation_formats gf ON gf.generation_id = g.id
     WHERE a.feed_id = $1 AND a.snapshot_window = $2 AND a.ioc_type_key = $3
       ${formatWhere}
     ORDER BY gf.format`,
    params
  );
  return format ? (rows[0] || null) : rows;
}

export async function getChunkGenerationFiles(db, generationId, format) {
  const { rows } = await db.query(
    `SELECT gc.chunk_key, gc.ordinal, c.storage_path, c.content_hash,
            c.byte_length, c.item_count
     FROM published_feed_generation_chunks gc
     JOIN published_feed_chunks c ON c.id = gc.chunk_id
     WHERE gc.generation_id = $1 AND gc.format = $2
     ORDER BY gc.ordinal`,
    [String(generationId), String(format)]
  );
  return rows;
}

function generationId() {
  return `${Date.now().toString(36)}-${crypto.randomBytes(10).toString('hex')}`;
}

function writerFor(format, stream, feed) {
  if (format === 'json') {
    return new StreamingJsonBodyWriter(stream, {
      name: feed.name,
      ...resolveJsonIncludeFlags(feed)
    });
  }
  if (format === 'stix') return new StreamingStixBodyWriter(stream, { slug: feed.slug });
  return new StreamingTxtWriter(stream);
}

async function openChunkWriters(cfg, feed, window, chunkCount, chunkKey, formats) {
  const slots = {};
  for (const format of formats) {
    // eslint-disable-next-line no-await-in-loop
    const opened = await openChunkPartStream(cfg, {
      feedId: feed.id,
      window,
      algoVersion: PUBLISHED_FEED_CHUNK_ALGO_VERSION,
      chunkCount,
      chunkKey,
      format
    });
    slots[format] = {
      ...opened,
      format,
      writer: writerFor(format, opened.stream, feed)
    };
  }
  return slots;
}

async function discardSlots(slots) {
  for (const slot of Object.values(slots || {})) {
    if (!slot.stream.destroyed) slot.stream.destroy();
    await removeFileQuiet(slot.partPath);
  }
}

async function finishChunkWriters(cfg, feed, window, chunkCount, chunkKey, slots) {
  const out = [];
  for (const slot of Object.values(slots)) {
    const finished = slot.writer.finish();
    // eslint-disable-next-line no-await-in-loop
    await finalizeStream(slot.stream);
    if (finished.byte_length === 0) {
      // eslint-disable-next-line no-await-in-loop
      await removeFileQuiet(slot.partPath);
      continue;
    }
    const contentHash = finished.fragment_hash || finished.content_hash;
    const finalPath = resolveChunkFinalPath(slot.dir, chunkKey, contentHash, slot.format);
    // eslint-disable-next-line no-await-in-loop
    const committed = await commitContentAddressedPart(slot.partPath, finalPath);
    out.push({
      feed_id: feed.id,
      snapshot_window: window,
      chunk_algo_version: PUBLISHED_FEED_CHUNK_ALGO_VERSION,
      chunk_count: chunkCount,
      chunk_key: chunkKey,
      format: slot.format,
      serializer_version: PUBLISHED_FEED_CHUNK_SERIALIZER_VERSION[slot.format],
      content_hash: contentHash,
      byte_length: finished.byte_length,
      item_count: finished.item_count,
      storage_path: toRelativeChunkPath(cfg.storageDir, finalPath),
      physical_bytes_written: committed.reused ? 0 : finished.byte_length
    });
  }
  return out;
}

async function addProjectionRow(slots, row) {
  const item = row.item_json && typeof row.item_json === 'object'
    ? row.item_json
    : (typeof row.item_json === 'string' ? JSON.parse(row.item_json) : null);
  if (slots.txt) await slots.txt.writer.addValue(row.txt_value);
  if (slots.json) {
    if (!item) throw new Error(`Projection item ${row.identity_key} has no JSON serializer input`);
    await slots.json.writer.addItem(item);
  }
  if (slots.stix) {
    if (!item) throw new Error(`Projection item ${row.identity_key} has no STIX serializer input`);
    await slots.stix.writer.addIndicator(indicatorFromPublishedItem(item));
  }
}

async function generateChunkFiles(db, feed, window, chunkCount, affectedChunkKeys, formats, cfg, asOf = null) {
  const keys = [...new Set(affectedChunkKeys.map(Number))].sort((a, b) => a - b);
  if (!keys.length) return { chunks: [], rowsRead: 0, physicalBytesWritten: 0 };
  const chunks = [];
  let rowsRead = 0;
  let currentKey = null;
  let slots = null;
  const useBaseProjection = isSlidingWindowIncrementalEnabled();
  const projectionWindow = useBaseProjection ? BASE_PROJECTION_WINDOW : window;
  try {
    if (useBaseProjection) {
      // $1 feed_id, $2 snapshot_window, $3 chunk keys; window filter (if any) starts at $4.
      const filter = projectionWindowFilter(window, 4, asOf);
      await db.query(
        `DECLARE pf_chunk_cur NO SCROLL CURSOR FOR
         SELECT identity_key, chunk_key, txt_value, item_json
         FROM published_feed_items
         WHERE feed_id = $1 AND snapshot_window = $2${filter.sql}
           AND chunk_key = ANY($3::integer[])
         ORDER BY chunk_key, recency_ts DESC NULLS LAST,
                  confidence_rank DESC, observable ASC, identity_key ASC`,
        [feed.id, projectionWindow, keys, ...filter.params]
      );
    } else {
      await db.query(
        `DECLARE pf_chunk_cur NO SCROLL CURSOR FOR
         SELECT identity_key, chunk_key, txt_value, item_json
         FROM published_feed_items
         WHERE feed_id = $1 AND snapshot_window = $2
           AND chunk_key = ANY($3::integer[])
         ORDER BY chunk_key, recency_ts DESC NULLS LAST,
                  confidence_rank DESC, observable ASC, identity_key ASC`,
        [feed.id, window, keys]
      );
    }
    for (;;) {
      // eslint-disable-next-line no-await-in-loop
      const batch = await db.query(`FETCH FORWARD ${CURSOR_BATCH} FROM pf_chunk_cur`);
      if (!batch.rows.length) break;
      for (const row of batch.rows) {
        rowsRead += 1;
        const key = Number(row.chunk_key);
        if (currentKey !== key) {
          if (slots) {
            // eslint-disable-next-line no-await-in-loop
            chunks.push(...await finishChunkWriters(cfg, feed, window, chunkCount, currentKey, slots));
          }
          currentKey = key;
          // eslint-disable-next-line no-await-in-loop
          slots = await openChunkWriters(cfg, feed, window, chunkCount, key, formats);
        }
        // eslint-disable-next-line no-await-in-loop
        await addProjectionRow(slots, row);
      }
    }
    await db.query('CLOSE pf_chunk_cur').catch(() => {});
    if (slots) chunks.push(...await finishChunkWriters(cfg, feed, window, chunkCount, currentKey, slots));
  } catch (err) {
    await db.query('CLOSE pf_chunk_cur').catch(() => {});
    await discardSlots(slots);
    throw err;
  }
  return {
    chunks,
    rowsRead,
    physicalBytesWritten: chunks.reduce((sum, chunk) => sum + chunk.physical_bytes_written, 0)
  };
}

async function writeRecencyHead(db, cfg, feed, window, id, asOf = null) {
  const useBaseProjection = isSlidingWindowIncrementalEnabled();
  const projectionWindow = useBaseProjection ? BASE_PROJECTION_WINDOW : window;
  const filter = useBaseProjection ? projectionWindowFilter(window, 4, asOf) : { sql: '', params: [] };
  const { rows } = await db.query(
    `SELECT txt_value
     FROM published_feed_items
     WHERE feed_id = $1 AND snapshot_window = $2${filter.sql}
     ORDER BY recency_ts DESC NULLS LAST, confidence_rank DESC, observable ASC, identity_key ASC
     LIMIT $3`,
    [feed.id, projectionWindow, RECENCY_HEAD_ITEMS, ...filter.params]
  );
  const content = rows.length ? `${rows.map((row) => row.txt_value).join('\n')}\n` : '';
  const hash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  const finalPath = resolveGenerationHeadPath(cfg.storageDir, feed.id, id);
  const partPath = `${finalPath}.part`;
  await fs.promises.mkdir(path.dirname(finalPath), { recursive: true });
  await fs.promises.writeFile(partPath, content, { mode: 0o640 });
  const handle = await fs.promises.open(partPath, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
  await commitArtifact(partPath, finalPath);
  return {
    storage_path: toRelativeChunkPath(cfg.storageDir, finalPath),
    content_hash: hash,
    item_count: rows.length,
    byte_length: Buffer.byteLength(content, 'utf8')
  };
}

async function upsertChunkRows(db, chunks) {
  const ids = new Map();
  for (const chunk of chunks) {
    // eslint-disable-next-line no-await-in-loop
    const { rows } = await db.query(
      `INSERT INTO published_feed_chunks (
         feed_id, snapshot_window, chunk_algo_version, chunk_count, chunk_key,
         format, serializer_version, content_hash, byte_length, item_count, storage_path
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (
         feed_id, snapshot_window, chunk_algo_version, chunk_count,
         chunk_key, format, serializer_version, content_hash
       ) DO UPDATE SET storage_path = EXCLUDED.storage_path
       RETURNING id`,
      [
        chunk.feed_id, chunk.snapshot_window, chunk.chunk_algo_version, chunk.chunk_count,
        chunk.chunk_key, chunk.format, chunk.serializer_version, chunk.content_hash,
        chunk.byte_length, chunk.item_count, chunk.storage_path
      ]
    );
    ids.set(`${chunk.format}:${chunk.chunk_key}`, Number(rows[0].id));
  }
  return ids;
}

function formatEnvelope(feed, format, generatedAt, itemCount) {
  if (format === 'json') {
    const flags = resolveJsonIncludeFlags(feed);
    return {
      header: buildJsonFeedHeader({
        name: feed.name,
        generatedAt,
        itemCount,
        ...flags
      }),
      footer: JSON_FEED_FOOTER,
      separator: ','
    };
  }
  if (format === 'stix') {
    return { header: buildStixFeedHeader(feed.slug), footer: STIX_FEED_FOOTER, separator: ',' };
  }
  return { header: '', footer: '', separator: '' };
}

/**
 * Build and atomically activate an immutable generation from the current projection.
 * Caller must already hold the feed advisory lock and an open SQL transaction. Projection
 * delta, cutoff advancement and activation commit together in the caller's COMMIT.
 */
function throwIfInjected(failAt, stage) {
  if (failAt && failAt === stage) {
    throw Object.assign(new Error(`injected generation failure: ${stage}`), {
      code: 'INJECTED_GENERATION_FAILURE',
      stage
    });
  }
}

export async function buildAndActivateChunkGeneration(db, feed, {
  window = 'all',
  iocTypeKey,
  configHash,
  candidateCutoff,
  affectedChunkKeys = null,
  expectedItemCount = null,
  fullRebuildReason = null,
  metrics = {},
  failAt = null,
  generateChunks = generateChunkFiles
}) {
  if (String(feed.chunk_backfill_status || '') !== 'ready') {
    throw Object.assign(new Error('Published Feed chunk backfill is not ready'), { code: 'CHUNK_BACKFILL_NOT_READY' });
  }
  const cfg = getPublishedFeedArtifactConfig();
  const formats = resolvePublishedFeedFormats(feed);
  const chunkCount = Number(feed.chunk_count)
    || choosePublishedFeedChunkCount(Number(expectedItemCount || 0));
  const algoVersion = Number(feed.chunk_algo_version || PUBLISHED_FEED_CHUNK_ALGO_VERSION);
  if (algoVersion !== PUBLISHED_FEED_CHUNK_ALGO_VERSION) {
    throw new Error(`Unsupported active chunk algorithm version: ${algoVersion}`);
  }
  const activeRows = await getActiveChunkGeneration(db, feed.id, iocTypeKey, window);
  const parent = activeRows[0] || null;
  let full = !parent || !affectedChunkKeys;
  let affected = full
    ? Array.from({ length: chunkCount }, (_, key) => key)
    : [...new Set(affectedChunkKeys.map(Number))].sort((a, b) => a - b);
  let resolvedRebuildReason = fullRebuildReason;
  const reuseCheckMeta = {};
  const id = generationId();
  const generatedAt = new Date().toISOString();
  // Freeze sliding-window membership to the same instant used for dirty/boundary work.
  const generationAsOf = candidateCutoff || null;
  const generationItemCount = expectedItemCount != null
    ? Number(expectedItemCount)
    : Number(parent?.item_count || 0);

  // Incremental reuse assumes the parent generation was a complete snapshot for
  // unaffected chunk keys. If projection membership for those keys diverges from
  // the parent's stored chunk item counts, dirty-only rebuild cannot converge
  // (manifest sum stays << expected and activation rolls back forever).
  if (!full && parent?.id) {
    const reuseFormat = formats.includes('txt') ? 'txt' : formats[0];
    const reuse = await canReuseUnaffectedChunks(db, {
      feedId: feed.id,
      artifactWindow: window,
      asOf: generationAsOf,
      parentGenerationId: parent.id,
      format: reuseFormat,
      excludeChunkKeys: affected,
      expectedTotal: generationItemCount
    });
    if (!reuse.reusable) {
      full = true;
      affected = Array.from({ length: chunkCount }, (_, key) => key);
      resolvedRebuildReason = resolvedRebuildReason || reuse.reason || 'reused_chunk_membership_drift';
      reuseCheckMeta.reuse_check = reuse;
    }
  }

  const generationMetrics = {
    ...metrics,
    generation_as_of: generationAsOf instanceof Date
      ? generationAsOf.toISOString()
      : (generationAsOf ? String(generationAsOf) : null),
    expected_item_count: generationItemCount,
    refresh_mode_hint: full ? 'chunked_full' : 'chunked_incremental',
    full_rebuild_reason: resolvedRebuildReason || null,
    ...reuseCheckMeta
  };

  await db.query(
    `INSERT INTO published_feed_generations (
       id, feed_id, snapshot_window, ioc_type_key, parent_generation_id, state,
       candidate_cutoff, generated_at, item_count, chunk_count, chunk_algo_version,
       formats, config_hash, full_rebuild_reason, generation_metrics
     ) VALUES ($1,$2,$3,$4,$5,'building',$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14::jsonb)`,
    [
      id, feed.id, window, iocTypeKey, parent?.id || null, candidateCutoff,
      generatedAt, generationItemCount, chunkCount, algoVersion,
      JSON.stringify(formats), configHash, resolvedRebuildReason, JSON.stringify(generationMetrics)
    ]
  );
  throwIfInjected(failAt, 'after_generation_insert');

  const t0 = Date.now();
  const generated = await generateChunks(
    db, feed, window, chunkCount, affected, formats, cfg, generationAsOf
  );
  throwIfInjected(failAt, 'after_chunks');
  const chunkIds = await upsertChunkRows(db, generated.chunks);
  const affectedSet = new Set(affected);

  if (parent) {
    await db.query(
      `INSERT INTO published_feed_generation_chunks (
         generation_id, format, chunk_key, chunk_id, ordinal
       )
       SELECT $1, gc.format, gc.chunk_key, gc.chunk_id, gc.chunk_key
       FROM published_feed_generation_chunks gc
       WHERE gc.generation_id = $2
         AND NOT (gc.chunk_key = ANY($3::integer[]))`,
      [id, parent.id, affected]
    );
  }
  for (const format of formats) {
    for (const key of affected) {
      const chunkId = chunkIds.get(`${format}:${key}`);
      if (!chunkId) continue; // bucket became empty
      // eslint-disable-next-line no-await-in-loop
      await db.query(
        `INSERT INTO published_feed_generation_chunks (
           generation_id, format, chunk_key, chunk_id, ordinal
         ) VALUES ($1,$2,$3,$4,$3)`,
        [id, format, key, chunkId]
      );
    }
  }

  const recencyHead = formats.includes('txt')
    ? await writeRecencyHead(db, cfg, feed, window, id, generationAsOf)
    : null;
  for (const format of formats) {
    // eslint-disable-next-line no-await-in-loop
    const { rows: refs } = await db.query(
      `SELECT c.content_hash, c.byte_length, c.item_count
       FROM published_feed_generation_chunks gc
       JOIN published_feed_chunks c ON c.id = gc.chunk_id
       WHERE gc.generation_id = $1 AND gc.format = $2
       ORDER BY gc.ordinal`,
      [id, format]
    );
    const formatItemCount = refs.reduce((sum, row) => sum + Number(row.item_count || 0), 0);
    if (format !== 'stix' && formatItemCount !== generationItemCount) {
      throw Object.assign(
        new Error(
          `Chunk manifest count mismatch for ${format}: ${formatItemCount} != ${generationItemCount}`
        ),
        {
          code: 'CHUNK_MANIFEST_COUNT_MISMATCH',
          feed_id: feed.id,
          feed_name: feed.name || null,
          snapshot_window: window,
          format,
          generation_id: id,
          generation_as_of: generationMetrics.generation_as_of,
          expected_item_count: generationItemCount,
          actual_item_count: formatItemCount,
          chunk_file_count: refs.length,
          affected_chunks: affected.length,
          rows_read: generated.rowsRead
        }
      );
    }
    const envelope = formatEnvelope(feed, format, generatedAt, formatItemCount);
    const byteLength = logicalRepresentationLength({
      header: envelope.header,
      footer: envelope.footer,
      chunks: refs,
      separator: envelope.separator
    });
    const etag = strongRepresentationEtag({
      format,
      serializerVersion: PUBLISHED_FEED_CHUNK_SERIALIZER_VERSION[format],
      header: envelope.header,
      footer: envelope.footer,
      chunks: refs,
      separator: envelope.separator
    });
    // eslint-disable-next-line no-await-in-loop
    await db.query(
      `INSERT INTO published_feed_generation_formats (
         generation_id, format, serializer_version, header_bytes, footer_bytes,
         separator_bytes, item_count, byte_length, strong_etag,
         recency_head_path, recency_head_hash, recency_head_item_count,
         recency_head_byte_length
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        id, format, PUBLISHED_FEED_CHUNK_SERIALIZER_VERSION[format],
        envelope.header, envelope.footer, envelope.separator, formatItemCount,
        byteLength, etag,
        format === 'txt' ? recencyHead?.storage_path || null : null,
        format === 'txt' ? recencyHead?.content_hash || null : null,
        format === 'txt' ? recencyHead?.item_count ?? null : null,
        format === 'txt' ? recencyHead?.byte_length ?? null : null
      ]
    );
  }
  throwIfInjected(failAt, 'after_manifest');

  await db.query(`UPDATE published_feed_generations SET state = 'ready' WHERE id = $1`, [id]);
  throwIfInjected(failAt, 'before_activation');
  if (parent) {
    await db.query(
      `UPDATE published_feed_generations
       SET state = 'superseded', superseded_at = NOW()
       WHERE id = $1 AND state = 'active'`,
      [parent.id]
    );
  }
  await db.query(
    `INSERT INTO published_feed_active_generations (
       feed_id, snapshot_window, ioc_type_key, generation_id, activated_at
     ) VALUES ($1,$2,$3,$4,NOW())
     ON CONFLICT (feed_id, snapshot_window, ioc_type_key)
     DO UPDATE SET generation_id = EXCLUDED.generation_id, activated_at = EXCLUDED.activated_at`,
    [feed.id, window, iocTypeKey, id]
  );
  throwIfInjected(failAt, 'during_activation');
  await db.query(
    `UPDATE published_feed_generations
     SET state = 'active', activated_at = NOW(),
         generation_metrics = COALESCE(generation_metrics, '{}'::jsonb) || $2::jsonb
     WHERE id = $1`,
    [
      id,
      JSON.stringify({
        affected_chunks: affected.length,
        generated_chunks: generated.chunks.length,
        rows_read: generated.rowsRead,
        physical_bytes_written: generated.physicalBytesWritten,
        chunk_generation_ms: Date.now() - t0,
        generation_as_of: generationMetrics.generation_as_of,
        expected_item_count: generationItemCount,
        emitted_item_count: generationItemCount
      })
    ]
  );
  await db.query(
    `UPDATE published_feeds
     SET projection_cutoff = $2,
         projection_pending_cutoff = NULL,
         last_generated_at = NOW(),
         last_status = 'success',
         last_error = NULL,
         last_refresh_checked_at = NOW(),
         last_refresh_mode = $3,
         last_changed_count = $4
     WHERE id = $1`,
    [feed.id, candidateCutoff, full ? 'chunked_full' : 'chunked_incremental', Number(metrics.semantic_changes || 0)]
  );
  // Chunk generation is now authoritative for this window; retire legacy monolithic pointers
  // so scheduled cleanup can reclaim superseded files after the retention window.
  await retireLegacyMonolithicSnapshotsForWindow(db, feed.id, window);
  throwIfInjected(failAt, 'after_activation');
  return {
    generationId: id,
    parentGenerationId: parent?.id || null,
    chunkCount,
    affectedChunks: affected.length,
    generatedChunks: generated.chunks.length,
    reusedChunks: Math.max(0, chunkCount * formats.length - generated.chunks.length),
    rowsRead: generated.rowsRead,
    physicalBytesWritten: generated.physicalBytesWritten,
    itemCount: generationItemCount,
    generatedAt
  };
}

export async function streamChunkGeneration(res, req, generation, chunks, cfg = getPublishedFeedArtifactConfig()) {
  const release = pinPublishedFeedGeneration(generation.id);
  let closed = false;
  const abort = () => { closed = true; };
  req.once('aborted', abort);
  res.once('close', abort);
  try {
    if (generation.header_bytes && !res.write(generation.header_bytes)) await once(res, 'drain');
    let emitted = false;
    for (const chunk of chunks) {
      if (closed || req.aborted || res.destroyed) return;
      if (emitted && generation.separator_bytes) {
        if (!res.write(generation.separator_bytes)) await once(res, 'drain');
      }
      const absolute = resolveStoredArtifactPath(cfg.storageDir, chunk.storage_path);
      const stream = fs.createReadStream(absolute);
      try {
        // eslint-disable-next-line no-await-in-loop
        for await (const bytes of stream) {
          if (closed || req.aborted || res.destroyed) {
            stream.destroy();
            return;
          }
          if (!res.write(bytes)) {
            // eslint-disable-next-line no-await-in-loop
            await once(res, 'drain');
          }
        }
      } finally {
        stream.destroy();
      }
      emitted = true;
    }
    if (generation.footer_bytes && !closed && !res.destroyed) res.write(generation.footer_bytes);
    if (!closed && !res.destroyed) res.end();
  } finally {
    req.off('aborted', abort);
    res.off('close', abort);
    release();
  }
}

/** Idempotent startup sweep: windows already served by chunk generations drop legacy pointers. */
export async function reconcileRetiredLegacySnapshotsForActiveChunkGenerations(pool) {
  const { rows } = await pool.query(
    `SELECT DISTINCT feed_id, snapshot_window
     FROM published_feed_active_generations
     ORDER BY feed_id, snapshot_window`
  );
  let retired = 0;
  for (const row of rows) {
    // eslint-disable-next-line no-await-in-loop
    const result = await retireLegacyMonolithicSnapshotsForWindow(
      pool,
      row.feed_id,
      row.snapshot_window
    );
    retired += result.retired;
  }
  return { windows: rows.length, retired };
}

/**
 * Remove generation_chunk manifest rows whose generation row is gone. Without the
 * generation_id FK (or when generations were deleted before it existed), these orphans
 * keep chunk rows reachable and prevent file GC.
 */
export async function reconcileOrphanGenerationChunkLinks(pool) {
  const result = await pool.query(
    `DELETE FROM published_feed_generation_chunks gc
     WHERE NOT EXISTS (
       SELECT 1 FROM published_feed_generations g WHERE g.id = gc.generation_id
     )`
  );
  return { orphanLinksRemoved: result.rowCount || 0 };
}

/** Delete chunk rows (and files) no longer referenced by any generation manifest. */
export async function purgeUnreachablePublishedFeedChunks(pool, {
  retentionMinutes = getPublishedFeedArtifactConfig().supersededRetentionMinutes,
  feedId = null
} = {}) {
  const cfg = getPublishedFeedArtifactConfig();
  const params = [String(retentionMinutes)];
  let feedFilter = '';
  if (feedId != null) {
    feedFilter = ' AND c.feed_id = $2';
    params.push(Number(feedId));
  }
  const { rows } = await pool.query(
    `DELETE FROM published_feed_chunks c
     WHERE c.created_at < NOW() - ($1::text || ' minutes')::interval
       AND NOT EXISTS (
         SELECT 1 FROM published_feed_generation_chunks gc WHERE gc.chunk_id = c.id
       )
       ${feedFilter}
     RETURNING storage_path`,
    params
  );
  let filesRemoved = 0;
  for (const row of rows) {
    // eslint-disable-next-line no-await-in-loop
    await removeFileQuiet(resolveStoredArtifactPath(cfg.storageDir, row.storage_path));
    filesRemoved += 1;
  }
  return { chunkRowsRemoved: rows.length, filesRemoved };
}

export async function cleanupPublishedFeedChunkGenerations(pool, {
  retentionMinutes = getPublishedFeedArtifactConfig().supersededRetentionMinutes
} = {}) {
  const cfg = getPublishedFeedArtifactConfig();
  const { rows: candidates } = await pool.query(
    `SELECT id, feed_id
     FROM published_feed_generations
     WHERE state IN ('superseded','failed')
       AND COALESCE(superseded_at, created_at) < NOW() - ($1::text || ' minutes')::interval
     ORDER BY created_at
     LIMIT 100`,
    [String(retentionMinutes)]
  );
  let generations = 0;
  let chunks = 0;
  for (const candidate of candidates) {
    if (isPublishedFeedGenerationPinned(candidate.id)) continue;
    const client = await pool.connect();
    let locked = false;
    try {
      // eslint-disable-next-line no-await-in-loop
      const lock = await client.query(
        'SELECT pg_try_advisory_lock($1::int, $2::int) AS ok',
        [874290151, Number(candidate.feed_id)]
      );
      locked = Boolean(lock.rows[0]?.ok);
      if (!locked || isPublishedFeedGenerationPinned(candidate.id)) continue;
      await client.query('BEGIN');
      const headPaths = await client.query(
        `SELECT recency_head_path
         FROM published_feed_generation_formats
         WHERE generation_id = $1 AND recency_head_path IS NOT NULL`,
        [candidate.id]
      );
      await client.query(
        `DELETE FROM published_feed_generation_chunks WHERE generation_id = $1`,
        [candidate.id]
      );
      const deleted = await client.query(
        `DELETE FROM published_feed_generations
         WHERE id = $1 AND state IN ('superseded','failed')
         RETURNING id`,
        [candidate.id]
      );
      if (!deleted.rowCount) {
        await client.query('ROLLBACK');
        continue;
      }
      const unreachable = await client.query(
        `DELETE FROM published_feed_chunks c
         WHERE c.feed_id = $1
           AND c.created_at < NOW() - ($2::text || ' minutes')::interval
           AND NOT EXISTS (
             SELECT 1 FROM published_feed_generation_chunks gc WHERE gc.chunk_id = c.id
           )
         RETURNING storage_path`,
        [candidate.feed_id, String(retentionMinutes)]
      );
      await client.query('COMMIT');
      generations += 1;
      for (const row of unreachable.rows) {
        // eslint-disable-next-line no-await-in-loop
        await removeFileQuiet(resolveStoredArtifactPath(cfg.storageDir, row.storage_path));
        chunks += 1;
      }
      for (const row of headPaths.rows) {
        // eslint-disable-next-line no-await-in-loop
        await removeFileQuiet(resolveStoredArtifactPath(cfg.storageDir, row.recency_head_path));
      }
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      if (locked) {
        await client.query(
          'SELECT pg_advisory_unlock($1::int, $2::int)',
          [874290151, Number(candidate.feed_id)]
        ).catch(() => {});
      }
      client.release();
    }
  }
  const orphanLinks = await reconcileOrphanGenerationChunkLinks(pool);
  const purged = await purgeUnreachablePublishedFeedChunks(pool, { retentionMinutes });
  return {
    generations,
    chunks,
    orphanLinksRemoved: orphanLinks.orphanLinksRemoved,
    unreachableChunksRemoved: purged.chunkRowsRemoved,
    unreachableFilesRemoved: purged.filesRemoved
  };
}
