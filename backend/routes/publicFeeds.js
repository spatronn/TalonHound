import crypto from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { hashFeedAccessToken } from '../lib/feedAccessToken.js';
import { FEED_WINDOWS, computeResponseEtag, sliceFeedContent, feedIocTypesKey, normalizeFeedIocTypes } from '../lib/feedFormatter.js';
import {
  getLatestSnapshotMeta,
  getSnapshotContentByIdAndHash,
  getSnapshotArtifactByIdAndHash,
  normalizeFeedConfig,
  FEED_EXPORT_MAX_LIMIT,
  resolveFeedIocTypes,
  resolveFeedFilterMode,
  FEED_FILTER_MODES,
  QUERY_FEED_SNAPSHOT_KEY,
  resolveRequestedFeedFormat
} from '../lib/feedPublisherService.js';
import {
  getPublishedFeedArtifactConfig,
  resolveStoredArtifactPath,
  statArtifact
} from '../lib/publishedFeedArtifact/store.js';
import {
  PUBLISHED_FEED_KEY_TYPE,
  hashApiKey,
  timingSafeHashEqual,
  keyStatus,
  redactApiKeyInText
} from '../lib/publishedFeedApiKey.js';
import { STIX_CONTENT_TYPE } from '../lib/publishedFeedStix.js';
import { createServiceLogger } from '../lib/appLogger.js';
import {
  getActiveChunkGeneration,
  getChunkGenerationFiles,
  isPublishedFeedChunkedEnabledForFeed,
  pinPublishedFeedGeneration,
  streamChunkGeneration
} from '../lib/publishedFeedChunkGeneration.js';

import { createSlidingWindowRateLimit } from '../lib/slidingWindowRateLimit.js';

const feedLog = createServiceLogger('published-feeds');
const FEED_PUBLIC_RATE_LIMIT_PER_MIN = Math.max(Number(process.env.FEED_PUBLIC_RATE_LIMIT_PER_MIN || 60), 1);
const rateLimit = createSlidingWindowRateLimit({
  windowMs: 60 * 1000,
  maxBuckets: Math.max(Number(process.env.FEED_PUBLIC_RATE_MAX_BUCKETS || 10_000), 100)
});

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket?.remoteAddress || '';
}

function checkRateLimit(bucketKey) {
  return rateLimit.check(bucketKey, FEED_PUBLIC_RATE_LIMIT_PER_MIN);
}

function parseLimitParam(raw, feedMaxItems) {
  if (raw == null || raw === '') {
    if (feedMaxItems != null && Number.isFinite(Number(feedMaxItems))) {
      return Math.min(Number(feedMaxItems), FEED_EXPORT_MAX_LIMIT);
    }
    return null;
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return { error: 'limit must be a positive integer' };
  return Math.min(Math.floor(n), FEED_EXPORT_MAX_LIMIT);
}

function parseWindowParam(raw, configuredWindow) {
  const configured = normalizeFeedConfig({ time_window: configuredWindow }).time_window || 'all';
  if (raw == null || raw === '') {
    return configured;
  }
  const v = String(raw).trim().toLowerCase();
  if (!FEED_WINDOWS.includes(v)) {
    return { error: 'Invalid window. Use 1d, 3d, 7d, or all.' };
  }
  if (v !== configured) {
    return {
      error: `This feed is configured for the "${configured}" window. Window overrides are not supported.`
    };
  }
  return v;
}

function parseIocTypeParam(raw, feedIocTypes) {
  const types = resolveFeedIocTypes({ ioc_types: feedIocTypes });
  const key = feedIocTypesKey(types);
  if (raw == null || raw === '') return key;
  const v = String(raw).trim().toLowerCase();
  const asMulti = normalizeFeedIocTypes(v.includes(',') ? v.split(',') : v);
  if (asMulti.ok && feedIocTypesKey(asMulti.value) === key) return key;
  // Single-type feeds accept the legacy scalar match (e.g. ?ioc_type=ip).
  if (types.length === 1 && types[0] === v) return key;
  if (!asMulti.ok && !['ip', 'domain', 'url', 'hash'].includes(v)) {
    return { error: 'Invalid ioc_type' };
  }
  return { error: 'ioc_type is not allowed for this feed' };
}

function touchAccessKey(pool, keyId, ip) {
  pool.query(
    `UPDATE published_feed_access_keys
     SET last_used_at = NOW(), last_used_ip = $2
     WHERE id = $1`,
    [keyId, ip || null]
  ).catch(() => {});
}

function feedContentType(format) {
  const f = String(format || '').toLowerCase();
  if (f === 'json') return 'application/json; charset=utf-8';
  if (f === 'stix') return STIX_CONTENT_TYPE;
  return 'text/plain; charset=utf-8';
}

/**
 * Stream only the first `maxLines` newline-terminated lines of a readable to the response,
 * with backpressure. Bounded memory (a small line buffer), for ?limit= on file-backed TXT.
 */
function pipeLimitedLines(src, res, maxLines) {
  let emitted = 0;
  let buf = '';
  let ended = false;
  const finish = () => { if (!ended) { ended = true; try { src.destroy(); } catch { /* ignore */ } res.end(); } };
  src.on('data', (chunk) => {
    if (ended) return;
    buf += chunk.toString('utf8');
    let idx;
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx + 1);
      buf = buf.slice(idx + 1);
      const ok = res.write(line);
      emitted += 1;
      if (emitted >= maxLines) return finish();
      if (!ok) { src.pause(); res.once('drain', () => { if (!ended) src.resume(); }); }
    }
  });
  src.on('end', () => finish());
  src.on('error', () => { if (!ended) { ended = true; if (!res.headersSent) res.status(503); res.end(); } });
}

function applySnapshotHeaders(res, { etag, lastModified, format }) {
  res.set('Content-Type', feedContentType(format));
  res.set('Cache-Control', 'private, max-age=300');
  res.set('ETag', etag);
  if (lastModified) res.set('Last-Modified', lastModified);
}

function conditionalNotModified(req, etag, lastModified) {
  const inm = req.headers['if-none-match'];
  const ims = req.headers['if-modified-since'];
  if (inm) return inm === etag;
  if (ims && lastModified && new Date(ims).getTime() >= new Date(lastModified).getTime()) {
    return true;
  }
  return false;
}

export function computeLegacySnapshotEtag(meta, iocTypeKey, window, limit, format) {
  const exactRepresentationKey = [
    meta?.content_hash,
    meta?.generated_at ? new Date(meta.generated_at).toISOString() : '',
    meta?.content_bytes ?? '',
    format
  ].join('|');
  return computeResponseEtag(exactRepresentationKey, iocTypeKey, window, limit);
}

function takeNewlinePrefix(buffer, maxLines) {
  if (maxLines == null) return buffer;
  let lines = 0;
  for (let i = 0; i < buffer.length; i += 1) {
    if (buffer[i] !== 0x0a) continue;
    lines += 1;
    if (lines >= maxLines) return buffer.subarray(0, i + 1);
  }
  return buffer;
}

async function serveChunkedSnapshot(pool, res, req, {
  feedId,
  iocTypeKey,
  window,
  format,
  effectiveLimit,
  logServe
}) {
  if (!isPublishedFeedChunkedEnabledForFeed(feedId) || window !== 'all') return false;
  const generation = await getActiveChunkGeneration(pool, feedId, iocTypeKey, window, format);
  if (!generation) return false;
  const cfg = getPublishedFeedArtifactConfig();
  const lastModified = generation.generated_at
    ? new Date(generation.generated_at).toUTCString()
    : undefined;

  if (format === 'txt' && effectiveLimit != null) {
    if (!generation.recency_head_path) return false;
    const release = pinPublishedFeedGeneration(generation.id);
    try {
      const absolute = resolveStoredArtifactPath(cfg.storageDir, generation.recency_head_path);
      const head = await readFile(absolute);
      const body = takeNewlinePrefix(head, effectiveLimit);
      const etag = `"${crypto.createHash('sha256').update(body).digest('hex')}"`;
      applySnapshotHeaders(res, { etag, lastModified, format });
      res.set('Content-Length', String(body.length));
      if (conditionalNotModified(req, etag, lastModified)) {
        logServe({ status: 304, content_loaded: false, generation_id: generation.id });
        res.status(304).end();
        return true;
      }
      logServe({
        status: 200,
        content_loaded: true,
        snapshot_bytes: body.length,
        generation_id: generation.id,
        recency_limit: effectiveLimit
      });
      if (req.method === 'HEAD') res.end();
      else res.end(body);
      return true;
    } catch {
      if (!res.headersSent) res.status(503);
      res.end('Feed momentarily unavailable');
      return true;
    } finally {
      release();
    }
  }

  const chunks = await getChunkGenerationFiles(pool, generation.id, format);
  for (const chunk of chunks) {
    let absolute;
    try {
      absolute = resolveStoredArtifactPath(cfg.storageDir, chunk.storage_path);
    } catch {
      res.status(503).send('Feed momentarily unavailable');
      return true;
    }
    // Preflight every immutable reference before sending the envelope. This prevents a
    // missing/short chunk from turning into a syntactically partial JSON/STIX response.
    // eslint-disable-next-line no-await-in-loop
    const st = await statArtifact(absolute);
    if (!st || Number(st.size) !== Number(chunk.byte_length)) {
      res.status(503).send('Feed momentarily unavailable');
      return true;
    }
  }
  const etag = generation.strong_etag;
  applySnapshotHeaders(res, { etag, lastModified, format });
  res.set('Content-Length', String(generation.byte_length));
  if (conditionalNotModified(req, etag, lastModified)) {
    logServe({
      status: 304,
      content_loaded: false,
      snapshot_bytes: Number(generation.byte_length),
      generation_id: generation.id
    });
    res.status(304).end();
    return true;
  }
  logServe({
    status: 200,
    content_loaded: true,
    snapshot_bytes: Number(generation.byte_length),
    generation_id: generation.id,
    chunk_count: chunks.length
  });
  if (req.method === 'HEAD') {
    res.end();
    return true;
  }
  await streamChunkGeneration(res, req, generation, chunks, cfg);
  return true;
}

async function resolvePublicRequestFormat(pool, feed, rawFormat, rawWindow) {
  const requestedWindow = rawWindow == null || rawWindow === ''
    ? String(feed.time_window || 'all')
    : String(rawWindow).toLowerCase();
  if (
    isPublishedFeedChunkedEnabledForFeed(feed.id || feed.feed_id)
    && requestedWindow === 'all'
  ) {
    const iocTypeKey = resolveFeedFilterMode(feed) === FEED_FILTER_MODES.QUERY
      ? QUERY_FEED_SNAPSHOT_KEY
      : feedIocTypesKey(resolveFeedIocTypes(feed));
    const active = await getActiveChunkGeneration(
      pool,
      feed.id || feed.feed_id,
      iocTypeKey,
      'all'
    );
    if (active.length) {
      const formats = active.map((row) => row.format);
      const requested = rawFormat == null || rawFormat === ''
        ? (formats.includes('txt') ? 'txt' : formats[0])
        : String(rawFormat).trim().toLowerCase();
      if (!['txt', 'json', 'stix'].includes(requested)) {
        return { error: "format must be 'txt', 'json', or 'stix'", status: 400 };
      }
      if (!formats.includes(requested)) {
        return { error: 'Requested format is not enabled for the active feed generation', status: 404 };
      }
      return { format: requested };
    }
  }
  return resolveRequestedFeedFormat(feed, rawFormat);
}

/**
 * Serve a feed snapshot's plaintext with caching headers, honoring optional
 * window / limit / ioc_type overrides. Shared by both public endpoints.
 *
 * 304 path loads metadata only (no content TOAST → Node). Body path pins
 * content by snapshot id + content_hash; one retry if a concurrent publish races.
 */
async function serveSnapshot(pool, res, req, { feedId, slug, iocTypes, window, maxItems, filterMode, format }) {
  const startedAt = Date.now();
  const queryMode = filterMode === FEED_FILTER_MODES.QUERY;
  const isStructured = String(format || '').toLowerCase() === 'json'
    || String(format || '').toLowerCase() === 'stix';

  // Query-mode feeds have a single window-agnostic snapshot keyed by QUERY_FEED_SNAPSHOT_KEY.
  // The IOC-type and window request overrides are Basic-Filters concepts and do not apply,
  // so they are ignored here; only ?limit= still trims the served content.
  let iocTypeResult;
  let windowResult;
  if (queryMode) {
    iocTypeResult = QUERY_FEED_SNAPSHOT_KEY;
    windowResult = 'all';
  } else {
    iocTypeResult = parseIocTypeParam(req.query.ioc_type, iocTypes);
    if (iocTypeResult && typeof iocTypeResult === 'object' && iocTypeResult.error) {
      return res.status(400).send(iocTypeResult.error);
    }
    windowResult = parseWindowParam(req.query.window, window);
    if (windowResult && typeof windowResult === 'object' && windowResult.error) {
      return res.status(400).send(windowResult.error);
    }
  }
  const limitResult = parseLimitParam(req.query.limit, maxItems);
  if (limitResult && typeof limitResult === 'object' && limitResult.error) {
    return res.status(400).send(limitResult.error);
  }
  // JSON/STIX feeds are a single structured document — line-based ?limit= slicing would
  // produce invalid output, so it does not apply (max_items is already enforced at generation).
  const effectiveLimit = isStructured ? null : limitResult;

  const logServe = (fields) => {
    feedLog.info('published feed serve', {
      feed_id: Number(feedId),
      slug: slug || null,
      duration_ms: Date.now() - startedAt,
      ...fields
    });
  };

  if (await serveChunkedSnapshot(pool, res, req, {
    feedId,
    iocTypeKey: iocTypeResult,
    window: windowResult,
    format,
    effectiveLimit,
    logServe
  })) {
    return;
  }

  // attempt 0 = first try; attempt 1 = one retry after id+hash miss
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const meta = await getLatestSnapshotMeta(pool, feedId, iocTypeResult, windowResult, format);
    if (!meta) {
      res.set('Content-Type', feedContentType(format));
      res.set('Cache-Control', 'private, max-age=300');
      logServe({ status: 404, content_loaded: false, snapshot_bytes: null });
      return res.status(404).send('');
    }

    const etag = computeLegacySnapshotEtag(
      meta,
      iocTypeResult,
      windowResult,
      effectiveLimit ?? 'all',
      format
    );
    const lastModified = meta.generated_at ? new Date(meta.generated_at).toUTCString() : undefined;
    applySnapshotHeaders(res, { etag, lastModified, format });

    if (conditionalNotModified(req, etag, lastModified)) {
      logServe({
        status: 304,
        content_loaded: false,
        snapshot_bytes: meta.content_bytes != null ? Number(meta.content_bytes) : null
      });
      return res.status(304).end();
    }

    // File-backed snapshot: stream the artifact (bounded memory, no full read into Node).
    if (meta.storage_path) {
      const artifact = await getSnapshotArtifactByIdAndHash(pool, meta.id, meta.content_hash);
      if (!artifact) {
        if (attempt === 0) continue; // publish raced; re-read metadata once
        logServe({ status: 503, content_loaded: false, snapshot_bytes: null });
        return res.status(503).send('Feed momentarily unavailable');
      }
      const cfg = getPublishedFeedArtifactConfig();
      let absPath;
      try {
        absPath = resolveStoredArtifactPath(cfg.storageDir, artifact.storage_path);
      } catch {
        logServe({ status: 503, content_loaded: false, snapshot_bytes: null });
        return res.status(503).send('Feed momentarily unavailable');
      }
      const st = await statArtifact(absPath);
      if (!st) {
        if (attempt === 0) continue;
        logServe({ status: 503, content_loaded: false, snapshot_bytes: null });
        return res.status(503).send('Feed momentarily unavailable');
      }
      // TXT with ?limit= streams only the first N lines; otherwise the whole artifact
      // (with Content-Length). JSON/STIX always stream the whole document.
      const lineLimit = (!isStructured && effectiveLimit != null) ? effectiveLimit : null;
      if (lineLimit == null) res.set('Content-Length', String(st.size));
      const fileStream = createReadStream(absPath);
      fileStream.on('error', () => { if (!res.headersSent) res.status(503); res.end(); });
      logServe({ status: 200, content_loaded: true, snapshot_bytes: Number(artifact.file_size || st.size) });
      if (lineLimit == null) return fileStream.pipe(res);
      return pipeLimitedLines(fileStream, res, lineLimit);
    }

    // Legacy inline-content snapshot.
    const snapshot = await getSnapshotContentByIdAndHash(pool, meta.id, meta.content_hash);
    if (!snapshot) {
      if (attempt === 0) continue;
      logServe({ status: 503, content_loaded: false, snapshot_bytes: null });
      return res.status(503).send('Feed momentarily unavailable');
    }

    // JSON/STIX serve the whole document; TXT may be trimmed by ?limit=/max_items.
    const outContent = isStructured ? snapshot.content : sliceFeedContent(snapshot.content, effectiveLimit).content;
    // Headers already set from the meta that matches this content_hash.
    const bytes = meta.content_bytes != null
      ? Number(meta.content_bytes)
      : Buffer.byteLength(outContent, 'utf8');
    logServe({ status: 200, content_loaded: true, snapshot_bytes: bytes });
    return res.send(outContent);
  }

  logServe({ status: 503, content_loaded: false, snapshot_bytes: null });
  return res.status(503).send('Feed momentarily unavailable');
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 */
export function registerPublicFeedRoutes(app, pool) {
  // Standard pull endpoint: GET /api/published-feeds/{slug}?api_key={API_KEY}
  //   * Authorized by a `published_feed` type key that is active (not revoked /
  //     disabled / expired). Any such key may pull any published feed.
  //   * The api_key value is never written to logs or error responses.
  //   * Only the `api_key` query parameter is honored (no key/token/path aliases).
  // Registered before the admin routes; falls through (next) when no api_key is present.
  app.get('/api/published-feeds/:slug', async (req, res, next) => {
    const apiKey = req.query.api_key;
    if (apiKey == null || apiKey === '') return next(); // admin/session route handles it

    const slug = String(req.params.slug || '').trim().toLowerCase();
    const presentedHash = hashApiKey(String(apiKey));

    if (!checkRateLimit(presentedHash)) {
      res.set('Cache-Control', 'no-store');
      return res.status(429).json({ message: 'Too many requests' });
    }

    try {
      const { rows: keyRows } = await pool.query(
        `SELECT id, token_hash, key_type, enabled, revoked_at, deleted_at, expires_at
         FROM published_feed_access_keys
         WHERE token_hash = $1 AND key_type = $2 AND deleted_at IS NULL
         LIMIT 1`,
        [presentedHash, PUBLISHED_FEED_KEY_TYPE]
      );

      const key = keyRows[0];
      // Constant-time confirm + status checks. Any failure returns a uniform 401/403.
      if (!key || !timingSafeHashEqual(presentedHash, key.token_hash)) {
        res.set('Cache-Control', 'no-store');
        return res.status(401).json({ message: 'Invalid API key' });
      }
      const status = keyStatus(key);
      if (status !== 'active') {
        res.set('Cache-Control', 'no-store');
        return res.status(403).json({ message: `API key is ${status}` });
      }

      const { rows: feedRows } = await pool.query(
        `SELECT id, enabled, ioc_types, time_window, max_items, filter_mode, advanced_query, formats
         FROM published_feeds WHERE slug = $1 LIMIT 1`,
        [slug]
      );
      const feed = feedRows[0];
      if (!feed || !feed.enabled) {
        return res.status(404).json({ message: 'Feed not found' });
      }

      const requested = await resolvePublicRequestFormat(
        pool,
        feed,
        req.query.format,
        req.query.window
      );
      if (requested.error) {
        return res.status(requested.status).json({ message: requested.error });
      }

      touchAccessKey(pool, key.id, clientIp(req));
      return await serveSnapshot(pool, res, req, {
        feedId: feed.id,
        slug,
        iocTypes: resolveFeedIocTypes(feed),
        window: feed.time_window,
        maxItems: feed.max_items,
        filterMode: resolveFeedFilterMode(feed),
        format: requested.format
      });
    } catch (err) {
      console.error('[published-feed] error', redactApiKeyInText(err?.message || String(err)));
      return res.status(500).json({ message: 'Internal error' });
    }
  });

  // Legacy per-feed token endpoint (feed-bound hash-only keys). Kept for backward
  // compatibility until consumers rotate onto Published Feed keys.
  const serveLegacyTokenFeed = async (req, res, pathFormat) => {
    const rawToken = String(req.params.token || '').trim();
    if (!rawToken) return res.status(404).send('Not found');

    const tokenHash = hashFeedAccessToken(rawToken);
    if (!checkRateLimit(tokenHash)) {
      return res.status(429).send('Too many requests');
    }

    try {
      const { rows: keyRows } = await pool.query(
        `SELECT k.id, k.enabled, k.revoked_at, k.deleted_at, k.expires_at,
                f.id AS feed_id, f.enabled AS feed_enabled, f.ioc_types, f.time_window, f.max_items,
                f.filter_mode, f.advanced_query, f.slug AS feed_slug, f.formats
         FROM published_feed_access_keys k
         JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.token_hash = $1 AND k.deleted_at IS NULL
         LIMIT 1`,
        [tokenHash]
      );

      if (!keyRows.length) return res.status(404).send('Not found');
      const key = keyRows[0];
      if (keyStatus(key) !== 'active') return res.status(403).send('Forbidden');
      if (!key.feed_enabled) return res.status(403).send('Forbidden');

      const rawFormat = req.query.format != null && req.query.format !== ''
        ? req.query.format
        : pathFormat;
      const requested = await resolvePublicRequestFormat(
        pool,
        key,
        rawFormat,
        req.query.window
      );
      if (requested.error) {
        return res.status(requested.status).send(requested.error);
      }

      touchAccessKey(pool, key.id, clientIp(req));
      return await serveSnapshot(pool, res, req, {
        feedId: key.feed_id,
        slug: key.feed_slug || null,
        iocTypes: resolveFeedIocTypes(key),
        window: key.time_window,
        maxItems: key.max_items,
        filterMode: resolveFeedFilterMode(key),
        format: requested.format
      });
    } catch (err) {
      console.error('[public-feed] error', err?.message || err);
      return res.status(500).send('Internal error');
    }
  };

  app.get('/public/feeds/:token/feed.txt', (req, res) => serveLegacyTokenFeed(req, res, 'txt'));
  app.get('/public/feeds/:token/feed.json', (req, res) => serveLegacyTokenFeed(req, res, 'json'));
}
