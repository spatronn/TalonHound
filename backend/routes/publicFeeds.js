import { createReadStream } from 'node:fs';
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
import { createServiceLogger } from '../lib/appLogger.js';

const feedLog = createServiceLogger('published-feeds');
const FEED_PUBLIC_RATE_LIMIT_PER_MIN = Math.max(Number(process.env.FEED_PUBLIC_RATE_LIMIT_PER_MIN || 60), 1);
const rateBuckets = new Map();

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket?.remoteAddress || '';
}

function checkRateLimit(bucketKey) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  let bucket = rateBuckets.get(bucketKey);
  if (!bucket || now - bucket.start >= windowMs) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(bucketKey, bucket);
  }
  bucket.count += 1;
  if (bucket.count > FEED_PUBLIC_RATE_LIMIT_PER_MIN) return false;
  return true;
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

function parseWindowParam(raw, feedDefault) {
  if (raw == null || raw === '') {
    return normalizeFeedConfig({ time_window: feedDefault }).time_window || 'all';
  }
  const v = String(raw).trim().toLowerCase();
  if (!FEED_WINDOWS.includes(v)) return { error: 'Invalid window. Use 1d, 3d, 7d, or all.' };
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
  return String(format || '').toLowerCase() === 'json'
    ? 'application/json; charset=utf-8'
    : 'text/plain; charset=utf-8';
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
  if (inm && inm === etag) return true;
  if (ims && lastModified && new Date(ims).getTime() >= new Date(lastModified).getTime()) {
    return true;
  }
  return false;
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
  const isJson = String(format || '').toLowerCase() === 'json';

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
  // JSON feeds are a single structured document — line-based ?limit= slicing would produce
  // invalid JSON, so it does not apply (max_items is already enforced at generation time).
  const effectiveLimit = isJson ? null : limitResult;

  const logServe = (fields) => {
    feedLog.info('published feed serve', {
      feed_id: Number(feedId),
      slug: slug || null,
      duration_ms: Date.now() - startedAt,
      ...fields
    });
  };

  // attempt 0 = first try; attempt 1 = one retry after id+hash miss
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const meta = await getLatestSnapshotMeta(pool, feedId, iocTypeResult, windowResult, format);
    if (!meta) {
      res.set('Content-Type', feedContentType(format));
      res.set('Cache-Control', 'private, max-age=300');
      logServe({ status: 404, content_loaded: false, snapshot_bytes: null });
      return res.status(404).send('');
    }

    const etag = computeResponseEtag(meta.content_hash, iocTypeResult, windowResult, effectiveLimit ?? 'all');
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
      // (with Content-Length). JSON always streams the whole document.
      const lineLimit = (!isJson && effectiveLimit != null) ? effectiveLimit : null;
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

    // JSON serves the whole document; TXT may be trimmed by ?limit=/max_items.
    const outContent = isJson ? snapshot.content : sliceFeedContent(snapshot.content, effectiveLimit).content;
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

      const requested = resolveRequestedFeedFormat(feed, req.query.format);
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
      const requested = resolveRequestedFeedFormat(
        { formats: key.formats },
        rawFormat
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
