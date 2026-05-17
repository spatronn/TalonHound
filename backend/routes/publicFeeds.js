import { hashFeedAccessToken } from '../lib/feedAccessToken.js';
import {
  FEED_IOC_TYPES,
  FEED_WINDOWS,
  computeResponseEtag,
  sliceFeedContent
} from '../lib/feedFormatter.js';
import { getLatestSnapshot, normalizeFeedConfig, FEED_EXPORT_MAX_LIMIT } from '../lib/feedPublisherService.js';

const FEED_PUBLIC_RATE_LIMIT_PER_MIN = Math.max(Number(process.env.FEED_PUBLIC_RATE_LIMIT_PER_MIN || 60), 1);
const rateBuckets = new Map();

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket?.remoteAddress || '';
}

function checkRateLimit(tokenHash) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  let bucket = rateBuckets.get(tokenHash);
  if (!bucket || now - bucket.start >= windowMs) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(tokenHash, bucket);
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

function parseIocTypeParam(raw, feedIocType) {
  const feedType = String(feedIocType || '').toLowerCase();
  if (raw == null || raw === '') return feedType;
  const v = String(raw).trim().toLowerCase();
  if (!FEED_IOC_TYPES.includes(v)) return { error: 'Invalid ioc_type' };
  if (v !== feedType) return { error: 'ioc_type is not allowed for this feed' };
  return v;
}

function touchAccessKey(pool, keyId, ip) {
  pool.query(
    `UPDATE published_feed_access_keys
     SET last_used_at = NOW(), last_used_ip = $2
     WHERE id = $1`,
    [keyId, ip || null]
  ).catch(() => {});
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 */
export function registerPublicFeedRoutes(app, pool) {
  app.get('/public/feeds/:token/feed.txt', async (req, res) => {
    const rawToken = String(req.params.token || '').trim();
    if (!rawToken) return res.status(404).send('Not found');

    const tokenHash = hashFeedAccessToken(rawToken);
    if (!checkRateLimit(tokenHash)) {
      return res.status(429).send('Too many requests');
    }

    try {
      const { rows: keyRows } = await pool.query(
        `SELECT k.id, k.enabled, k.revoked_at, f.id AS feed_id, f.enabled AS feed_enabled, f.ioc_type, f.time_window, f.max_items
         FROM published_feed_access_keys k
         JOIN published_feeds f ON f.id = k.feed_id
         WHERE k.token_hash = $1
         LIMIT 1`,
        [tokenHash]
      );

      if (!keyRows.length) return res.status(404).send('Not found');
      const key = keyRows[0];
      if (key.revoked_at || !key.enabled) return res.status(403).send('Forbidden');
      if (!key.feed_enabled) return res.status(403).send('Forbidden');

      const iocTypeResult = parseIocTypeParam(req.query.ioc_type, key.ioc_type);
      if (iocTypeResult && typeof iocTypeResult === 'object' && iocTypeResult.error) {
        return res.status(400).send(iocTypeResult.error);
      }

      const windowResult = parseWindowParam(req.query.window, key.time_window);
      if (windowResult && typeof windowResult === 'object' && windowResult.error) {
        return res.status(400).send(windowResult.error);
      }

      const limitResult = parseLimitParam(req.query.limit, key.max_items);
      if (limitResult && typeof limitResult === 'object' && limitResult.error) {
        return res.status(400).send(limitResult.error);
      }

      const snapshot = await getLatestSnapshot(pool, key.feed_id, iocTypeResult, windowResult);
      if (!snapshot) {
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.set('Cache-Control', 'private, max-age=300');
        return res.status(404).send('');
      }

      const sliced = sliceFeedContent(snapshot.content, limitResult);
      const etag = computeResponseEtag(
        snapshot.content_hash,
        iocTypeResult,
        windowResult,
        limitResult ?? 'all'
      );
      const lastModified = snapshot.generated_at ? new Date(snapshot.generated_at).toUTCString() : undefined;

      res.set('Content-Type', 'text/plain; charset=utf-8');
      res.set('Cache-Control', 'private, max-age=300');
      res.set('ETag', etag);
      if (lastModified) res.set('Last-Modified', lastModified);

      const inm = req.headers['if-none-match'];
      const ims = req.headers['if-modified-since'];
      if (inm && inm === etag) return res.status(304).end();
      if (ims && lastModified && new Date(ims).getTime() >= new Date(lastModified).getTime()) {
        return res.status(304).end();
      }

      touchAccessKey(pool, key.id, clientIp(req));
      return res.send(sliced.content);
    } catch (err) {
      console.error('[public-feed] error', err?.message || err);
      return res.status(500).send('Internal error');
    }
  });
}
