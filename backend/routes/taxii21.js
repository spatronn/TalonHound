/**
 * TAXII 2.1 read-only server.
 *
 *   GET /taxii2/                                          discovery
 *   GET /taxii2/talonhound/                               api-root
 *   GET /taxii2/talonhound/collections/                   list
 *   GET /taxii2/talonhound/collections/{id}/              detail
 *   GET /taxii2/talonhound/collections/{id}/objects/      objects
 *
 * Auth: Published Feed API key (Bearer, or ?api_key= for clients that cannot
 * set Authorization). Scope: published_feeds:read. No session cookies.
 * Write methods are not registered.
 */

import { hashApiKey, timingSafeHashEqual, keyStatus } from '../lib/publishedFeedApiKey.js';
import { hasApiScope, normalizeScopes, API_SCOPE } from '../lib/apiKeyProfiles.js';
import { touchApiKeyLastUsed } from '../lib/apiKeyAuth.js';
import {
  TAXII_API_ROOT,
  TAXII_CONTENT_TYPE,
  taxiiAcceptOk,
  publicOrigin,
  discoveryResource,
  apiRootResource,
  taxiiCollectionFromFeed,
  parseTaxiiLimit,
  pageTaxiiObjects,
  sendTaxiiError,
  sendTaxiiJson,
  listStixEnabledFeeds,
  getStixEnabledFeedBySlug,
  loadStixObjectsFromFeed,
  isValidTaxiiCollectionId
} from '../lib/taxii21.js';
import { createSlidingWindowRateLimit } from '../lib/slidingWindowRateLimit.js';

const TAXII_RATE_LIMIT_PER_MIN = Math.max(Number(process.env.FEED_PUBLIC_RATE_LIMIT_PER_MIN || 60), 1);
const rateLimit = createSlidingWindowRateLimit({
  windowMs: 60 * 1000,
  maxBuckets: Math.max(Number(process.env.FEED_PUBLIC_RATE_MAX_BUCKETS || 10_000), 100)
});

function clientIp(req) {
  const fwd = String(req?.headers?.['x-forwarded-for'] || '')
    .split(',')[0]
    .trim();
  return fwd || req?.ip || req?.socket?.remoteAddress || '';
}

function checkRateLimit(bucketKey) {
  return rateLimit.check(bucketKey, TAXII_RATE_LIMIT_PER_MIN);
}

function extractTaxiiKey(req) {
  const h = req.headers?.authorization;
  if (h && typeof h === 'string') {
    const m = h.match(/^Bearer\s+(\S+)/i);
    if (m) return m[1].trim();
  }
  const q = req.query?.api_key;
  if (typeof q === 'string' && q.trim()) return q.trim();
  return null;
}

function authenticateTaxii(pool) {
  return async function authenticateTaxiiMiddleware(req, res, next) {
    if (!taxiiAcceptOk(req)) {
      return sendTaxiiError(res, 406, 'Not Acceptable', `Accept must include ${TAXII_CONTENT_TYPE}`);
    }
    const rawKey = extractTaxiiKey(req);
    if (!rawKey) {
      res.set('WWW-Authenticate', 'Bearer');
      return sendTaxiiError(res, 401, 'Authentication Failure', 'Missing API key (Authorization Bearer or api_key query parameter)');
    }
    const presentedHash = hashApiKey(rawKey);
    if (!checkRateLimit(presentedHash)) {
      return sendTaxiiError(res, 429, 'Too Many Requests', 'Rate limit exceeded');
    }
    try {
      const { rows } = await pool.query(
        `SELECT id, name, token_hash, key_type, scopes, enabled, revoked_at, deleted_at, expires_at
         FROM published_feed_access_keys
         WHERE token_hash = $1 AND deleted_at IS NULL
         LIMIT 1`,
        [presentedHash]
      );
      const row = rows[0];
      if (!row || !timingSafeHashEqual(presentedHash, row.token_hash)) {
        res.set('WWW-Authenticate', 'Bearer');
        return sendTaxiiError(res, 401, 'Authentication Failure', 'Invalid API key');
      }
      const status = keyStatus(row);
      if (status === 'deleted') {
        res.set('WWW-Authenticate', 'Bearer');
        return sendTaxiiError(res, 401, 'Authentication Failure', 'Invalid API key');
      }
      if (status === 'disabled' || status === 'expired') {
        return sendTaxiiError(
          res,
          403,
          'Forbidden',
          status === 'expired' ? 'API key is expired' : 'API key is disabled'
        );
      }
      const scopes = normalizeScopes(row.scopes);
      if (!hasApiScope(scopes, API_SCOPE.PUBLISHED_FEEDS_READ)) {
        return sendTaxiiError(
          res,
          403,
          'Forbidden',
          `API key lacks required scope: ${API_SCOPE.PUBLISHED_FEEDS_READ}`
        );
      }
      req.apiKey = {
        id: Number(row.id),
        name: row.name,
        key_type: row.key_type,
        scopes
      };
      req.authVia = 'api_key';
      touchApiKeyLastUsed(pool, row.id, clientIp(req));
      return next();
    } catch {
      return sendTaxiiError(res, 500, 'Internal Server Error', 'Internal error');
    }
  };
}

function rejectWrite(_req, res) {
  return sendTaxiiError(res, 405, 'Method Not Allowed', 'TAXII write/import is not supported');
}

/**
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 */
export function registerTaxii21Routes(app, pool) {
  const auth = authenticateTaxii(pool);
  const root = `/taxii2/${TAXII_API_ROOT}`;

  const discoveryPaths = ['/taxii2', '/taxii2/'];
  const apiRootPaths = [root, `${root}/`];
  const collectionsPaths = [`${root}/collections`, `${root}/collections/`];
  const collectionPaths = [`${root}/collections/:id`, `${root}/collections/:id/`];
  const objectsPaths = [`${root}/collections/:id/objects`, `${root}/collections/:id/objects/`];

  app.get(discoveryPaths, auth, (req, res) => {
    return sendTaxiiJson(res, 200, discoveryResource(publicOrigin(req)));
  });

  app.get(apiRootPaths, auth, (req, res) => {
    return sendTaxiiJson(res, 200, apiRootResource(publicOrigin(req)));
  });

  app.get(collectionsPaths, auth, async (req, res) => {
    try {
      const feeds = await listStixEnabledFeeds(pool);
      const origin = publicOrigin(req);
      return sendTaxiiJson(res, 200, {
        collections: feeds.map((f) => taxiiCollectionFromFeed(f, origin))
      });
    } catch {
      return sendTaxiiError(res, 500, 'Internal Server Error', 'Internal error');
    }
  });

  app.get(collectionPaths, auth, async (req, res) => {
    try {
      const id = String(req.params.id || '').trim();
      if (!isValidTaxiiCollectionId(id)) {
        return sendTaxiiError(res, 404, 'Resource Not Found', 'Collection not found');
      }
      const feed = await getStixEnabledFeedBySlug(pool, id);
      if (!feed) {
        return sendTaxiiError(res, 404, 'Resource Not Found', 'Collection not found');
      }
      return sendTaxiiJson(res, 200, taxiiCollectionFromFeed(feed, publicOrigin(req)));
    } catch {
      return sendTaxiiError(res, 500, 'Internal Server Error', 'Internal error');
    }
  });

  app.get(objectsPaths, auth, async (req, res) => {
    try {
      const id = String(req.params.id || '').trim();
      if (!isValidTaxiiCollectionId(id)) {
        return sendTaxiiError(res, 404, 'Resource Not Found', 'Collection not found');
      }
      const feed = await getStixEnabledFeedBySlug(pool, id);
      if (!feed) {
        return sendTaxiiError(res, 404, 'Resource Not Found', 'Collection not found');
      }
      const limit = parseTaxiiLimit(req.query.limit);
      if (!limit.ok) {
        return sendTaxiiError(res, 400, 'Bad Request', limit.error);
      }
      const loaded = await loadStixObjectsFromFeed(pool, feed);
      if (!loaded.ok) {
        return sendTaxiiError(res, loaded.status, loaded.title, loaded.description);
      }
      const paged = pageTaxiiObjects(loaded.objects, { limit: limit.value, next: req.query.next });
      if (!paged.ok) {
        return sendTaxiiError(res, 400, 'Bad Request', paged.error);
      }
      return sendTaxiiJson(res, 200, paged.envelope);
    } catch {
      return sendTaxiiError(res, 500, 'Internal Server Error', 'Internal error');
    }
  });

  for (const paths of [discoveryPaths, apiRootPaths, collectionsPaths, collectionPaths, objectsPaths]) {
    app.post(paths, auth, rejectWrite);
    app.put(paths, auth, rejectWrite);
    app.patch(paths, auth, rejectWrite);
    app.delete(paths, auth, rejectWrite);
  }
}
