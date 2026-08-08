import { hashApiKey, timingSafeHashEqual, keyStatus } from './publishedFeedApiKey.js';
import { hasApiScope, normalizeScopes } from './apiKeyProfiles.js';
import { ensureRequestId } from './apiRequestId.js';
import { sendApiError, API_ERROR_CODE } from './apiV1Errors.js';

function extractBearer(req) {
  const h = req.headers?.authorization;
  if (!h || typeof h !== 'string') return null;
  const m = h.match(/^Bearer\s+(\S+)/i);
  return m ? m[1].trim() : null;
}

function clientIp(req) {
  const fwd = String(req?.headers?.['x-forwarded-for'] || '')
    .split(',')[0]
    .trim();
  if (fwd) return fwd;
  return req?.ip || req?.socket?.remoteAddress || null;
}

/** Fire-and-forget last-used stamp (same pattern as Published Feed). */
export function touchApiKeyLastUsed(pool, keyId, ip) {
  pool.query(
    `UPDATE published_feed_access_keys
     SET last_used_at = NOW(), last_used_ip = $2
     WHERE id = $1`,
    [keyId, ip || null]
  ).catch(() => {});
}

/**
 * Authenticate `Authorization: Bearer <API_KEY>` against published_feed_access_keys.
 * Does NOT grant UI/session roles — only attaches req.apiKey.
 *
 * @param {import('pg').Pool} pool
 * @returns {import('express').RequestHandler}
 */
export function authenticateApiKey(pool) {
  return async function authenticateApiKeyMiddleware(req, res, next) {
    ensureRequestId(req, res);
    const rawKey = extractBearer(req);
    if (!rawKey) {
      return sendApiError(
        res,
        401,
        API_ERROR_CODE.INVALID_API_KEY,
        'Missing or invalid Authorization Bearer token',
        req
      );
    }

    const presentedHash = hashApiKey(rawKey);
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
        return sendApiError(res, 401, API_ERROR_CODE.INVALID_API_KEY, 'Invalid API key', req);
      }

      const status = keyStatus(row);
      if (status === 'deleted') {
        return sendApiError(res, 401, API_ERROR_CODE.INVALID_API_KEY, 'Invalid API key', req);
      }
      if (status === 'disabled' || status === 'expired') {
        return sendApiError(
          res,
          403,
          API_ERROR_CODE.API_KEY_DISABLED,
          status === 'expired' ? 'API key is expired' : 'API key is disabled',
          req
        );
      }

      req.apiKey = {
        id: Number(row.id),
        name: row.name,
        key_type: row.key_type,
        scopes: normalizeScopes(row.scopes)
      };
      req.authVia = 'api_key';
      // Intentionally no req.user — API keys must not inherit browser-session admin rights.
      touchApiKeyLastUsed(pool, row.id, clientIp(req));
      return next();
    } catch {
      return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
    }
  };
}

/**
 * Require a specific API scope on req.apiKey (must run after authenticateApiKey).
 * @param {string} scope
 * @returns {import('express').RequestHandler}
 */
export function requireApiScope(scope) {
  const required = String(scope || '').trim();
  return function requireApiScopeMiddleware(req, res, next) {
    ensureRequestId(req, res);
    if (!req.apiKey) {
      return sendApiError(res, 401, API_ERROR_CODE.INVALID_API_KEY, 'Invalid API key', req);
    }
    if (!hasApiScope(req.apiKey.scopes, required)) {
      return sendApiError(
        res,
        403,
        API_ERROR_CODE.INSUFFICIENT_SCOPE,
        `API key lacks required scope: ${required}`,
        req
      );
    }
    return next();
  };
}
