/**
 * MCP Bearer authentication against published_feed_access_keys.
 * Resolves an accountable owner user for RBAC intersection.
 */

import { hashApiKey, timingSafeHashEqual, keyStatus } from './publishedFeedApiKey.js';
import { hasApiScope, isMcpAccessProfile, normalizeScopes, API_SCOPE } from './apiKeyProfiles.js';
import { normalizeAppRole } from './rbac.js';
import { ensureRequestId } from './apiRequestId.js';
import { sendApiError, API_ERROR_CODE } from './apiV1Errors.js';
import { isMcpEnabled } from './mcpConfig.js';
import { touchApiKeyLastUsed } from './apiKeyAuth.js';

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

function hasAnyMcpScope(scopes) {
  return [
    API_SCOPE.MCP_IOC_READ,
    API_SCOPE.MCP_IOC_CREATE,
    API_SCOPE.MCP_ENRICHMENT_READ,
    API_SCOPE.MCP_SOURCES_READ
  ].some((s) => hasApiScope(scopes, s));
}

/**
 * Authenticate MCP requests. Sets:
 *   req.apiKey, req.user (owner), req.authVia = 'mcp', req.mcpAuth
 *
 * @param {import('pg').Pool} pool
 * @returns {import('express').RequestHandler}
 */
export function authenticateMcp(pool) {
  return async function authenticateMcpMiddleware(req, res, next) {
    ensureRequestId(req, res);
    if (!isMcpEnabled()) {
      return sendApiError(res, 503, API_ERROR_CODE.INTERNAL_ERROR, 'MCP is disabled', req);
    }

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
        `SELECT k.id, k.name, k.token_hash, k.key_type, k.scopes, k.enabled,
                k.revoked_at, k.deleted_at, k.expires_at, k.owner_user_id,
                u.id AS owner_id, u.public_id AS owner_public_id, u.username AS owner_username,
                u.role AS owner_role, u.status AS owner_status
         FROM published_feed_access_keys k
         LEFT JOIN users u ON u.id = k.owner_user_id
         WHERE k.token_hash = $1 AND k.deleted_at IS NULL
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

      const scopes = normalizeScopes(row.scopes);
      if (!isMcpAccessProfile(row.key_type) && !hasAnyMcpScope(scopes)) {
        return sendApiError(
          res,
          403,
          API_ERROR_CODE.INSUFFICIENT_SCOPE,
          'API key is not authorized for MCP',
          req
        );
      }

      if (!row.owner_user_id || !row.owner_id) {
        return sendApiError(
          res,
          403,
          API_ERROR_CODE.INSUFFICIENT_SCOPE,
          'MCP credential has no accountable owner user',
          req
        );
      }

      const ownerRole = normalizeAppRole(row.owner_role);
      if (!ownerRole) {
        return sendApiError(
          res,
          403,
          API_ERROR_CODE.INSUFFICIENT_SCOPE,
          'MCP owner user has an invalid role',
          req
        );
      }

      const ownerStatus = String(row.owner_status || '').trim().toLowerCase();
      if (ownerStatus && ownerStatus !== 'active') {
        return sendApiError(
          res,
          403,
          API_ERROR_CODE.API_KEY_DISABLED,
          'MCP owner user is not active',
          req
        );
      }

      req.apiKey = {
        id: Number(row.id),
        name: row.name,
        key_type: row.key_type,
        scopes,
        owner_user_id: Number(row.owner_user_id)
      };
      req.user = {
        id: Number(row.owner_id),
        publicId: row.owner_public_id || null,
        username: row.owner_username || null,
        // users table has no email column; username is the login identifier.
        email: row.owner_username || null,
        role: ownerRole
      };
      req.authVia = 'mcp';
      req.mcpAuth = {
        scopes,
        ownerRole,
        apiKeyId: Number(row.id),
        apiKeyName: row.name,
        keyType: row.key_type
      };
      touchApiKeyLastUsed(pool, row.id, clientIp(req));
      return next();
    } catch {
      return sendApiError(res, 500, API_ERROR_CODE.INTERNAL_ERROR, 'Internal error', req);
    }
  };
}
