/**
 * Auth-03/04 helpers: Bearer must not bypass role policy; ingest is a machine principal
 * with an explicit path allowlist (not human admin).
 */

import { normalizeAppRole, ROLES } from './rbac.js';

/** Exact method+path pairs the ingest token may call. Default deny everything else. */
export const INGEST_ALLOWED_ROUTES = Object.freeze([
  Object.freeze({ method: 'POST', path: '/api/ioc/ip' })
]);

export function isIngestAuth(req) {
  return req?.authVia === 'ingest';
}

/** Human admin (cookie/bearer), never ingest synthetic principal. */
export function isHumanAdmin(req) {
  if (isIngestAuth(req)) return false;
  return normalizeAppRole(req?.user?.role) === ROLES.ADMIN;
}

/**
 * Deny-by-default gateway for machine ingest. Non-ingest requests pass through.
 * @returns {import('express').RequestHandler}
 */
export function ingestCapabilityPolicy(req, res, next) {
  if (!isIngestAuth(req)) return next();
  if (!req.path?.startsWith('/api')) return next();

  const method = String(req.method || '').toUpperCase();
  const path = String(req.path || '');
  const allowed = INGEST_ALLOWED_ROUTES.some(
    (r) => r.method === method && r.path === path
  );
  if (!allowed) {
    return res.status(403).json({
      message: 'Forbidden: ingest principal is not permitted for this endpoint'
    });
  }
  return next();
}
