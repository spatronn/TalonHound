/**
 * Role-based access (stage 2). Analyst can triage; admin retains full control.
 * @typedef {'admin' | 'analyst' | 'readonly'} AppRole
 */

export const ROLES = Object.freeze({
  ADMIN: 'admin',
  ANALYST: 'analyst',
  READONLY: 'readonly'
});

const ALL_APP_ROLES = new Set([ROLES.ADMIN, ROLES.ANALYST, ROLES.READONLY]);

export const BULK_TRIAGE_MAX_ITEMS = 100;

export function normalizeAppRole(value) {
  const r = String(value || '').trim().toLowerCase();
  if (ALL_APP_ROLES.has(r)) return r;
  return null;
}

/** Legacy JWTs without role are treated as admin so existing sessions keep full access. */
export function effectiveRoleFromPayload(roleClaim) {
  const n = normalizeAppRole(roleClaim);
  if (n) return n;
  if (roleClaim === undefined || roleClaim === null || roleClaim === '') return ROLES.ADMIN;
  return null;
}

export function isAdminRole(role) {
  return normalizeAppRole(role) === ROLES.ADMIN;
}

export function isReadOnlyRole(role) {
  return normalizeAppRole(role) === ROLES.READONLY;
}

/** Analyst and admin may change verdicts, assign, and run bulk triage. */
export function canTriage(role) {
  const r = normalizeAppRole(role);
  return r === ROLES.ADMIN || r === ROLES.ANALYST;
}

/**
 * @param  {...AppRole} allowed
 * @returns {import('express').RequestHandler}
 */
export function requireRole(...allowed) {
  const set = new Set(allowed);
  return (req, res, next) => {
    if (req.authVia === 'ingest') {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;
    if (!set.has(role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    return next();
  };
}

/** Shorthand for verdict/assign/bulk triage routes. */
export function requireTriageRole() {
  return requireRole(ROLES.ADMIN, ROLES.ANALYST);
}

/**
 * Read-only users: GET/HEAD only, except:
 *   - PUT /api/users/:id (handler enforces self + fields)
 *   - PUT /api/users/me/preferences (self timezone preference)
 * Ingest / bearer bypass (machine & existing automation).
 */
export function rbacHttpPolicy(req, res, next) {
  if (!req.path.startsWith('/api')) return next();
  if (req.method === 'OPTIONS') return next();

  if (req.authVia === 'ingest' || req.authVia === 'bearer') {
    return next();
  }

  const role = normalizeAppRole(req.user?.role) || ROLES.ADMIN;
  if (role !== ROLES.READONLY) {
    return next();
  }

  const m = req.method;
  if (m === 'GET' || m === 'HEAD') {
    return next();
  }

  if (m === 'PUT' && (/^\/api\/users\/\d+$/.test(req.path) || req.path === '/api/users/me/preferences')) {
    return next();
  }

  return res.status(403).json({ message: 'Forbidden: read-only role' });
}
