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

/**
 * Strict JWT role claim resolution. Only canonical app roles are trusted.
 * Missing / empty / unknown / malformed claims return null (fail closed — never admin).
 */
export function effectiveRoleFromPayload(roleClaim) {
  return normalizeAppRole(roleClaim);
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
    const role = normalizeAppRole(req.user?.role);
    if (!role || !set.has(role)) {
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

  // Public / deferred-auth routes (login, docs, /api/v1, ?api_key feeds) skip
  // requireAuth and have no req.user — do not invent admin or block them here.
  if (!req.user) return next();

  const role = normalizeAppRole(req.user.role);
  // Authenticated identity with missing/invalid role: fail closed (never default admin).
  if (!role) {
    return res.status(403).json({ message: 'Forbidden' });
  }
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
