/**
 * Canonical System Administrator authorization.
 *
 * Privilege is users.is_system_admin (exactly one protected account). It is
 * independent of JWT role claims: role=admin is not sufficient. The JWT does
 * not carry the flag; callers resolve it from the database by internal user id.
 *
 * This is TalonHound application privilege, not host/root/sudo.
 */

/**
 * Whether the authenticated caller is the protected System Administrator
 * (users.is_system_admin = TRUE). Machine/ingest principals (no numeric id)
 * are never system admins.
 * @param {import('pg').Pool} pool
 * @param {import('express').Request} req
 */
export async function isCallerSystemAdmin(pool, req) {
  if (req?.authVia === 'ingest') return false;
  const id = req?.user?.id;
  if (id == null || !Number.isFinite(Number(id))) return false;
  if (!pool?.query) return false;
  try {
    const { rows } = await pool.query(
      'SELECT is_system_admin FROM users WHERE id = $1 LIMIT 1',
      [Number(id)]
    );
    return rows[0]?.is_system_admin === true;
  } catch {
    return false;
  }
}

export const SYSTEM_ADMIN_FORBIDDEN = Object.freeze({
  code: 'FORBIDDEN',
  message: 'Only the System Administrator can perform this action'
});

/**
 * Express middleware: fail closed unless isCallerSystemAdmin is true.
 * Authentication (401) is the caller's responsibility (global requireAuth).
 * @param {import('pg').Pool} pool
 * @param {string} [message]
 * @returns {import('express').RequestHandler}
 */
export function requireSystemAdmin(pool, message) {
  const body = {
    code: 'FORBIDDEN',
    message: message || SYSTEM_ADMIN_FORBIDDEN.message
  };
  return async (req, res, next) => {
    try {
      const ok = await isCallerSystemAdmin(pool, req);
      if (!ok) {
        return res.status(403).json(body);
      }
      return next();
    } catch {
      return res.status(403).json(body);
    }
  };
}
