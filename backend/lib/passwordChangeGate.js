/**
 * Restrict authenticated users with must_change_password=true to session/password/logout only.
 */

const ALLOW_EXACT = new Set([
  '/api/auth/me',
  '/api/auth/logout',
  '/api/auth/change-password',
  '/api/auth/login'
]);

/**
 * @param {import('pg').Pool} pool
 * @returns {import('express').RequestHandler}
 */
export function createPasswordChangeGate(pool) {
  return async function passwordChangeGate(req, res, next) {
    if (req.method === 'OPTIONS') return next();
    if (!req.path.startsWith('/api')) return next();
    if (!req.user) return next();
    // Machine credentials are not subject to interactive password-change flow.
    if (req.authVia === 'ingest') return next();

    if (ALLOW_EXACT.has(req.path)) return next();

    const userId = req.user?.id;
    // Fail closed: interactive sessions must carry a resolvable user id so
    // must_change_password can be enforced. Do not skip the gate when identity is missing.
    if (userId == null || !Number.isFinite(Number(userId))) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
      const { rows } = await pool.query(
        'SELECT must_change_password FROM users WHERE id = $1',
        [Number(userId)]
      );
      if (!rows.length) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
      if (!rows[0].must_change_password) {
        return next();
      }
      return res.status(403).json({
        code: 'PASSWORD_CHANGE_REQUIRED',
        message: 'Password change is required before continuing'
      });
    } catch (err) {
      return res.status(500).json({
        message: 'Failed to verify password change status',
        detail: err?.message || String(err)
      });
    }
  };
}

export { ALLOW_EXACT as PASSWORD_CHANGE_GATE_ALLOWLIST };
